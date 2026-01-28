#include "utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "logging.hpp"

// Anonymous namespace for file-local constants and helper functions.
namespace {
constexpr size_t kMaxPathLengthInternal = PATH_MAX; // Internal max path length.
constexpr size_t kMsgBufferSize = 64;               // Buffer size for generic messages.
constexpr size_t kStatusBufferSize = 128;           // Buffer size for wait status parsing.
constexpr int kInvalidFd = -1;                      // Represents an invalid file descriptor.
constexpr uintptr_t kStackAlignment = 0xf;          // Stack alignment requirement (16 bytes for many architectures).
constexpr int kMaxRegisterArgs = 8;                 // Maximum number of arguments passed via registers (e.g., AArch64).

// Permission characters used in memory map parsing.
constexpr char kReadPerm = 'r';
constexpr char kWritePerm = 'w';
constexpr char kExecPerm = 'x';
constexpr char kNoPerm = '-';

// Characters used for generating random magic strings.
constexpr std::string_view kRandomChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#if defined(__x86_64__)
// Helper function to set x86_64 specific registers for remote calls.
void setup_x86_64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    // Arguments are passed in RDI, RSI, RDX, RCX, R8, R9.
    if (args.size() >= 1)
        regs.rdi = args[0];
    if (args.size() >= 2)
        regs.rsi = args[1];
    if (args.size() >= 3)
        regs.rdx = args[2];
    if (args.size() >= 4)
        regs.rcx = args[3];
    if (args.size() >= 5)
        regs.r8 = args[4];
    if (args.size() >= 6)
        regs.r9 = args[5];
}
#elif defined(__aarch64__)
// Helper function to set AArch64 specific registers for remote calls.
void setup_aarch64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    // Arguments are passed in x0-x7.
    for (size_t i = 0; i < std::min(args.size(), static_cast<size_t>(kMaxRegisterArgs)); i++) {
        regs.regs[i] = args[i];
    }
}
#elif defined(__arm__)
// Helper function to set ARM specific registers for remote calls.
void setup_arm_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    // Arguments are passed in R0-R3.
    for (size_t i = 0; i < std::min(args.size(), static_cast<size_t>(4)); i++) { // ARM has 4 register arguments (R0-R3)
        regs.uregs[i] = args[i];
    }
}
#endif
} // namespace

/**
 * @brief Switches the mount namespace of the current process to that of the target PID, or restores it.
 *
 * This is crucial for operations like `open()` on `/proc/<pid>/mem` or other sensitive files,
 * which might be in a different mount namespace than the injector.
 *
 * @param pid If non-zero, switches to the namespace of `pid`.
 *  If zero, restores to the namespace stored in `*fd`.
 * @param fd On entry (pid != 0), points to an int to store the original namespace FD.
 *  On entry (pid == 0), points to the FD of the namespace to restore to.
 *  FD is consumed/set to kInvalidFd on successful restore.
 * @return True on success, false on failure.
 */
bool switch_mnt_ns(int pid, int *fd) {
    if (pid == 0) { // Restore original namespace
        if (!fd || *fd == kInvalidFd) {
            LOGE("Invalid file descriptor for namespace switch (restore operation).");
            return false;
        }

        UniqueFd nsfd(*fd); // Take ownership of the FD.
        *fd = kInvalidFd;   // Invalidate original pointer.

        if (setns(nsfd, CLONE_NEWNS) == -1) {
            PLOGE("Failed to switch back to original namespace (FD: %d).", nsfd.operator const int &());
            return false;
        }

        LOGD("Successfully switched back to original namespace (FD: %d).", nsfd.operator const int &());
        return true;
    } else { // Switch to target PID's namespace
        int old_nsfd = kInvalidFd;

        if (fd) { // If an FD pointer is provided, save current namespace FD.
            old_nsfd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
            if (old_nsfd == kInvalidFd) {
                PLOGE("Failed to open current mount namespace for backup.");
                return false;
            }
            *fd = old_nsfd; // Store the original namespace FD.
        }

        std::string target_path = "/proc/" + std::to_string(pid) + "/ns/mnt";
        UniqueFd target_nsfd = open(target_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (target_nsfd == kInvalidFd) {
            PLOGE("Failed to open target PID %d's mount namespace: %s", pid, target_path.c_str());
            if (fd)
                *fd = kInvalidFd; // Invalidate backup FD if target fails.
            return false;
        }

        if (setns(target_nsfd, CLONE_NEWNS) == -1) {
            PLOGE("Failed to switch to target PID %d's mount namespace: %s", pid, target_path.c_str());
            if (fd)
                *fd = kInvalidFd; // Invalidate backup FD if target fails.
            return false;
        }

        LOGD("Successfully switched to mount namespace for PID %d.", pid);
        return true;
    }
}

/**
 * @brief Writes data to the remote process's memory using either `process_vm_writev` or `/proc/<pid>/mem`.
 *
 * `process_vm_writev` is generally preferred for performance and atomicity but requires kernel support.
 * `/proc/<pid>/mem` is a fallback or for specific use cases.
 *
 * @param pid The target process ID.
 * @param remote_addr The target address in the remote process.
 * @param buf A pointer to the local buffer containing data to write.
 * @param len The number of bytes to write.
 * @param use_proc_mem If true, uses /proc/<pid>/mem; otherwise, uses process_vm_writev.
 * @return The number of bytes written, or -1 on error.
 */
ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len, bool use_proc_mem) {
    if (!buf || len == 0) {
        LOGE("Invalid parameters for write_proc: buffer is null or length is zero.");
        return -1;
    }

    LOGV("Writing %zu bytes to PID %d at address %" PRIxPTR " (use_proc_mem=%s).", len, pid, remote_addr,
         use_proc_mem ? "true" : "false");

    ssize_t bytes_written;

    if (use_proc_mem) {
        // Fallback or specific use case: writing via /proc/<pid>/mem.
        // This requires opening the mem file and using pwrite to specify the offset.
        char proc_path[kMaxPathLengthInternal];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);

        UniqueFd proc_fd = open(proc_path, O_WRONLY | O_CLOEXEC);
        if (proc_fd == kInvalidFd) {
            PLOGE("Failed to open %s for writing.", proc_path);
            return -1;
        }

        bytes_written = pwrite(proc_fd, buf, len, static_cast<off_t>(remote_addr));
        if (bytes_written == -1) {
            PLOGE("pwrite failed for remote address %" PRIxPTR ".", remote_addr);
        }
    } else {
        // Preferred method: process_vm_writev for direct memory access.
        // It transfers data between the vector of iovecs from local process to remote process.
        struct iovec local_iov = {.iov_base = const_cast<void *>(buf), .iov_len = len};
        struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

        bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (bytes_written == -1) {
            PLOGE("process_vm_writev failed for remote address %" PRIxPTR ".", remote_addr);
        }
    }

    if (bytes_written != -1 && static_cast<size_t>(bytes_written) != len) {
        LOGW("Partial write: %zd bytes written, %zu expected for PID %d at %" PRIxPTR ".", bytes_written, len, pid,
             remote_addr);
    }

    return bytes_written;
}

/**
 * @brief Reads data from the remote process's memory using `process_vm_readv`.
 *
 * `process_vm_readv` is generally the most efficient and robust way to read from another process's memory.
 *
 * @param pid The target process ID.
 * @param remote_addr The source address in the remote process.
 * @param buf A pointer to the local buffer to store the read data.
 * @param len The number of bytes to read.
 * @return The number of bytes read, or -1 on error.
 */
ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    if (!buf || len == 0) {
        LOGE("Invalid parameters for read_proc: buffer is null or length is zero.");
        return -1;
    }

    LOGV("Reading %zu bytes from PID %d at address %" PRIxPTR ".", len, pid, remote_addr);

    // Setup iovec structures for local and remote memory.
    struct iovec local_iov = {.iov_base = buf, .iov_len = len};
    struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read == -1) {
        PLOGE("process_vm_readv failed for remote address %" PRIxPTR ".", remote_addr);
    } else if (static_cast<size_t>(bytes_read) != len) {
        LOGW("Partial read: %zd bytes read, %zu expected for PID %d at %" PRIxPTR ".", bytes_read, len, pid,
             remote_addr);
    }

    return bytes_read;
}

/**
 * @brief Retrieves the current CPU registers of the target process using ptrace.
 *
 * This function handles architecture-specific differences in `ptrace` calls for registers.
 *
 * @param pid The target process ID.
 * @param regs A reference to a `user_regs_struct` to store the registers.
 * @return True on success, false on failure.
 */
bool get_regs(int pid, struct user_regs_struct &regs) {
    LOGV("Retrieving registers for PID %d.", pid);

#if defined(__x86_64__) || defined(__i386__)
    // For x86/x86_64, PTRACE_GETREGS is used directly with `struct
    // user_regs_struct`.
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("Failed to get registers for PID %d.", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    // For ARM/AArch64, PTRACE_GETREGSET is used with `NT_PRSTATUS` and an iovec.
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("Failed to get register set for PID %d.", pid);
#if defined(__arm__)
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            PLOGE("Fallback to PTRACE_GETREGS failed.");
            return false;
        }
#else
        return false;
#endif
    }
#else
#    error "Unsupported architecture for register access in get_regs."
#endif

    LOGV("Successfully retrieved registers for PID %d.", pid);
    return true;
}

/**
 * @brief Sets the CPU registers of the target process using ptrace.
 *
 * This function handles architecture-specific differences in `ptrace` calls for registers.
 *
 * @param pid The target process ID.
 * @param regs A reference to a `user_regs_struct` containing the registers to set.
 * @return True on success, false on failure.
 */
bool set_regs(int pid, struct user_regs_struct &regs) {
    LOGV("Setting registers for PID %d.", pid);

#if defined(__x86_64__) || defined(__i386__)
    // For x86/x86_64, PTRACE_SETREGS is used directly.
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("Failed to set registers for PID %d.", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    // For ARM/AArch64, PTRACE_SETREGSET is used.
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("Failed to set register set for PID %d.", pid);
#if defined(__arm__)
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            PLOGE("Fallback to PTRACE_SETREGS failed.");
            return false;
        }
#else
        return false;
#endif
    }
#else
#    error "Unsupported architecture for register access in set_regs."
#endif

    LOGV("Successfully set registers for PID %d.", pid);
    return true;
}

/**
 * @brief Gets a descriptive string of the memory region containing a given address.
 * @param map_info A vector of `lsplt::MapInfo` for the process.
 * @param addr The address to look up.
 * @return A string representing the memory region (e.g., "path perms"), or
 * "<unknown>".
 */
std::string get_addr_mem_region(const std::vector<lsplt::MapInfo> &map_info, uintptr_t addr) {
    for (const auto &map : map_info) {
        if (map.start <= addr && map.end > addr) {
            std::string perms_str;
            perms_str.reserve(4); // "rwx" + null or '-'

            perms_str += (map.perms & PROT_READ) ? kReadPerm : kNoPerm;
            perms_str += (map.perms & PROT_WRITE) ? kWritePerm : kNoPerm;
            perms_str += (map.perms & PROT_EXEC) ? kExecPerm : kNoPerm;

            return map.path + ' ' + perms_str;
        }
    }
    return "<unknown>";
}

/**
 * @brief Finds the base address of a module in a process's memory map.
 *
 * This function iterates through memory maps and identifies the entry
 * that corresponds to the start of a shared library (offset 0) with a matching suffix.
 *
 * @param map_info A vector of `lsplt::MapInfo` for the process.
 * @param module_suffix The suffix of the module path (e.g., "libc.so").
 * @return The base address of the module, or nullptr if not found.
 */
void *find_module_base(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix) {
    for (const auto &map : map_info) {
        // A module's base is typically its first segment with offset 0.
        if (map.offset == 0 && map.path.ends_with(module_suffix)) {
            LOGV("Found module base for '%.*s' at %p.", static_cast<int>(module_suffix.length()), module_suffix.data(),
                 reinterpret_cast<void *>(map.start));
            return reinterpret_cast<void *>(map.start);
        }
    }

    LOGV("Module base not found for suffix '%.*s'.", static_cast<int>(module_suffix.length()), module_suffix.data());
    return nullptr;
}

/**
 * @brief Finds the address of a function in a remote process by resolving it locally and calculating the offset.
 *
 * This is a common technique for remote code injection:
 * 1. Load the target module locally (e.g., `libc.so`).
 * 2. Find the function's address in the *local* module.
 * 3. Calculate the offset of the function from the *local* module's base.
 * 4. Find the module's base address in the *remote* process.
 * 5. Add the calculated offset to the *remote* module's base to get the remote function address.
 *
 * @param local_map_info Memory map of the local (injector) process.
 * @param remote_map_info Memory map of the remote (target) process.
 * @param module_name The name of the module (e.g., "libc.so").
 * @param function_name The name of the function (e.g., "open").
 * @return The remote address of the function, or nullptr if not found.
 */
void *find_func_addr(const std::vector<lsplt::MapInfo> &local_map_info,
                     const std::vector<lsplt::MapInfo> &remote_map_info, std::string_view module_name,
                     std::string_view function_name) {
    LOGV("Resolving function '%.*s' in module '%.*s'.", static_cast<int>(function_name.length()), function_name.data(),
         static_cast<int>(module_name.length()), module_name.data());

    // 1. Open the module locally to find the symbol.
    // RTLD_NOW ensures all undefined symbols are resolved immediately.
    void *lib_handle = dlopen(module_name.data(), RTLD_NOW);
    if (!lib_handle) {
        LOGE("Failed to open local library '%.*s': %s.", static_cast<int>(module_name.length()), module_name.data(),
             dlerror());
        return nullptr;
    }

    // Use a lambda for RAII-like dlclose to ensure handle is closed.
    auto lib_closer = [lib_handle]() {
        dlclose(lib_handle);
    };

    // 2. Find the function's address in the *local* module.
    auto *symbol_addr = reinterpret_cast<uint8_t *>(dlsym(lib_handle, function_name.data()));
    if (!symbol_addr) {
        LOGE("Failed to find local symbol '%.*s' in library '%.*s': %s.", static_cast<int>(function_name.length()),
             function_name.data(), static_cast<int>(module_name.length()), module_name.data(), dlerror());
        lib_closer(); // Ensure local handle is closed before returning.
        return nullptr;
    }
    LOGV("Found local symbol '%.*s' at address %p.", static_cast<int>(function_name.length()), function_name.data(),
         symbol_addr);

    // 3. Find the module's base address in the *local* process.
    auto *local_base = reinterpret_cast<uint8_t *>(find_module_base(local_map_info, module_name));
    if (!local_base) {
        LOGE("Failed to find local base address for module '%.*s'.", static_cast<int>(module_name.length()),
             module_name.data());
        lib_closer();
        return nullptr;
    }

    // 4. Find the module's base address in the *remote* process.
    auto *remote_base = reinterpret_cast<uint8_t *>(find_module_base(remote_map_info, module_name));
    if (!remote_base) {
        LOGE("Failed to find remote base address for module '%.*s'.", static_cast<int>(module_name.length()),
             module_name.data());
        lib_closer();
        return nullptr;
    }

    // 5. Calculate the offset and derive the remote function address.
    ptrdiff_t symbol_offset = symbol_addr - local_base;
    auto *remote_symbol_addr = remote_base + symbol_offset;

    LOGV("Address translation: local_base=%p, remote_base=%p, offset=%td -> remote_addr=%p", local_base, remote_base,
         symbol_offset, remote_symbol_addr);

    lib_closer(); // Close local handle.
    return remote_symbol_addr;
}

/**
 * @brief Aligns the stack pointer (`REG_SP`) to ensure proper stack frame setup.
 *
 * Stack alignment (typically 16-bytes on modern architectures) is crucial for correct function calls,
 * especially for variadic functions or those using SIMD registers.
 *
 * @param regs A reference to the `user_regs_struct` to modify.
 * @param preserve_bytes Number of bytes to preserve below the new stack pointer.
 * This is useful if some data needs to be kept on the stack just before the new alignment.
 */
void align_stack(struct user_regs_struct &regs, uintptr_t preserve_bytes) {
    // Decrement stack pointer by preserve_bytes, then align it down to the nearest multiple of (kStackAlignment + 1).
    regs.REG_SP = (regs.REG_SP - preserve_bytes) & ~kStackAlignment;
    LOGV("Stack aligned to %" PRIxPTR " (preserved %zu bytes).", static_cast<uintptr_t>(regs.REG_SP), preserve_bytes);
}

/**
 * @brief Pushes a block of memory onto the remote process's stack.
 *
 * This function decrements the stack pointer, aligns it
 * (if necessary, by a subsequent call to align_stack after multiple pushes), and then writes the data.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (its stack pointer will be updated).
 * @param data A pointer to the local data to push.
 * @param length The number of bytes to push.
 * @return The remote address where the data was pushed, or 0 on error.
 */
uintptr_t push_memory(int pid, struct user_regs_struct &regs, const void *data, size_t length) {
    if (!data || length == 0) {
        LOGE("Invalid parameters for push_memory: data=%p, length=%zu.", data, length);
        return 0;
    }

    // Decrement stack pointer to make space for the data.
    regs.REG_SP -= length;
    // Align the stack.
    // This might shift REG_SP further down if not already aligned.
    // If multiple small pushes happen, it's better to align once at the end or before a call.
    // For a single block, aligning after decrement is fine.
    align_stack(regs);

    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    // Write the data to the remote stack.
    if (write_proc(pid, stack_addr, data, length) != static_cast<ssize_t>(length)) {
        LOGE("Failed to push %zu bytes to remote stack at %" PRIxPTR ".", length, stack_addr);
        return 0;
    }

    LOGV("Pushed %zu bytes to remote stack at %" PRIxPTR ".", length, stack_addr);
    return stack_addr;
}

/**
 * @brief Pushes a null-terminated string onto the remote process's stack.
 *
 * This function calculates the string length (including null terminator),
 * decrements the stack pointer, aligns it, and then writes the string.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (its stack pointer will be updated).
 * @param str The null-terminated C-style string to push.
 * @return The remote address where the string was pushed, or 0 on error.
 */
uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    if (!str) {
        LOGE("Null string pointer passed to push_string.");
        return 0;
    }

    size_t str_length = strlen(str) + 1; // Include null terminator.

    // Decrement stack pointer and align it.
    regs.REG_SP -= str_length;
    align_stack(regs); // Align the stack after making space.

    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    // Write the string to the remote stack.
    if (write_proc(pid, stack_addr, str, str_length) != static_cast<ssize_t>(str_length)) {
        LOGE("Failed to push string '%s' (%zu bytes) to remote stack at %" PRIxPTR ".", str, str_length, stack_addr);
        return 0;
    }

    LOGV("Pushed string '%s' (%zu bytes) to remote stack at %" PRIxPTR ".", str, str_length, stack_addr);
    return stack_addr;
}

/**
 * @brief Prepares and initiates a remote function call in the target process.
 *
 * This function sets up the target process's registers according to the calling convention of the architecture:
 *
 * - Arguments are placed in registers or on the stack.
 * - The return address is pushed onto the stack (x86) or placed in a link register (ARM/AArch64).
 * - The instruction pointer is set to the target function's address.
 *
 * Finally, `PTRACE_CONT` is used to resume the target process.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (will be modified with call context).
 * @param func_addr The remote address of the function to call.
 * @param return_addr The address in the remote process where execution should resume after the call.
 * @param args A vector of `uintptr_t` representing the function arguments.
 * @return True if the remote call was successfully initiated, false otherwise.
 */
bool remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                     std::vector<uintptr_t> &args) {
    // Ensure stack is aligned before modifying it for function arguments.
    align_stack(regs);

    LOGV("Setting up remote function call to %p (func_addr=%" PRIxPTR ") with %zu arguments. Return to %p.",
         reinterpret_cast<void *>(func_addr), func_addr, args.size(), reinterpret_cast<void *>(return_addr));
    for (size_t i = 0; i < args.size(); i++) {
        LOGV("  arg[%zu] = %p (%" PRIuPTR ")", i, reinterpret_cast<void *>(args[i]), args[i]);
    }

#if defined(__x86_64__)
    // x86_64 Calling Convention (System V AMD64 ABI):
    // Arguments: RDI, RSI, RDX, RCX, R8, R9.
    // Additional arguments on stack (right-to-left).
    // Return Address: Pushed onto stack by CALL instruction.
    // Return Value: RAX.
    setup_x86_64_args(regs, args);

    if (args.size() > kMaxRegisterArgs) { // kMaxRegisterArgs for x86_64 is 6
        // Push excess arguments onto the stack.
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);
        // Align stack while reserving space for args.

        // Write stack arguments from `args.data() + kMaxRegisterArgs` (the elements beyond registers).
        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for x86_64 remote call.");
            return false;
        }
    }

    // Push the return address onto the stack. This simulates what a `call` instruction would do.
    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) !=
        sizeof(return_addr)) {
        LOGE("Failed to write return address for x86_64 remote call.");
        return false;
    }

    regs.REG_IP = func_addr; // Set instruction pointer to the target function.

#elif defined(__i386__)
    // i386 Calling Convention (cdecl):
    // Arguments: All pushed onto stack (right-to-left).
    // Return Address: Pushed onto stack by CALL instruction.
    // Return Value: EAX.
    if (args.size() > 0) {
        size_t stack_args_size = args.size() * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        // i386 cdecl expects arguments pushed Right-to-Left (stack grows down).
        // Since `write_proc` writes to increasing addresses (up), a linear write
        // starting at the new SP places the first argument at the lowest address.
        // This matches the ABI memory layout without needing to reverse the vector.
        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data(), stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push arguments for i386 remote call.");
            return false;
        }
    }

    // Push the return address onto the stack.
    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) !=
        sizeof(return_addr)) {
        LOGE("Failed to write return address for i386 remote call.");
        return false;
    }

    regs.REG_IP = func_addr; // Set instruction pointer.

#elif defined(__aarch64__)
    // AArch64 Calling Convention (Procedure Call Standard for the ARM 64-bit Architecture):
    // Arguments: x0-x7.
    // Additional arguments on stack.
    // Return Address: x30 (Link Register, LR).
    // Return Value: x0.
    setup_aarch64_args(regs, args);

    if (args.size() > kMaxRegisterArgs) { // kMaxRegisterArgs for AArch64 is 8
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for AArch64 remote call.");
            return false;
        }
    }

    regs.regs[30] = return_addr; // Set Link Register (LR) to return address.
    regs.REG_IP = func_addr;     // Set Program Counter (PC) to target function.

#elif defined(__arm__)
    // ARM Calling Convention (ARM Procedure Call Standard - AAPCS):
    // Arguments: R0-R3. Additional arguments on stack.
    // Return Address: R14 (Link Register, LR).
    // Return Value: R0.
    setup_arm_args(regs, args);

    if (args.size() > 4) { // ARM has 4 register arguments (R0-R3).
        size_t stack_args_size = (args.size() - 4) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + 4, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for ARM remote call.");
            return false;
        }
    }

    regs.uregs[14] = return_addr; // Set Link Register (R14) to return address.
    regs.REG_IP = func_addr;      // Set Program Counter (R15) to target function.

    // Handle Thumb mode for ARM.
    // If func_addr is odd, it indicates Thumb instruction set.
    // Clear the LSB of PC and set the T bit in CPSR (R16).
    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        regs.REG_IP = regs.REG_IP & ~1;                // Clear LSB for actual address.
        regs.uregs[16] = regs.uregs[16] | CPSR_T_MASK; // Set T bit.
    } else {
        regs.uregs[16] = regs.uregs[16] & ~CPSR_T_MASK; // Clear T bit for ARM mode.
    }

#else
#    error "Unsupported architecture for remote function calls in remote_pre_call."
#endif

    // Set the modified registers in the target process.
    if (!set_regs(pid, regs)) {
        LOGE("Failed to set registers for remote function call in PID %d.", pid);
        return false;
    }

    // Continue the target process execution.
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        PLOGE("Failed to continue remote process %d execution.", pid);
        return false;
    }

    LOGV("Remote function call initiated successfully for PID %d to %p.", pid, reinterpret_cast<void *>(func_addr));
    return true;
}

/**
 * @brief Waits for and finalizes a remote function call, retrieving its return value.
 *
 * After `remote_pre_call` resumes the process, this function waits for the process to stop
 * (ideally at the `return_addr` previously set).
 * It then retrieves the registers to extract the function's return value.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (will be updated with post-call registers).
 * @param expected_return_addr The address where the remote call was expected to return to.
 *  Used for error checking (e.g., if a crash occurs elsewhere).
 * @return The return value of the remote function (from REG_RET), or 0 on error.
 */
uintptr_t remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t expected_return_addr) {
    LOGV("Waiting for remote function call completion in PID %d.", pid);

    int status;
    // Wait for the target process to stop.
    if (!wait_for_trace(pid, &status, __WALL)) {
        LOGE("Failed to wait for remote function completion in PID %d.", pid);
        return 0;
    }

    // Retrieve the registers after the call.
    if (!get_regs(pid, regs)) {
        LOGE("Failed to get registers after remote call completion in PID %d.", pid);
        return 0;
    }

    int stop_signal = WSTOPSIG(status);
    LOGV("Remote function in PID %d stopped with signal: %s(%d) at address %p.", pid, sigabbrev_np(stop_signal),
         stop_signal, reinterpret_cast<void *>(regs.REG_IP));

    // Check if the process stopped at the expected return address.
    // SIGTRAP is often received if a breakpoint was set at return_addr, or if single-stepping.
    // A SIGSEGV here indicates a crash during the remote function execution.
    if (static_cast<uintptr_t>(regs.REG_IP) != expected_return_addr) {
        // Log unexpected return, potentially indicating a crash or unexpected flow.
        LOGE("Remote function in PID %d returned to unexpected address %p (expected %p).", pid,
             reinterpret_cast<void *>(regs.REG_IP), reinterpret_cast<void *>(expected_return_addr));

        // Attempt to get more detailed crash info if it was a SIGSEGV or similar.
        if (stop_signal == SIGSEGV || stop_signal == SIGBUS || stop_signal == SIGILL) {
            siginfo_t crash_info;
            if (ptrace(PTRACE_GETSIGINFO, pid, 0, &crash_info) == 0) {
                LOGE("Crash details for PID %d: si_code=%d si_addr=%p.", pid, crash_info.si_code, crash_info.si_addr);
            } else {
                PLOGE("Failed to get crash signal info for PID %d.", pid);
            }
        }
        return 0; // Indicate failure.
    }

    uintptr_t return_value = regs.REG_RET; // Extract the return value from the appropriate register.
    LOGV("Remote function in PID %d completed with return value: %p (%" PRIxPTR ").", pid,
         reinterpret_cast<void *>(return_value), return_value);
    return return_value;
}

/**
 * @brief Executes a complete remote function call (pre-call, continue, post-call).
 *
 * This is a convenience wrapper combining `remote_pre_call` and `remote_post_call`.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (will be modified).
 * @param func_addr The remote address of the function to call.
 * @param return_addr The address in the remote process where execution should
 * resume after the call.
 * @param args A vector of `uintptr_t` representing the function arguments.
 * @return The return value of the remote function, or 0 on error.
 */
uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                      std::vector<uintptr_t> &args) {
    if (!remote_pre_call(pid, regs, func_addr, return_addr, args)) {
        LOGE("Failed to prepare remote function call in PID %d.", pid);
        return 0;
    }
    return remote_post_call(pid, regs, return_addr);
}

/**
 * @brief Forks twice to create a daemon process.
 *
 * The first `fork` creates a child.
 * The parent waits for this child to exit and then returns its PID.
 * The child then `forks` again.
 * The second child becomes the daemon, and the first child exits,
 * ensuring the daemon is not a session leader and is re-parented to `init`.
 *
 * @return 0 in the grand-child (daemon), PID of first child in parent, or -1 on error.
 */
int fork_dont_care() {
    // First fork: Parent returns, child continues to fork again.
    int first_pid = fork();
    if (first_pid < 0) {
        PLOGE("Failed first fork for daemon process.");
        return first_pid;
    }

    if (first_pid == 0) { // This is the first child process.
        // Second fork: First child exits, grand-child becomes daemon.
        int second_pid = fork();
        if (second_pid < 0) {
            PLOGE("Failed second fork for daemon process.");
            exit(EXIT_FAILURE); // Grand-child creation failed, exit first child.
        } else if (second_pid > 0) {
            exit(EXIT_SUCCESS); // First child exits.
        }
        // This is the grand-child process, now a daemon.
        return 0;
    } else { // This is the original parent process.
        int status;
        // Wait for the first child to terminate (it will exit after the second
        // fork).
        waitpid(first_pid, &status, __WALL);
        return first_pid; // Return PID of the first child.
    }
}

/**
 * @brief Waits for the target process to stop due to ptrace.
 *
 * This function continuously calls `waitpid` until the process stops.
 * It handles `EINTR` (interrupted system call) by retrying.
 *
 * @param pid The target process ID.
 * @param status A pointer to an integer to store the wait status.
 * @param flags Flags for `waitpid` (e.g., `__WALL`).
 * @return True if the process successfully stopped, false otherwise.
 */
bool wait_for_trace(int pid, int *status, int flags) {
    if (!status) {
        LOGE("Null status pointer passed to wait_for_trace.");
        return false;
    }

    while (true) {
        pid_t result = waitpid(pid, status, flags);
        if (result == -1) {
            if (errno == EINTR) {
                LOGV("waitpid for PID %d interrupted, retrying.", pid);
                continue; // Retry on EINTR.
            } else {
                PLOGE("waitpid failed for PID %d.", pid);
                return false;
            }
        }

        // If waitpid returns a valid PID, check if the process actually stopped.
        if (!WIFSTOPPED(*status)) {
            LOGE("Process %d not stopped for trace: %s.", pid, parse_status(*status).c_str());
            return false;
        }

        LOGV("Process %d stopped for trace with status: %s.", pid, parse_status(*status).c_str());
        return true;
    }
}

/**
 * @brief Parses the wait status integer into a human-readable string.
 * @param status The status integer returned by `waitpid`.
 * @return A string describing the wait status (e.g., "exited with code 0", "stopped by signal SIGSTOP").
 */
std::string parse_status(int status) {
    char status_buf[kStatusBufferSize];

    if (WIFEXITED(status)) {
        // Process exited normally.
        snprintf(status_buf, sizeof(status_buf), "0x%x exited with code %d", status, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        // Process terminated by a signal.
        snprintf(status_buf, sizeof(status_buf), "0x%x terminated by signal %s(%d)", status,
                 sigabbrev_np(WTERMSIG(status)), WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        // Process stopped by a signal (e.g., ptrace, job control).
        int stop_signal = WSTOPSIG(status);
        snprintf(status_buf, sizeof(status_buf), "0x%x stopped by signal=%s(%d), event=%s", status,
                 sigabbrev_np(stop_signal), stop_signal, parse_ptrace_event(status));
    } else {
        // Unknown status.
        snprintf(status_buf, sizeof(status_buf), "0x%x unknown status", status);
    }

    return std::string(status_buf);
}

/**
 * @brief Retrieves the executable path of a process by reading its `/proc/<pid>/exe` symlink.
 * @param pid The target process ID.
 * @return The absolute path to the executable, or an empty string on error.
 */
std::string get_program(int pid) {
    std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
    char resolved_path[kMaxPathLengthInternal + 1]; // +1 for null terminator.

    ssize_t link_size = readlink(exe_path.c_str(), resolved_path, kMaxPathLengthInternal);
    if (link_size == -1) {
        PLOGE("Failed to read executable path for PID %d: %s", pid, exe_path.c_str());
        return "";
    }

    resolved_path[link_size] = '\0'; // Null-terminate the string.
    return std::string(resolved_path);
}

/**
 * @brief Finds a suitable return address within a specific module in the remote process.
 *
 * For remote code injection, after a remote function call completes,
 * the instruction pointer needs to be set to a safe and controlled location.
 * A non-executable segment within a common library like `libc.so` is often chosen
 * because it's guaranteed to exist and typically won't trigger unwanted execution.
 *
 * @param map_info A vector of `lsplt::MapInfo` for the remote process.
 * @param module_suffix The suffix of the module path (e.g., "libc.so").
 * @return A pointer to a suitable return address, or nullptr if not found.
 */
void *find_module_return_addr(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix) {
    for (const auto &map : map_info) {
        // Look for a readable, non-executable segment of the module.
        // This is a common heuristic for finding a safe return address for ptrace.
        if (!(map.perms & PROT_EXEC) && (map.perms & PROT_READ) && map.path.ends_with(module_suffix)) {
            LOGV("Found return address region for '%.*s' at %p.", static_cast<int>(module_suffix.length()),
                 module_suffix.data(), reinterpret_cast<void *>(map.start));
            return reinterpret_cast<void *>(map.start);
        }
    }

    LOGV("No suitable return address region found for module suffix '%.*s'.", static_cast<int>(module_suffix.length()),
         module_suffix.data());
    return nullptr;
}

/**
 * @brief Generates a random alphanumeric string of a specified length.
 *
 * Uses `std::random_device` for seeding and `std::mt19937` for pseudo-random number generation.
 *
 * @param length The desired length of the magic string.
 * @return The generated magic string.
 */
std::string generateMagic(size_t length) {
    if (length == 0) {
        LOGW("Zero length requested for magic string, returning empty string.");
        return "";
    }

    // Seed the random number generator using a hardware-entropy source if available.
    std::mt19937 random_generator{std::random_device{}()};
    // Distribution to pick a random character from kRandomChars.
    std::uniform_int_distribution<size_t> char_distribution(0, kRandomChars.length() - 1);

    std::string magic_string;
    magic_string.reserve(length); // Reserve memory to avoid reallocations.

    for (size_t i = 0; i < length; i++) {
        magic_string += kRandomChars[char_distribution(random_generator)];
    }

    LOGV("Generated magic string of length %zu.", length);
    return magic_string;
}

/**
 * @brief Sets the SELinux security context of a file using the `setxattr` syscall.
 *
 * This is relevant for Android systems where SELinux policies often
 * restrict processes from accessing files with certain contexts.
 *
 * @param file_path The path to the file.
 * @param security_context The new security context string (e.g., "u:object_r:system_file:s0").
 * @return 0 on success, -1 on failure.
 */
int setfilecon(const char *file_path, const char *security_context) {
    if (!file_path || !security_context) {
        LOGE("Invalid parameters for setfilecon: file_path=%p, security_context=%p.", file_path, security_context);
        return -1;
    }

    size_t context_len = strlen(security_context) + 1; // Include null terminator.
    // Call the setxattr syscall directly.
    // `XATTR_NAME_SELINUX` specifies the SELinux extended attribute.
    int result = syscall(__NR_setxattr, file_path, XATTR_NAME_SELINUX, security_context, context_len, 0);

    if (result == 0) {
        LOGV("Successfully set SELinux context '%s' for file '%s'.", security_context, file_path);
    } else {
        PLOGE("Failed to set SELinux context '%s' for file '%s'.", security_context, file_path);
    }

    return result;
}

/**
 * @brief Sets the SELinux context for newly created sockets in the current thread/process.
 *
 * This function attempts to write the security context to `/proc/thread-self/attr/sockcreate`.
 * If that fails (e.g., permission issues, or old kernel), it falls back to a process-specific path.
 *
 * @param security_context The SELinux context string to set.
 * @return True on success, false on failure.
 */
bool set_sockcreate_con(const char *security_context) {
    if (!security_context) {
        LOGE("Null security context passed to set_sockcreate_con.");
        return false;
    }

    size_t context_size = strlen(security_context) + 1; // Include null terminator.

    // Try setting via `/proc/thread-self/attr/sockcreate`, which is the most specific.
    UniqueFd sockcreate_fd = open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC);
    if (sockcreate_fd != kInvalidFd &&
        write(sockcreate_fd, security_context, context_size) == static_cast<ssize_t>(context_size)) {
        LOGV("Successfully set socket creation context via /proc/thread-self/attr/sockcreate: '%s'.", security_context);
        return true;
    }

    LOGV("Failed to set socket creation context via /proc/thread-self/attr/sockcreate,"
         " attempting process-specific fallback.");

    // Fallback: Try a process-specific path (might be less effective or deprecated depending on kernel).
    char process_path[kMaxPathLengthInternal];
    snprintf(process_path, sizeof(process_path), "/proc/%d/attr/sockcreate", gettid());
    // Using gettid() for thread ID.

    sockcreate_fd = open(process_path, O_WRONLY | O_CLOEXEC);
    if (sockcreate_fd == kInvalidFd ||
        write(sockcreate_fd, security_context, context_size) != static_cast<ssize_t>(context_size)) {
        PLOGE("Failed to set socket creation context via fallback path '%s'.", process_path);
        return false;
    }

    LOGV("Successfully set socket creation context via fallback path '%s': '%s'.", process_path, security_context);
    return true;
}

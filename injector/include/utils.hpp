#pragma once

#include <algorithm> // For std::swap in UniqueFd
#include <limits.h>  // For PATH_MAX
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <unistd.h>
#include <vector>

#include "lsplt.hpp"

// Macros for syscall error checking. These are typically used after remote
// syscall emulation.
#define SYSCALL_IS_ERR(e) (((unsigned long)e) > -4096UL) // Checks if a syscall return value indicates an error.
#define SYSCALL_ERR(e) (-(int)(e))                       // Converts a syscall error value to a negative errno.

// Architecture-specific register definitions.
// These macros abstract away the differences in register names across architectures,
// allowing for generic code that manipulates `struct user_regs_struct`.
#if defined(__x86_64__)
#    define REG_SP rsp       // Stack pointer register
#    define REG_IP rip       // Instruction pointer register
#    define REG_RET rax      // Return value register
#    define REG_NR orig_rax  // Syscall number register
#    define REG_SYS_ARG0 rdi // First syscall argument register
#elif defined(__i386__)
#    define REG_SP esp
#    define REG_IP eip
#    define REG_RET eax
#    define REG_NR orig_eax
#    define REG_SYS_ARG0 ebx
#elif defined(__aarch64__)
#    define REG_SP sp            // Stack pointer register (AArch64)
#    define REG_IP pc            // Program counter register (AArch64)
#    define REG_RET regs[0]      // Return value register (x0)
#    define REG_NR regs[8]       // Syscall number register (x8)
#    define REG_SYS_ARG0 regs[0] // First syscall argument register (x0)
#elif defined(__arm__)
#    define REG_SP uregs[13]           // Stack pointer register (R13)
#    define REG_IP uregs[15]           // Program counter register (R15)
#    define REG_RET uregs[0]           // Return value register (R0)
#    define REG_NR uregs[7]            // Syscall number register (R7)
#    define REG_SYS_ARG0 uregs[0]      // First syscall argument register (R0)
#    define user_regs_struct user_regs // ARM's equivalent to user_regs_struct is user_regs
#    define SYS_mmap SYS_mmap2         // ARM uses mmap2 syscall
#endif

// --- Remote Memory Operations ---

/**
 * @brief Writes data to the remote process's memory.
 * @param pid The target process ID.
 * @param remote_addr The target address in the remote process.
 * @param buf A pointer to the local buffer containing data to write.
 * @param len The number of bytes to write.
 * @param use_proc_mem If true, uses /proc/<pid>/mem; otherwise, uses
 * process_vm_writev.
 * @return The number of bytes written, or -1 on error.
 */
ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len, bool use_proc_mem = false);

/**
 * @brief Reads data from the remote process's memory.
 * @param pid The target process ID.
 * @param remote_addr The source address in the remote process.
 * @param buf A pointer to the local buffer to store the read data.
 * @param len The number of bytes to read.
 * @return The number of bytes read, or -1 on error.
 */
ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len);

// --- Remote Register Operations ---

/**
 * @brief Retrieves the current CPU registers of the target process.
 * @param pid The target process ID.
 * @param regs A reference to a `user_regs_struct` to store the registers.
 * @return True on success, false on failure.
 */
bool get_regs(int pid, struct user_regs_struct &regs);

/**
 * @brief Sets the CPU registers of the target process.
 * @param pid The target process ID.
 * @param regs A reference to a `user_regs_struct` containing the registers to set.
 * @return True on success, false on failure.
 */
bool set_regs(int pid, struct user_regs_struct &regs);

// --- Module and Symbol Resolution ---

/**
 * @brief Gets a descriptive string of the memory region containing a given
 * address.
 * @param map_info A vector of `lsplt::MapInfo` for the process.
 * @param addr The address to look up.
 * @return A string representing the memory region (e.g., "path perms"), or "<unknown>".
 */
std::string get_addr_mem_region(const std::vector<lsplt::MapInfo> &map_info, uintptr_t addr);

/**
 * @brief Finds the base address of a module in a process's memory map.
 * @param map_info A vector of `lsplt::MapInfo` for the process.
 * @param module_suffix The suffix of the module path (e.g., "libc.so").
 * @return The base address of the module, or nullptr if not found.
 */
void *find_module_base(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix);

/**
 * @brief Finds the address of a function in a remote process by resolving it
 * locally and calculating the offset.
 *
 * This function opens the module locally, finds the symbol address,
 * calculates its offset from the local module base, and then adds that offset to the remote module base.
 *
 * @param local_map_info Memory map of the local (injector) process.
 * @param remote_map_info Memory map of the remote (target) process.
 * @param module_name The name of the module (e.g., "libc.so").
 * @param function_name The name of the function (e.g., "open").
 * @return The remote address of the function, or nullptr if not found.
 */
void *find_func_addr(const std::vector<lsplt::MapInfo> &local_map_info,
                     const std::vector<lsplt::MapInfo> &remote_map_info, std::string_view module_name,
                     std::string_view function_name);

/**
 * @brief Finds a suitable return address within a specific module in the remote
 * process.
 *
 * This typically looks for a non-executable segment of the module to return to,
 * as `PTRACE_CONT` will resume execution at the specified instruction pointer.
 *
 * @param map_info A vector of `lsplt::MapInfo` for the remote process.
 * @param module_suffix The suffix of the module path (e.g., "libc.so").
 * @return A pointer to a suitable return address, or nullptr if not found.
 */
void *find_module_return_addr(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix);

// --- Remote Stack Manipulation ---

/**
 * @brief Aligns the stack pointer (`REG_SP`) to ensure proper stack frame setup.
 * @param regs A reference to the `user_regs_struct` to modify.
 * @param preserve_bytes Number of bytes to preserve below the new stack pointer.
 */
void align_stack(struct user_regs_struct &regs, uintptr_t preserve_bytes = 0);

/**
 * @brief Pushes a block of memory onto the remote process's stack.
 *
 * This function decrements the stack pointer, aligns it, and then writes the data.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (its stack pointer will be updated).
 * @param data A pointer to the local data to push.
 * @param length The number of bytes to push.
 * @return The remote address where the data was pushed, or 0 on error.
 */
uintptr_t push_memory(int pid, struct user_regs_struct &regs, const void *data, size_t length);

/**
 * @brief Pushes a null-terminated string onto the remote process's stack.
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (its stack pointer will be updated).
 * @param str The null-terminated C-style string to push.
 * @return The remote address where the string was pushed, or 0 on error.
 */
uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str);

// --- Remote Function Call Emulation ---

/**
 * @brief Prepares and initiates a remote function call in the target process.
 *
 * This function sets up registers (arguments, return address, instruction pointer) and
 * then continues the target process execution using PTRACE_CONT.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (will be modified).
 * @param func_addr The remote address of the function to call.
 * @param return_addr The address in the remote process where execution should
 * resume after the call.
 * @param args A vector of `uintptr_t` representing the function arguments.
 * @return True if the remote call was successfully initiated, false otherwise.
 */
bool remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                     std::vector<uintptr_t> &args);

/**
 * @brief Waits for and finalizes a remote function call, retrieving its return value.
 *
 * This function waits for the target process to stop after a remote call and
 * then retrieves the return value from the appropriate register.
 *
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (will be updated with post-call registers).
 * @param expected_return_addr The address where the remote call was expected to return to.
 *  Used for error checking (e.g., if a crash occurs elsewhere).
 * @return The return value of the remote function, or 0 on error.
 */
uintptr_t remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t expected_return_addr);

/**
 * @brief Executes a complete remote function call (pre-call, continue,
 * post-call).
 * @param pid The target process ID.
 * @param regs A reference to the `user_regs_struct` (will be modified).
 * @param func_addr The remote address of the function to call.
 * @param return_addr The address in the remote process where execution should resume after the call.
 * @param args A vector of `uintptr_t` representing the function arguments.
 * @return The return value of the remote function, or 0 on error.
 */
uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                      std::vector<uintptr_t> &args);

// --- Process Management and Ptrace Utilities ---

/**
 * @brief Forks twice to create a daemon process, returning 0 in the daemon,
 * or the child pid in parent.
 * @return 0 in the grand-child (daemon), PID of first child in parent, or -1 on error.
 */
int fork_dont_care();

/**
 * @brief Waits for the target process to stop due to ptrace.
 *
 * This function handles `EINTR` and ensures the process is actually stopped.
 *
 * @param pid The target process ID.
 * @param status A pointer to an integer to store the wait status.
 * @param flags Flags for `waitpid` (e.g., `__WALL`).
 * @return True if the process successfully stopped, false otherwise.
 */
bool wait_for_trace(int pid, int *status, int flags);

/**
 * @brief Parses the wait status integer into a human-readable string.
 * @param status The status integer returned by `waitpid`.
 * @return A string describing the wait status.
 */
std::string parse_status(int status);

/**
 * @brief Retrieves the executable path of a process.
 * @param pid The target process ID.
 * @return The absolute path to the executable, or an empty string on error.
 */
std::string get_program(int pid);

/**
 * @brief Gets the command-line arguments of a process.
 * @param pid The target process ID.
 * @return A vector of strings representing the command-line arguments.
 */
std::vector<std::string> get_cmdline(int pid);

/**
 * @brief Parses the `exec` status of a process
 * @param pid The target process ID.
 * @return A string representing the `exec` status (placeholder).
 */
std::string parse_exec(int pid);

/**
 * @brief Skips the current syscall in the target process
 * @param pid The target process ID.
 * @return True on success, false on failure (placeholder).
 */
bool skip_syscall(int pid);

/**
 * @brief Executes a syscall in the remote process using ptrace.
 * @param pid The target process ID.
 * @param ret Reference to store the syscall return value.
 * @param nr The syscall number.
 * @param arg0 to arg5 - Syscall arguments.
 * @return True on success, false on failure.
 */
bool do_syscall(int pid, uintptr_t &ret, int nr, uintptr_t arg0 = 0, uintptr_t arg1 = 0, uintptr_t arg2 = 0,
                uintptr_t arg3 = 0, uintptr_t arg4 = 0, uintptr_t arg5 = 0);

/**
 * @brief Switches the mount namespace of the current process to that of the target PID, or restores it.
 * @param pid If non-zero, switches to the namespace of `pid`.
 *  If zero, restores to the namespace stored in `*fd`.
 * @param fd On entry (pid != 0), points to an int to store the original namespace FD.
 *  On entry (pid == 0), points to the FD of the namespace to restore to.
 *  FD is consumed/set to kInvalidFd on successful restore.
 * @return True on success, false on failure.
 */
bool switch_mnt_ns(int pid, int *fd);

/**
 * @brief Remotely calls mmap in the target process.
 * @param pid The target process ID.
 * @param addr The preferred starting address for the new mapping.
 * @param size The length of the mapping.
 * @param prot Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC).
 * @param flags Mapping flags (MAP_PRIVATE, MAP_ANONYMOUS, etc.).
 * @param fd File descriptor to map from (or -1 for anonymous).
 * @param offset Offset into the file (or 0 for anonymous).
 * @return The starting address of the new mapping, or MAP_FAILED on error.
 */
uintptr_t remote_mmap(int pid, uintptr_t addr, size_t size, int prot, int flags, int fd, off_t offset);

/**
 * @brief Remotely calls munmap in the target process.
 * @param pid The target process ID.
 * @param addr The starting address of the region to unmap.
 * @param size The length of the region to unmap.
 * @return True on success, false on failure.
 */
bool remote_munmap(int pid, uintptr_t addr, size_t size);

/**
 * @brief Remotely calls open in the target process.
 * @param pid The target process ID.
 * @param path_addr The remote address of the path string.
 * @param flags Open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.).
 * @return The file descriptor in the remote process, or -1 on error.
 */
int remote_open(int pid, uintptr_t path_addr, int flags);

/**
 * @brief Remotely calls close in the target process.
 * @param pid The target process ID.
 * @param fd The file descriptor in the remote process to close.
 * @return True on success, false on failure.
 */
bool remote_close(int pid, int fd);

/**
 * @brief Waits for a child process to terminate.
 * @param pid The child process ID.
 * @return The exit status of the child, or -1 on error.
 */
int wait_for_child(int pid);

/**
 * @brief Determines the ELF class (32-bit or 64-bit) of an executable file.
 * @param path The path to the ELF file.
 * @return `ELFCLASS32` for 32-bit, `ELFCLASS64` for 64-bit, or `ELFNONE` on error.
 */
int get_elf_class(std::string_view path);

// --- Miscellaneous Utilities ---

constexpr size_t kMaxPathLength = PATH_MAX; // Max path length, consistent with main.cpp
constexpr size_t kDefaultMagicLength = 16;  // Default length for generated magic strings.

/**
 * @brief Generates a random alphanumeric string.
 * @param length The desired length of the magic string.
 * @return The generated magic string.
 */
std::string generateMagic(size_t length);

/**
 * @brief Sets the SELinux security context of a file.
 * @param file_path The path to the file.
 * @param security_context The new security context string.
 * @return 0 on success, -1 on failure.
 */
int setfilecon(const char *file_path, const char *security_context);

/**
 * @brief RAII wrapper for file descriptors.
 *
 * This class automatically closes the file descriptor when it goes out of scope.
 */
class UniqueFd {
    using Fd = int; // Alias for file descriptor type.

public:
    /**
     * @brief Default constructor. Initializes with an invalid FD.
     */
    UniqueFd() = default;

    /**
     * @brief Constructor that takes an existing file descriptor.
     * @param fd The file descriptor to manage.
     */
    UniqueFd(Fd fd) : fd_(fd) {}

    /**
     * @brief Destructor. Closes the managed file descriptor if valid.
     */
    ~UniqueFd() {
        if (fd_ >= 0)
            close(fd_);
    }

    // Delete copy constructor and assignment operator to prevent double-free issues.
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    /**
     * @brief Move constructor. Transfers ownership of the file descriptor.
     * @param other The `UniqueFd` object to move from.
     */
    UniqueFd(UniqueFd &&other) noexcept {
        std::swap(fd_, other.fd_);
    }

    /**
     * @brief Move assignment operator. Transfers ownership of the file descriptor.
     * @param other The `UniqueFd` object to move from.
     * @return A reference to this `UniqueFd` object.
     */
    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) { // Handle self-assignment
            if (fd_ >= 0)
                close(fd_); // Close current FD before taking ownership
            fd_ = -1;       // Invalidate current FD before swap
            std::swap(fd_, other.fd_);
        }
        return *this;
    }

    /**
     * @brief Assignment from raw int FD. Closes the current FD.
     */
    UniqueFd &operator=(Fd fd) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = fd;
        return *this;
    }

    /**
     * @brief Allows implicit conversion to the underlying file descriptor type.
     * @return The managed file descriptor.
     */
    operator const Fd &() const {
        return fd_;
    }

private:
    Fd fd_ = -1; // The managed file descriptor, initialized to invalid.
};

/**
 * @brief Sets the SELinux context for newly created sockets.
 *
 * This allows the injector to create sockets with a specific security context
 * that might be required for interaction with target processes under SELinux.
 * It attempts to write to `/proc/thread-self/attr/sockcreate` or a process-specific fallback.
 *
 * @param security_context The SELinux context string to set.
 * @return True on success, false on failure.
 */
bool set_sockcreate_con(const char *security_context);

// --- Ptrace Event and Signal Parsing ---

#define WPTEVENT(x) (x >> 16) // Macro to extract the ptrace event code from wait status.
#define CASE_CONST_RETURN(x) \
    case x:                  \
        return #x; // Helper macro for switch-case to return string literal.

/**
 * @brief Parses a ptrace event code into a human-readable string.
 * @param status The wait status containing the ptrace event code.
 * @return A string representing the ptrace event.
 */
inline const char *parse_ptrace_event(int status) {
    status = WPTEVENT(status); // Extract the event code.
    switch (status) {
        CASE_CONST_RETURN(PTRACE_EVENT_FORK)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK)
        CASE_CONST_RETURN(PTRACE_EVENT_CLONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXEC)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK_DONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXIT)
        CASE_CONST_RETURN(PTRACE_EVENT_SECCOMP)
        CASE_CONST_RETURN(PTRACE_EVENT_STOP) // Not a standard event, but sometimes
                                             // seen for special stops
    default:
        return "(no event)"; // Default for unknown or no event.
    }
}

/**
 * @brief Returns the abbreviated name of a signal.
 * @param sig The signal number.
 * @return The abbreviated signal name (e.g., "SIGSEGV"), or "(unknown)".
 */
inline const char *sigabbrev_np(int sig) {
    // NSIG is the total number of signals, sys_signame array is indexed by signal
    // number. Note: sys_signame is part of glibc and may require _GNU_SOURCE or
    // similar.
    if (sig > 0 && sig < NSIG)
        return sys_signame[sig];
    return "(unknown)";
}

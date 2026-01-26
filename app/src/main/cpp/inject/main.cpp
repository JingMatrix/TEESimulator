#include <android/dlext.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "logging.hpp" // Custom logging utilities
#include "lsplt.hpp"   // Library for scanning memory maps
#include "utils.hpp"   // Utility functions for ptrace, remote memory, etc.

using namespace std::string_literals;

/*
       +-----------------------------------+
       |        Injector (main.cpp)        |
       +-----------------------------------+
                       |
                       | 1. PTRACE_ATTACH: Attach to target process
                       V
+-----------------------------------------------------------------+
|                    Target Process (PID)                         |
|                                                                 |
|  +-----------------------------------------------------------+  |
|  |           Registers Backup / Restore (Ptrace)             |  |
|  +-----------------------------------------------------------+  |
|                      ^                                          |
|                      | 2. GET/SET REGS: Save and restore        |
|                      v    the target's CPU registers.           |
|  +-----------------------------------------------------------+  |
|  |           Memory Map Scanning (lsplt::MapInfo)            |  |
|  +-----------------------------------------------------------+  |
|                      ^                                          |
|                      | 3. Scan Maps: Identify module bases      |
|                      v    and their memory regions.             |
|  +-----------------------------------------------------------+  |
|  |           Remote FD Transfer (Unix Domain Socket)         |  |
|  |(Library FD from Injector -> Target Process via SCM_RIGHTS)|
|  +-----------------------------------------------------------+  |
|                      ^                                          |
|                      | 4. sendmsg/recvmsg: IPC for FD passing   |
|                      v                                          |
|  +-----------------------------------------------------------+  |
|  |         Remote Library Loading (android_dlopen_ext)       |  |
|  |    (Loads shared library using the transferred FD)        |  |
|  +-----------------------------------------------------------+  |
|                      ^                                          |
|                      | 5. remote_call: Execute dlopen remotely  |
|                      v                                          |
|  +-----------------------------------------------------------+  |
|  |             Entry Point Resolution (dlsym)                |  |
|  +-----------------------------------------------------------+  |
|                      ^                                          |
|                      | 6. remote_call: Execute dlsym remotely   |
|                      v                                          |
|  +-----------------------------------------------------------+  |
|  |             Entry Point Execution (remote_call)           |  |
|  +-----------------------------------------------------------+  |
|                                                                 |
+-----------------------------------------------------------------+
                       |
                       | 7. PTRACE_DETACH: Detach from target process
                       V
        +-----------------------------------+
        |        Injector (main.cpp)        |
        +-----------------------------------+
                       |
                       V
                     DONE
*/

namespace inject {

// Namespace for constants used throughout the injection process.
namespace constants {
constexpr size_t kMagicLength = 16;
// Length of the random magic string for socket paths.

constexpr size_t kMaxPathLength = PATH_MAX;
// Maximum length for file paths.

constexpr const char *kSystemFileContext = "u:object_r:system_file:s0";
// SELinux context for system files,
// used for socket creation and library file context.

constexpr const char *kLibcModule = "libc.so";
// Name of the C standard library.

constexpr const char *kLibdlModule = "libdl.so";
// Name of the dynamic linker library.
} // namespace constants

/**
 * @brief Manages a remotely loaded library handle and associated file descriptor.
 *
 * This class uses RAII to ensure the remote file descriptor (if transferred) is closed
 * when the object goes out of scope.
 *
 * Note that this handle does *not* automatically `dlclose` the remotely loaded library.
 * The library remains loaded in the target process.
 */
class RemoteLibraryHandle {
public:
    /**
     * @brief Constructs a RemoteLibraryHandle.
     * @param pid The target process ID.
     * @param fd The file descriptor transferred to the remote process.
     * @param handle The dlopen handle returned by the remote dlopen call.
     */
    RemoteLibraryHandle(int pid, int fd, uintptr_t handle = 0) : pid_(pid), fd_(fd), handle_(handle) {}

    /**
     * @brief Destructor. Attempts to close the remote file descriptor.
     *
     * This ensures the transferred FD is closed in the remote process, preventing leaks.
     * It requires reading remote registers and calling remote `close()` via ptrace.
     */
    ~RemoteLibraryHandle() {
        if (fd_ == -1) {
            return;
        }
        // Only attempt to close if a valid FD exists.

        LOGD("Cleaning up remote file descriptor %d in process %d.", fd_, pid_);

        struct user_regs_struct regs{};
        // We need current registers to perform a remote call.
        if (!get_regs(pid_, regs)) {
            LOGW("Failed to get remote registers for FD cleanup in destructor.");
            return;
        }

        // Scan maps to find the remote 'close' function address.
        std::vector<lsplt::MapInfo> local_map = lsplt::MapInfo::Scan();
        std::vector<lsplt::MapInfo> remote_map = lsplt::MapInfo::Scan(std::to_string(pid_));

        if (auto close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close")) {
            std::vector<uintptr_t> args = {static_cast<uintptr_t>(fd_)};
            // Perform a remote call to close the file descriptor.
            remote_call(pid_, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr_, args);
        } else {
            LOGW("Failed to find remote 'close' function to cleanup transferred FD.");
        }
    }

    // Delete copy constructor and assignment operator to prevent unintended copying.
    RemoteLibraryHandle(const RemoteLibraryHandle &) = delete;
    RemoteLibraryHandle &operator=(const RemoteLibraryHandle &) = delete;

    /**
     * @brief Move constructor.
     * @param other The RemoteLibraryHandle to move from.
     */
    RemoteLibraryHandle(RemoteLibraryHandle &&other) noexcept
        : pid_(other.pid_), fd_(other.fd_), handle_(other.handle_) {
        // Invalidate the 'other' object to prevent it from closing the FD.
        other.fd_ = -1;
        other.handle_ = 0;
    }

    /**
     * @brief Set the remote dlopen handle.
     */
    void set_handle(uintptr_t handle) {
        handle_ = handle;
    }

    /**
     * @brief Get the remote dlopen handle.
     * @return The handle to the remotely loaded library.
     */
    uintptr_t handle() const {
        return handle_;
    }

    /**
     * @brief Set the return address for remote calls.
     */
    void set_libc_return_addr(uintptr_t addr) {
        libc_return_addr_ = addr;
    }

    /**
     * @brief Get the transferred file descriptor.
     * @return The file descriptor in the remote process.
     */
    int fd() const {
        return fd_;
    }

private:
    int pid_;                          // Target process ID.
    int fd_;                           // File descriptor in the remote process.
    uintptr_t handle_;                 // Handle returned by remote dlopen.
    uintptr_t libc_return_addr_ = 0x0; // Return address for remote calls.
};

/**
 * @brief Transfers a file descriptor from the injector process to the remote process.
 *
 * This function uses Unix domain sockets with SCM_RIGHTS to send a file descriptor.
 * It involves setting SELinux contexts, creating local and remote sockets, binding,
 * and then coordinating sendmsg/recvmsg calls using ptrace.
 *
 * @param pid The target process ID.
 * @param lib_path The path to the library file being transferred.
 * @param regs The current registers of the target process (will be modified).
 * @param local_map Memory map of the injector process.
 * @param remote_map Memory map of the target process.
 * @param libc_return_addr A valid return address within libc.so for remote calls.
 * @return An optional integer containing the transferred file descriptor in the
 *  remote process, or std::nullopt if the transfer fails.
 */
static std::optional<int> transfer_fd_to_remote(int pid, const char *lib_path, struct user_regs_struct &regs,
                                                const std::vector<lsplt::MapInfo> &local_map,
                                                const std::vector<lsplt::MapInfo> &remote_map,
                                                uintptr_t libc_return_addr) {
    LOGD("Attempting to transfer file descriptor for library: %s", lib_path);

    // 1. Set SELinux context for socket creation in the injector process.
    // This is crucial for Android where SELinux might prevent socket operations.
    if (!set_sockcreate_con(constants::kSystemFileContext)) {
        LOGE("Failed to set socket creation context.");
        return std::nullopt;
    }

    // 2. Create a local Unix domain socket for FD transfer.
    UniqueFd local_socket = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (local_socket == -1) {
        PLOGE("Failed to create local Unix domain socket.");
        return std::nullopt;
    }

    // 3. Set SELinux context for the library file if possible.
    // This might be required for the target process to open/access it later if directly opening by path.
    // For FD transfer, this is less critical as the FD's context is inherited, but good practice.
    if (setfilecon(lib_path, constants::kSystemFileContext) == -1) {
        // Log a warning, but don't fail, as FD transfer might still work.
        PLOGE("Failed to set context of library file: %s. This might cause issues.", lib_path);
    }

    // 4. Open the local library file to get a file descriptor.
    UniqueFd local_lib_fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (local_lib_fd == -1) {
        PLOGE("Failed to open library file: %s", lib_path);
        return std::nullopt;
    }

    // Struct to hold addresses of remote libc functions needed for socket operations.
    struct RemoteFunctions {
        void *socket_addr;
        void *bind_addr;
        void *recvmsg_addr;
        void *close_addr;
        void *errno_addr; // Address of __errno for getting remote errno.
    } funcs{};

    // 5. Resolve required libc functions in the remote process.
    funcs.socket_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "socket");
    funcs.bind_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "bind");
    funcs.recvmsg_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "recvmsg");
    funcs.close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close");
    funcs.errno_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "__errno");

    if (!funcs.socket_addr || !funcs.bind_addr || !funcs.recvmsg_addr || !funcs.close_addr || !funcs.errno_addr) {
        LOGE("Failed to resolve all required libc functions in remote process.");
        return std::nullopt;
    }

    // Lambda to get the remote errno value.
    auto get_remote_errno = [&]() -> int {
        std::vector<uintptr_t> args; // No args for __errno.
        auto addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.errno_addr), libc_return_addr, args);
        int err = 0;
        if (!addr || !read_proc(pid, addr, &err, sizeof(err))) {
            LOGW("Failed to read remote errno value.");
            return 0;
        }
        return err;
    };

    // Lambda to close a file descriptor in the remote process.
    auto close_remote = [&](int fd) {
        std::vector<uintptr_t> args = {static_cast<uintptr_t>(fd)};
        if (remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.close_addr), libc_return_addr, args) ==
            static_cast<uintptr_t>(-1)) {
            LOGE("Failed to close remote fd %d. Remote errno: %d", fd, get_remote_errno());
        } else {
            LOGV("Successfully closed remote fd %d.", fd);
        }
    };

    // 6. Create a Unix domain socket in the remote process.
    std::vector<uintptr_t> args = {AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0};
    int remote_fd = static_cast<int>(
        remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.socket_addr), libc_return_addr, args));
    if (remote_fd <= 0) {
        // remote_call returns 0 on failure.
        // socket() returning 0 is technically possible (if stdin closed),
        // but highly unlikely for a daemon. We treat 0 as failure here to catch the injection error.
        errno = get_remote_errno(); // Set local errno for PLOGE.
        PLOGE("Failed to create remote socket (returned %d).", remote_fd);
        return std::nullopt;
    }
    LOGD("Successfully created remote socket with FD: %d", remote_fd);

    // 7. Generate a unique magic string for the abstract Unix domain socket path.
    auto magic = generateMagic(constants::kMagicLength);
    struct sockaddr_un sock_addr{.sun_family = AF_UNIX, .sun_path = {0}};
    // Abstract Unix domain sockets have sun_path[0] as null, and the name starts from sun_path[1].
    memcpy(sock_addr.sun_path + 1, magic.c_str(), magic.size());
    socklen_t addr_len = sizeof(sock_addr.sun_family) + 1 + magic.size(); // Length includes null byte and magic.

    // 8. Push the sockaddr_un structure to the remote process's stack.
    auto remote_addr = push_memory(pid, regs, &sock_addr, sizeof(sock_addr));
    if (remote_addr == 0) {
        LOGE("Failed to push socket address to remote memory.");
        close_remote(remote_fd);
        return std::nullopt;
    }

    // 9. Bind the remote socket to the abstract Unix domain socket path.
    args = {static_cast<uintptr_t>(remote_fd), remote_addr, static_cast<uintptr_t>(addr_len)};
    auto bind_result = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.bind_addr), libc_return_addr, args);
    if (bind_result == static_cast<uintptr_t>(-1)) {
        errno = get_remote_errno();
        PLOGE("Failed to bind remote socket to path: %s", magic.c_str());
        close_remote(remote_fd);
        return std::nullopt;
    }
    LOGD("Remote socket bound to path: %s", magic.c_str());

    // Prepare control message buffer for SCM_RIGHTS (file descriptor passing).
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = {0};

    // 10. Push the control message buffer to the remote process's stack.
    auto remote_cmsgbuf = push_memory(pid, regs, &cmsgbuf, sizeof(cmsgbuf));
    if (remote_cmsgbuf == 0) {
        LOGE("Failed to push control message buffer to remote memory.");
        close_remote(remote_fd);
        return std::nullopt;
    }

    // Prepare msghdr structure for recvmsg call.
    struct msghdr msg_hdr{};
    msg_hdr.msg_control = reinterpret_cast<void *>(remote_cmsgbuf);
    msg_hdr.msg_controllen = sizeof(cmsgbuf);

    // 11. Push the msghdr structure to the remote process's stack.
    auto remote_hdr = push_memory(pid, regs, &msg_hdr, sizeof(msg_hdr));
    if (remote_hdr == 0) {
        LOGE("Failed to push message header to remote memory.");
        close_remote(remote_fd);
        return std::nullopt;
    }

    // 12. Initiate the remote recvmsg call. This will block the remote process.
    args = {static_cast<uintptr_t>(remote_fd), remote_hdr, MSG_WAITALL};
    if (!remote_pre_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.recvmsg_addr), 0, args)) {
        LOGE("Failed to initiate remote recvmsg call.");
        close_remote(remote_fd);
        return std::nullopt;
    }
    LOGD("Remote recvmsg initiated, waiting for FD transfer...");

    // 13. Prepare the local msghdr for sending the file descriptor.
    // The msg_control and msg_name fields of the local msghdr are set up.
    msg_hdr.msg_control = &cmsgbuf; // Use local cmsgbuf for sending.
    msg_hdr.msg_name = &sock_addr;
    msg_hdr.msg_namelen = addr_len;

    // Set up the control message to include the file descriptor.
    {
        auto *cmsg = CMSG_FIRSTHDR(&msg_hdr);
        if (!cmsg) {
            LOGE("CMSG_FIRSTHDR returned null, internal error.");
            close_remote(remote_fd);
            return std::nullopt;
        }
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        *reinterpret_cast<int *>(CMSG_DATA(cmsg)) = local_lib_fd; // The FD to send.
    }

    // 14. Send the file descriptor from the injector to the remote process.
    if (sendmsg(local_socket, &msg_hdr, 0) == -1) {
        PLOGE("Failed to send file descriptor to remote process.");
        // We do not close local_lib_fd here as it might be transferred even if
        // sendmsg errors, or could be intended for further use. The destructor of
        // UniqueFd will handle it.
        close_remote(remote_fd);
        return std::nullopt;
    }
    LOGD("Local FD %d sent to remote process.", local_lib_fd.operator const int &());

    // 15. Complete the remote recvmsg call. This will retrieve the return value.
    auto recvmsg_result =
        static_cast<ssize_t>(remote_post_call(pid, regs, 0)); // No specific expected return address for recvmsg
    if (recvmsg_result == -1) {
        errno = get_remote_errno();
        PLOGE("Remote recvmsg call failed.");
        close_remote(remote_fd);
        return std::nullopt;
    }
    LOGD("Remote recvmsg completed with result: %zd", recvmsg_result);

    // 16. Read the control message buffer back from the remote process to extract the FD.
    if (read_proc(pid, remote_cmsgbuf, &cmsgbuf, sizeof(cmsgbuf)) != sizeof(cmsgbuf)) {
        LOGE("Failed to read control message buffer from remote process.");
        close_remote(remote_fd);
        return std::nullopt;
    }

    // Parse the control message to get the transferred FD.
    auto *cmsg = CMSG_FIRSTHDR(&msg_hdr);
    if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS) {
        LOGE("Invalid control message received from remote process. Expected "
             "SCM_RIGHTS.");
        close_remote(remote_fd);
        return std::nullopt;
    }

    int transferred_fd = *reinterpret_cast<int *>(CMSG_DATA(cmsg));
    LOGI("Successfully transferred FD %d to remote process, new remote FD: %d", local_lib_fd.operator const int &(),
         transferred_fd);

    // 17. Close the remote socket.
    close_remote(remote_fd);

    return transferred_fd;
}

/**
 * @brief Retrieves the error string from dlerror in the remote process.
 *
 * This function performs remote calls to `dlerror` and `strlen` to read
 * the error message from the remote process's memory.
 *
 * @param pid The target process ID.
 * @param regs The current registers of the target process (will be modified).
 * @param local_map Memory map of the injector process.
 * @param remote_map Memory map of the target process.
 * @param libc_return_addr A valid return address within libc.so for remote calls.
 * @return The error string from remote dlerror, or an explanatory message if retrieval fails.
 */
static std::string get_remote_dlerror(int pid, struct user_regs_struct &regs,
                                      const std::vector<lsplt::MapInfo> &local_map,
                                      const std::vector<lsplt::MapInfo> &remote_map, uintptr_t libc_return_addr) {
    auto dlerror_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlerror");
    if (!dlerror_addr) {
        return "Failed to find dlerror function in remote libdl.";
    }

    std::vector<uintptr_t> args; // dlerror takes no arguments.
    // Call dlerror remotely to get the address of the error string.
    auto dlerror_str_addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlerror_addr), libc_return_addr, args);
    if (dlerror_str_addr == 0) {
        // According to dlerror man page, it can return NULL if no error has occurred.
        // For our use case (after a failed dlopen/dlsym), a null return implies a problem.
        return "Remote dlerror returned null (no error message available or an issue occurred).";
    }

    // To read the string, we first need its length using remote strlen.
    auto strlen_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "strlen");
    if (!strlen_addr) {
        return "Failed to find strlen function in remote libc.";
    }

    args.clear();
    args.push_back(dlerror_str_addr);
    auto dlerror_len = remote_call(pid, regs, reinterpret_cast<uintptr_t>(strlen_addr), libc_return_addr, args);
    if (dlerror_len <= 0 || dlerror_len > 1024) { // Basic sanity check for length.
        return "Invalid dlerror string length received from remote strlen.";
    }

    std::string err;
    err.resize(dlerror_len + 1, 0); // Resize to include null terminator.
    // Read the error string from the remote process.
    if (read_proc(pid, dlerror_str_addr, err.data(), dlerror_len) != static_cast<ssize_t>(dlerror_len)) {
        return "Failed to read remote dlerror string from target process memory.";
    }
    err.resize(dlerror_len); // Trim null terminator if present.
    return err;
}

/**
 * @brief Remotely calls android_dlopen_ext to load a shared library.
 *
 * This function handles pushing the library path and dlextinfo structure
 * to the remote process's memory and then executing android_dlopen_ext.
 *
 * @param pid The target process ID.
 * @param regs The current registers of the target process (will be modified).
 * @param local_map Memory map of the injector process.
 * @param remote_map Memory map of the target process.
 * @param lib_fd The file descriptor of the library to load, previously transferred.
 * @param lib_path The path to the library (used for debugging/error messages).
 * @param libc_return_addr A valid return address within libc.so for remote calls.
 * @return An optional uintptr_t containing the handle to the loaded library, or std::nullopt if loading fails.
 */
static std::optional<uintptr_t> remote_dlopen(int pid, struct user_regs_struct &regs,
                                              const std::vector<lsplt::MapInfo> &local_map,
                                              const std::vector<lsplt::MapInfo> &remote_map, int lib_fd,
                                              const char *lib_path, uintptr_t libc_return_addr) {
    LOGD("Attempting remote dlopen for library: %s with FD: %d", lib_path, lib_fd);

    auto dlopen_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "android_dlopen_ext");
    if (!dlopen_addr) {
        LOGE("Failed to find 'android_dlopen_ext' in remote '%s'.", constants::kLibdlModule);
        // Fallback to 'dlopen' if 'android_dlopen_ext' is not found.
        // This is a common pattern for broader compatibility.
        dlopen_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlopen");
        if (!dlopen_addr) {
            LOGE("Failed to find 'dlopen' in remote '%s' either. Cannot load library.", constants::kLibdlModule);
            return std::nullopt;
        }
        LOGW("Using 'dlopen' as 'android_dlopen_ext' was not found. FD passing might not be supported.");
        // If falling back to dlopen, FD passing is not directly supported, and `dlext_info` becomes irrelevant.
        //
        // In this case, `lib_path` would need to be a valid path accessible to the target process.
    }

    // Setup android_dlextinfo structure to pass the file descriptor.
    android_dlextinfo dlext_info{};
    dlext_info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    dlext_info.library_fd = lib_fd;

    // Push the dlext_info structure and library path string to the remote stack.
    uintptr_t remote_info = push_memory(pid, regs, &dlext_info, sizeof(dlext_info));
    uintptr_t remote_path = push_string(pid, regs, lib_path);

    if (remote_info == 0 || remote_path == 0) {
        LOGE("Failed to push dlopen arguments to remote memory.");
        return std::nullopt;
    }

    // Perform the remote call to android_dlopen_ext.
    // Arguments: const char* filename, int flags, const android_dlextinfo* extinfo
    std::vector<uintptr_t> args = {remote_path, RTLD_NOW, remote_info};
    uintptr_t remote_handle = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlopen_addr), libc_return_addr, args);

    if (remote_handle == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr);
        LOGE("Remote dlopen failed for library: %s. dlerror: %s", lib_path, error_msg.c_str());
        return std::nullopt;
    }

    LOGI("Successfully loaded library '%s' in remote process. Handle: %p", lib_path,
         reinterpret_cast<void *>(remote_handle));
    return remote_handle;
}

/**
 * @brief Remotely calls dlsym to find the address of a symbol within a loaded
 * library.
 *
 * @param pid The target process ID.
 * @param regs The current registers of the target process (will be modified).
 * @param entry_name The name of remote entry point function.
 * @param local_map Memory map of the injector process.
 * @param remote_map Memory map of the target process.
 * @param remote_handle The handle to the remotely loaded library.
 * @param libc_return_addr A valid return address within libc.so for remote calls.
 * @return An optional uintptr_t containing the address of the resolved symbol,
 *  or std::nullopt if the symbol is not found.
 */
static std::optional<uintptr_t> remote_find_entry(int pid, struct user_regs_struct &regs, const char *entry_name,
                                                  const std::vector<lsplt::MapInfo> &local_map,
                                                  const std::vector<lsplt::MapInfo> &remote_map,
                                                  uintptr_t remote_handle, uintptr_t libc_return_addr) {
    LOGD("Attempting to find remote entry symbol '%s' in library handle %p.", entry_name,
         reinterpret_cast<void *>(remote_handle));

    auto dlsym_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlsym");
    if (!dlsym_addr) {
        LOGE("Failed to find 'dlsym' in remote '%s'.", constants::kLibdlModule);
        return std::nullopt;
    }

    // Push the entry symbol name string to the remote stack.
    uintptr_t remote_symbol = push_string(pid, regs, entry_name);
    if (remote_symbol == 0) {
        LOGE("Failed to push entry symbol name to remote memory.");
        return std::nullopt;
    }

    // Perform the remote call to dlsym.
    // Arguments: void* handle, const char* symbol
    std::vector<uintptr_t> args = {remote_handle, remote_symbol};
    uintptr_t entry_addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlsym_addr), libc_return_addr, args);

    if (entry_addr == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr);
        LOGE("Failed to find entry symbol '%s' in remote library (handle %p). dlerror: %s", entry_name,
             reinterpret_cast<void *>(remote_handle), error_msg.c_str());
        return std::nullopt;
    }

    LOGI("Found entry point '%s' at remote address: %p", entry_name, reinterpret_cast<void *>(entry_addr));
    return entry_addr;
}

/**
 * @brief Remotely calls the found entry point function in the injected library.
 *
 * The entry point is assumed to take the library handle as its single argument.
 *
 * @param pid The target process ID.
 * @param regs The current registers of the target process (will be modified).
 * @param entry_addr The remote address of the entry point function.
 * @param remote_handle The handle to the remotely loaded library.
 * @param libc_return_addr A valid return address within libc.so for remote calls.
 * @return True if the remote call was initiated successfully, false otherwise.
 */
static bool remote_call_entry(int pid, struct user_regs_struct &regs, uintptr_t entry_addr, uintptr_t remote_handle,
                              uintptr_t libc_return_addr) {
    LOGD("Attempting to call remote entry point at address %p with handle %p.", reinterpret_cast<void *>(entry_addr),
         reinterpret_cast<void *>(remote_handle));

    // Arguments for the entry point (typically just the library handle).
    std::vector<uintptr_t> args = {remote_handle};
    uintptr_t result = remote_call(pid, regs, entry_addr, libc_return_addr, args);

    // The return value of the entry point is logged, but not necessarily checked for success.
    // The interpretation of the return value depends on the injected library's contract.
    LOGI("Remote entry point call completed. Return value: %p", reinterpret_cast<void *>(result));
    return true; // Return true if the call itself completed, regardless of its return value.
}

/**
 * @brief RAII wrapper to ensure a temporary file is deleted (unlinked)
 * when the object goes out of scope.
 *
 * This is crucial for stealth: we want the library to exist on the filesystem
 * for the shortest time possible.
 */
class ScopedFileDeleter {
public:
    explicit ScopedFileDeleter(std::string path) : path_(std::move(path)) {}

    ~ScopedFileDeleter() {
        if (!path_.empty()) {
            LOGD("Cleaning up staged file: %s", path_.c_str());
            unlink(path_.c_str());
        }
    }

    // Disable copy to prevent double-deletion issues
    ScopedFileDeleter(const ScopedFileDeleter&) = delete;
    ScopedFileDeleter& operator=(const ScopedFileDeleter&) = delete;

private:
    std::string path_;
};

/**
 * @brief Copies a file from source to destination.
 *
 * @param src Absolute path to source file.
 * @param dst Absolute path to destination file.
 * @return True on success, false on failure.
 */
static bool copy_file(const char* src, const char* dst) {
    std::ifstream src_file(src, std::ios::binary);
    std::ofstream dst_file(dst, std::ios::binary);

    if (!src_file) {
        PLOGE("Failed to open source file for copying: %s", src);
        return false;
    }
    if (!dst_file) {
        PLOGE("Failed to open destination file for copying: %s", dst);
        return false;
    }

    dst_file << src_file.rdbuf();
    return src_file.good() && dst_file.good();
}

/**
 * @brief Performs injection via the "Staging" method.
 *
 * This strategy is used when direct FD passing fails (e.g., due to Seccomp filters).
 * 1. Copies the library to a world-readable location (/data/local/tmp).
 * 2. Sets permissions and SELinux context to mimic a system library.
 * 3. Loads it via standard dlopen().
 * 4. Immediately deletes the file to hide tracks.
 *
 * @param pid The target process ID.
 * @param regs The target process registers (must be Red-Zone adjusted if x86_64).
 * @param local_map Local memory map.
 * @param remote_map Remote memory map.
 * @param lib_path The path to the original library.
 * @param libc_return_addr Return address for remote calls.
 * @return The handle of the loaded library, or std::nullopt on failure.
 */
static std::optional<uintptr_t> inject_via_staging(int pid, struct user_regs_struct &regs,
                                                   const std::vector<lsplt::MapInfo> &local_map,
                                                   const std::vector<lsplt::MapInfo> &remote_map,
                                                   const char *lib_path, uintptr_t libc_return_addr) {
    LOGI("Initiating Staging Fallback mechanism...");

    // 1. Generate a random path in /data/local/tmp
    // /data/local/tmp is chosen because it is traversable by most contexts.
    std::string staged_path = "/data/local/tmp/lib" + generateMagic(8) + ".so";

    // Ensure the file is deleted when this function exits (Success or Failure).
    // The kernel keeps the inode alive for the mapped process even after unlink.
    ScopedFileDeleter file_guard(staged_path);

    LOGD("Staging library to: %s", staged_path.c_str());

    // 2. Copy the library
    if (!copy_file(lib_path, staged_path.c_str())) {
        LOGE("Failed to copy library during staging.");
        return std::nullopt;
    }

    // 3. Set Permissions to 644 (RW-R--R--)
    // This allows the target process (likely running as a specific UID) to read the file.
    if (chmod(staged_path.c_str(), 0644) != 0) {
        PLOGE("Failed to chmod staged file.");
        return std::nullopt;
    }

    // 4. Set SELinux Context
    if (setfilecon(staged_path.c_str(), constants::kSystemFileContext) != 0) {
        LOGW("Failed to set SELinux context on staged file. Injection might fail if target is enforcing.");
    }

    // 5. Resolve 'dlopen' in the remote process
    auto dlopen_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlopen");
    if (!dlopen_addr) {
        LOGE("Failed to find 'dlopen' in remote process.");
        return std::nullopt;
    }

    // 6. Push the staged path to remote memory
    uintptr_t remote_path_addr = push_string(pid, regs, staged_path.c_str());
    if (remote_path_addr == 0) {
        LOGE("Failed to push staged path string to remote memory.");
        return std::nullopt;
    }

    // 7. Call dlopen(path, RTLD_NOW)
    std::vector<uintptr_t> args = {remote_path_addr, RTLD_NOW};
    uintptr_t handle = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlopen_addr),
                                   libc_return_addr, args);

    if (handle == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr);
        LOGE("Staged dlopen failed. dlerror: %s", error_msg.c_str());
        return std::nullopt;
    }

    LOGI("Successfully loaded staged library. Handle: %p", reinterpret_cast<void*>(handle));
    return handle;
}

/**
 * @brief RAII wrapper for ptrace attachment and detachment.
 *
 * This class ensures that PTRACE_ATTACH is followed by PTRACE_DETACH, even if exceptions or early returns occur.
 */
class PtraceAttachment {
public:
    /**
     * @brief Constructs a PtraceAttachment and attaches to the target process.
     * @param target_pid The PID of the process to attach to.
     */
    explicit PtraceAttachment(int target_pid) : pid_(target_pid), attached_(false) {
        LOGD("Attempting to attach to process %d...", pid_);
        if (ptrace(PTRACE_ATTACH, pid_, 0, 0) == -1) {
            PLOGE("Failed to attach to process %d.", pid_);
            return;
        }
        attached_ = true;
        LOGI("Successfully attached to process %d.", pid_);
    }

    /**
     * @brief Destructor. Detaches from the target process if currently attached.
     */
    ~PtraceAttachment() {
        if (attached_) {
            LOGD("Attempting to detach from process %d...", pid_);
            if (ptrace(PTRACE_DETACH, pid_, 0, 0) == -1) {
                PLOGE("Failed to detach from process %d. Manual cleanup might be required.", pid_);
            } else {
                LOGI("Successfully detached from process %d.", pid_);
            }
        }
    }

    /**
     * @brief Checks if the ptrace attachment was successful.
     * @return True if attached, false otherwise.
     */
    bool is_attached() const {
        return attached_;
    }

    // Delete copy constructor and assignment operator. Ptrace attachments are unique.
    PtraceAttachment(const PtraceAttachment &) = delete;
    PtraceAttachment &operator=(const PtraceAttachment &) = delete;

private:
    int pid_;       // The PID of the attached process.
    bool attached_; // Flag indicating current attachment status.
};

// RAII Class to ensure registers are always restored
class RegisterRestorer {
public:
    RegisterRestorer(int pid, const struct user_regs_struct& original_regs)
        : pid_(pid), regs_(original_regs) {}

    ~RegisterRestorer() {
        // Always restore registers when this object goes out of scope
        if (set_regs(pid_, regs_)) {
            LOGD("Original registers for process %d restored.", pid_);
        } else {
            PLOGE("Failed to restore original registers for process %d.", pid_);
        }
    }
private:
    int pid_;
    struct user_regs_struct regs_;
};

/**
 * @brief Injects a shared library into a target process using ptrace.
 *
 * This is the main orchestration function for the library injection.
 * It handles attachment, remote memory/register manipulation, FD transfer,
 * staging fallback, remote dlopen/dlsym, and remote entry point execution.
 *
 * @param pid The target process ID.
 * @param lib_path The absolute path to the shared library to inject.
 * @param entry_name The name of the entry point function within the library.
 *  (Currently hardcoded to 'entry' internally but kept as param for future flexibility)
 * @return True if injection was successful, false otherwise.
 */
bool inject_library(int pid, const char *lib_path, const char *entry_name) {
    LOGI("Starting injection of library '%s' (entry: '%s') into process %d.", lib_path, entry_name, pid);

    // 1. Ptrace attachment using RAII.
    PtraceAttachment ptrace_guard(pid);
    if (!ptrace_guard.is_attached()) {
        LOGE("Failed to attach to target process %d.", pid);
        return false;
    }

    // 2. Wait for the target process to stop after attachment.
    int status;
    if (!wait_for_trace(pid, &status, __WALL)) {
        LOGE("Failed to wait for target process %d to stop after attachment.", pid);
        return false;
    }

    // Verify the stop reason is SIGSTOP (expected after PTRACE_ATTACH).
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        LOGE("Target process %d stopped for an unexpected reason: %s (expected SIGSTOP).", pid,
             parse_status(status).c_str());
        return false;
    }
    LOGD("Target process %d successfully stopped by SIGSTOP.", pid);

    // 3. Backup and retrieve current registers.
    // Registers are manipulated during remote calls and must be restored afterwards.
    struct user_regs_struct current_regs{}, backup_regs{};
    if (!get_regs(pid, current_regs)) {
        LOGE("Failed to get registers for target process %d.", pid);
        return false;
    }
    backup_regs = current_regs; // Store a copy for restoration.
    LOGD("Process %d registers backed up.", pid);

    // Skip the Red Zone (128 bytes) on x86_64 to prevent stack corruption
    #if defined(__x86_64__)
    current_regs.rsp -= 128;
    #endif

    // Ensures original state is restored even if injection fails/crashes mid-way.
    RegisterRestorer reg_guard(pid, backup_regs);

    // Create a scope to ensure RAII objects are destroyed BEFORE register restoration
    {
        // 4. Scan local and remote memory maps to resolve function addresses.
        LOGD("Scanning memory maps for target process %d...", pid);
        std::vector<lsplt::MapInfo> remote_map = lsplt::MapInfo::Scan(std::to_string(pid));
        std::vector<lsplt::MapInfo> local_map = lsplt::MapInfo::Scan();
        LOGD("Memory maps scanned.");

        // 5. Find a suitable return address within libc.so for remote calls.
        // This address is used to ensure remote calls return to a safe and controlled location.
        auto libc_return_addr = find_module_return_addr(remote_map, constants::kLibcModule);
        if (!libc_return_addr) {
            LOGE("Failed to find a suitable return address for '%s' in target process %d.", constants::kLibcModule,
                 pid);
            return false;
        }
        LOGD("Found libc return address: %p", reinterpret_cast<void *>(libc_return_addr));

        // 6. Attempt to transfer the library's file descriptor to the remote process.
        int remote_fd = -1;
        auto lib_fd_opt = transfer_fd_to_remote(pid, lib_path, current_regs, local_map, remote_map,
                                                reinterpret_cast<uintptr_t>(libc_return_addr));
        std::optional<RemoteLibraryHandle> remote_lib_guard;
        std::optional<uintptr_t> handle_opt;

        if (lib_fd_opt) {
            remote_fd = *lib_fd_opt;
            remote_lib_guard.emplace(pid, remote_fd);
            remote_lib_guard->set_libc_return_addr(reinterpret_cast<uintptr_t>(libc_return_addr));

            LOGD("FD Transfer successful (FD: %d). Attempting android_dlopen_ext...", remote_fd);
            handle_opt = remote_dlopen(pid, current_regs, local_map, remote_map, remote_fd, lib_path,
                                       reinterpret_cast<uintptr_t>(libc_return_addr));
        } else {
            LOGW("Failed to transfer library file descriptor for '%s' to target process %d.", lib_path, pid);
        }

        // 7. Staging Fallback (Copy-Inject-Delete) if FD transfer failed.
        if (!handle_opt) {
            handle_opt = inject_via_staging(pid, current_regs, local_map, remote_map,
                                            lib_path, reinterpret_cast<uintptr_t>(libc_return_addr));
        }
        if (!handle_opt || *handle_opt == 0) {
            LOGE("Failed to load library '%s' in remote process %d.", lib_path, pid);
            // If dlopen fails, the remote_lib_guard.fd() is still valid in the target process and needs to be closed.
            // The RemoteLibraryHandle constructor takes care of this.
            return false;
        }
        uintptr_t handle = *handle_opt;
        if (remote_lib_guard) remote_lib_guard->set_handle(handle);

        // 8. Find the entry point symbol in the remotely loaded library.
        auto entry_opt = remote_find_entry(pid, current_regs, entry_name, local_map, remote_map,
                                           handle, reinterpret_cast<uintptr_t>(libc_return_addr));
        if (!entry_opt) {
            LOGE("Failed to find entry point '%s' in remote library (handle %p).", entry_name,
                 reinterpret_cast<void *>(handle));
            return false;
        }
        uintptr_t entry_addr = *entry_opt;

        // 9. Call the remote entry point function.
        if (!remote_call_entry(pid, current_regs, entry_addr, handle,
                               reinterpret_cast<uintptr_t>(libc_return_addr))) {
            LOGE("Failed to call remote entry point '%s'.", entry_name);
            return false;
        }
    }

    LOGI("Library injection completed successfully for process %d.", pid);
    return true;
}

} // namespace inject

/**
 * @brief Main function for the injector tool.
 *
 * Parses command-line arguments, validates them, and initiates the library injection.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return EXIT_SUCCESS on successful injection, EXIT_FAILURE otherwise.
 */
int main(int argc, char **argv) {

    // Check for correct number of arguments.
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <pid> <lib_path> <entry_name>\n", argv[0]);
        fprintf(stderr, "  pid        - Target process ID\n");
        fprintf(stderr, "  lib_path   - Absolute path to the shared library to inject\n");
        fprintf(stderr, "  entry_name - Entry point symbol name (e.g., 'entry') in "
                        "the library\n");
        return EXIT_FAILURE;
    }

    // Parse and validate PID.
    char *endptr;
    long pid_long = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || pid_long <= 0 || pid_long > INT_MAX) {
        fprintf(stderr, "Error: Invalid PID '%s'. PID must be a positive integer.\n", argv[1]);
        return EXIT_FAILURE;
    }
    int pid = static_cast<int>(pid_long);

    // Resolve and validate library path.
    char resolved_path[inject::constants::kMaxPathLength];
    if (realpath(argv[2], resolved_path) == nullptr) {
        fprintf(stderr, "Error: Failed to resolve library path '%s': %s\n", argv[2], strerror(errno));
        return EXIT_FAILURE;
    }

    if (access(resolved_path, R_OK) != 0) {
        fprintf(stderr, "Error: Library file '%s' is not readable: %s\n", resolved_path, strerror(errno));
        return EXIT_FAILURE;
    }

    // Validate entry name.
    const char *entry_name = argv[3];
    if (strlen(entry_name) == 0) {
        fprintf(stderr, "Error: Entry name cannot be empty.\n");
        return EXIT_FAILURE;
    }

    LOGI("TEESimulator injector starting...");
    bool success = inject::inject_library(pid, resolved_path, entry_name);

    if (success) {
        LOGI("Injection completed successfully.");
        return EXIT_SUCCESS;
    } else {
        LOGE("Injection failed.");
        return EXIT_FAILURE;
    }
}

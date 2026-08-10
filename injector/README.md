# injector

`inject` is a standalone native executable that runs our code inside a process we don't own. The keystore daemon (`keystore2` on API ≥ 31, legacy `keystore` on API 29–30) is a system service we can't recompile or restart with our flags, but our KeyMint/keystore interceptors have to live *in its address space* to hook its Binder handling. `inject` puts them there: it attaches with `ptrace`, loads a shared object into the running daemon, calls the library's `entry()`, and detaches — leaving the daemon running as if nothing happened, now with our hooks installed.

The control daemon drives it in a loop: `inject <pid> <library.so> entry`, re-running each time the keystore daemon's pid changes (it restarts often, and each restart drops our library). The library it loads is `libteesim_keymint.so` or `libteesim_keystore.so`; both export `entry(void*)`.

## Remote calls

Everything here is built on one primitive: calling an arbitrary function *in another process*. `remote_call` in [`utils.cpp`](utils.cpp) does it.

After `PTRACE_ATTACH` the target stops with `SIGSTOP`; we `wait_for_trace` for that, then `get_regs` to snapshot every register (`backup_regs`). To call `f(a, b, …)` we take a working copy of those registers and rewrite them: arguments go into the ABI's argument registers (`rdi/rsi/…` on x86_64, `x0–x7` on arm64, `r0–r3` on arm — see `setup_*_args`), overflow arguments and any pushed structs/strings go on the target's own stack, `REG_IP` (the program counter) is pointed at `f`, and — the key part — we set a **return address we control**. `set_regs` writes this back, `PTRACE_CONT` resumes the target, and it runs `f` for us.

The return address is not real code. `find_module_return_addr` walks the target's maps and returns the start of a **readable, non-executable** page of `libc.so`. On x86_64 we push it on the stack (what a `call` would do); on arm64/arm we load it into the link register (`x30`/`r14`). When `f` finishes and returns *there*, the CPU tries to fetch an instruction from a non-executable page and faults with `SIGSEGV`, faulting address == our return address. That fault is exactly the event that hands control back to us: `waitpid` returns, and `remote_post_call` confirms a clean return by checking `REG_IP == expected_return_addr` (any *other* stop address means `f` crashed somewhere real — it logs `PTRACE_GETSIGINFO` and bails). The function's result is read straight out of `REG_RET` (`rax`/`x0`/`r0`). This is why the "return address" must be a page that exists but can't run: the fault is the signal, not an error.

`remote_pre_call` / `remote_post_call` are the same thing split in two, used once — for `recvmsg`, where we need to leave the target *parked inside* the call while we act from the outside.

Supporting pieces in [`utils.cpp`](utils.cpp):

- `read_proc` / `write_proc` — move bytes across the process boundary with [`process_vm_readv`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/include/sys/uio.h) / `process_vm_writev` (write can fall back to `/proc/<pid>/mem`). No word-at-a-time `PTRACE_PEEK`.
- `push_memory` / `push_string` — reserve space on the target's stack (decrement `REG_SP`, 16-byte align, write). Return the remote address so it can be passed as a pointer argument.
- `find_func_addr` — resolves a remote function without symbols in the target. It `dlopen`s the *same* module locally, `dlsym`s the symbol, computes its offset from the local module base, and adds that offset to the module's base **in the target** (found via LSPlt maps). ASLR randomizes the load base but not the internal layout, so the offset is identical across processes — as long as both map the same `libc.so`, which they do (it's the system one).

`REG_SP`, `REG_IP`, `REG_RET` and friends are macros in [`utils.hpp`](include/utils.hpp) that paper over the per-arch register names in `user_regs_struct`.

## Loading the .so

A system process runs under a **restricted linker namespace**. Its dynamic linker will refuse to `dlopen` a path under `/data` no matter what the file permissions say — the namespace's allowed search paths simply don't include it, and the linker rejects the path before it ever opens the file (its `is_accessible` gate matches the path against the namespace's `permitted_paths_` / `default_library_paths_` — see [`linker_namespaces.cpp`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_namespaces.cpp)). So we can't hand `keystore2` a path to our library.

The way around it is `android_dlopen_ext` with [`ANDROID_DLEXT_USE_LIBRARY_FD`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/include/android/dlext.h): give the linker an already-open file descriptor and it loads the ELF from that fd, skipping the path/namespace check entirely. The catch is that the fd has to be valid *in the target's* file table. `transfer_fd_to_remote` gets it there over a Unix socket using `SCM_RIGHTS` (the kernel's fd-passing mechanism — it duplicates the sender's open file into the receiver's table). The dance:

1. Resolve `socket`, `bind`, `recvmsg`, `close`, `__errno` in the target's libc.
2. Remote-call `socket(AF_UNIX, SOCK_DGRAM)` so the target creates the receiving socket **itself** — meaning it lives in keystore's own SELinux domain and credentials, which is what makes the transfer legal.
3. Bind it to an **abstract** address (`sun_path[0] == '\0'`, random 16-char magic after). Abstract sockets have no filesystem entry, so there's no directory to be denied traversal on; they're scoped to the network namespace, which injector and target share.
4. Push a `cmsghdr` buffer and `msghdr` onto the target's stack and start `recvmsg(fd, …, MSG_WAITALL)` with `remote_pre_call` — this leaves the target **blocked inside `recvmsg`**, waiting for a datagram.
5. From the injector, `sendmsg` to that abstract address with the local library fd attached as `SCM_RIGHTS`. The kernel installs a copy in the target.
6. `remote_post_call` finishes the parked `recvmsg`; we `read_proc` the control buffer back out of the target's memory and parse the `SCM_RIGHTS` cmsg to learn the fd *number the target received*. That number is what we pass to `android_dlopen_ext`.

`get_remote_errno` is worth knowing: bionic's `errno` is thread-local, so to read it we remote-call `__errno` (which returns `&errno`) and then `read_proc` the int at that address. That's how the error logs here carry real errno values from calls that happened in another process.

Once `dlopen` succeeds the transferred fd has done its job; `RemoteLibraryHandle`'s destructor remote-calls `close` on it so it doesn't leak in the daemon.

### Staging fallback

If the fd transfer fails — a seccomp filter blocks `recvmsg`/`SCM_RIGHTS`, or the functions won't resolve — `inject_via_staging` copies the library to `/data/local/tmp/lib<magic>.so`, `chmod`s it `0644`, and remote-calls plain `dlopen(path, RTLD_NOW)`. `ScopedFileDeleter` `unlink`s the file immediately after; the inode stays alive because the target has it mapped. This only works where the daemon's namespace is loose enough to `dlopen` a `/data/local/tmp` path — true on Android 10/11's `keystore`, **not** on `keystore2`, whose namespace rejects it. On keystore2, fd passing is the only path that works.

## Loading order and the entry contract

`inject_library` in [`main.cpp`](main.cpp) is the orchestrator. Read the RAII objects as the real control flow — they encode the ordering the injection depends on:

- `PtraceAttachment` — attach on construct, detach on destruct.
- On x86_64, `current_regs.rsp -= 128` up front to step over the **red zone** (128 bytes below `rsp` that the interrupted function may still be using) before we start pushing.
- `RegisterRestorer` holds `backup_regs` and restores them on scope exit, so the target resumes at the exact instruction it was interrupted on.
- An explicit inner `{ }` block wraps the work so that `RemoteLibraryHandle` (which remote-calls `close`) destructs **before** `RegisterRestorer` runs — the fd cleanup needs the target still attached and its registers still in our working state.

The loaded library must export `extern "C" bool entry(void*)`. `remote_find_entry` `dlsym`s it in the target, `remote_call_entry` calls it with the `dlopen` handle as its single argument and logs the return value. We never `dlclose` — the library stays resident. `get_remote_dlerror` reads the target's `dlerror()` string (via remote `dlerror` + `strlen` + `read_proc`) so failed loads report a real reason.

One sharp edge: `inject` reports success once `entry` has been *called*, regardless of what `entry` returns. `remote_call_entry` always returns `true`. So if `entry()` itself fails, `inject` still exits 0, and the control daemon treats that pid as covered. "Injection succeeded" means "the library loaded and `entry` ran," not "the hooks are live" — so the daemon confirms separately by waiting for the library to check in over the `@teesim` control channel, and logs a warning if it never does.

## LSPlt usage

LSPlt is linked in, but only `lsplt::MapInfo::Scan()` is used — it parses `/proc/<pid>/maps` into `{start, end, perms, offset, path}` records. That feeds `find_module_base`, `find_func_addr`, and `find_module_return_addr`. The PLT/GOT rewriting LSPlt is actually built for happens later, **inside** the injected interceptors — not in this tool.

## Files

- [`main.cpp`](main.cpp) — the injection orchestration: `transfer_fd_to_remote`, `remote_dlopen`, `remote_find_entry`, `remote_call_entry`, `inject_via_staging`, and the RAII guards, plus `main`'s argument validation (`realpath` the library, check readability, parse pid).
- [`utils.cpp`](utils.cpp) / [`include/utils.hpp`](include/utils.hpp) — the ptrace primitives: register get/set, remote memory read/write, stack pushing, `remote_call`, symbol/base/return-address resolution, `UniqueFd`, magic-string generation, and status/signal parsing. The header also declares helpers (`remote_mmap`, `switch_mnt_ns`, `do_syscall`, …) that aren't on the injection path — don't assume everything declared is exercised by `inject`.
- [`include/logging.hpp`](include/logging.hpp) — pulls in the shared [`logging.hpp`](include/logging.hpp) and sets `LOG_TAG`.

Builds as the `inject` target in the top-level `CMakeLists.txt` (`-static-libstdc++`, linked against `lsplt` and `log`). Cross-builds per ABI; nothing device-specific at build time.

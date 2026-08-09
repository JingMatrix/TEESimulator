/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <binder/Common.h>

#ifndef BINDER_NO_LIBBASE

#include <android-base/unique_fd.h>

namespace android::binder {
using android::base::borrowed_fd;
using android::base::unique_fd;
} // namespace android::binder

#else // BINDER_NO_LIBBASE

#include <errno.h>
#include <fcntl.h> // not needed for unique_fd, but a lot of users depend on open(3)
#include <unistd.h>

namespace android::binder {

// Container for a file descriptor that automatically closes the descriptor as
// it goes out of scope.
//
//      unique_fd ufd(open("/some/path", "r"));
//      if (!ufd.ok()) return error;
//
//      // Do something useful with ufd.get(), possibly including early 'return'.
//
//      return 0; // Descriptor is closed for you.
//
class LIBBINDER_EXPORTED unique_fd final {
public:
    unique_fd() {}

    explicit unique_fd(int fd) { reset(fd); }
    ~unique_fd() { reset(); }

    unique_fd(const unique_fd&) = delete;
    void operator=(const unique_fd&) = delete;
    unique_fd(unique_fd&& other) noexcept { reset(other.release()); }
    unique_fd& operator=(unique_fd&& s) noexcept {
        int fd = s.fd_;
        s.fd_ = -1;
        reset(fd);
        return *this;
    }

    [[clang::reinitializes]] void reset(int new_value = -1) {
        int previous_errno = errno;

        if (fd_ != -1) {
            ::close(fd_);
        }

        fd_ = new_value;
        errno = previous_errno;
    }

    int get() const { return fd_; }

    bool ok() const { return get() >= 0; }

    [[nodiscard]] int release() {
        int ret = fd_;
        fd_ = -1;
        return ret;
    }

private:
    int fd_ = -1;
};

// A wrapper type that can be implicitly constructed from either int or
// unique_fd. This supports cases where you don't actually own the file
// descriptor, and can't take ownership, but are temporarily acting as if
// you're the owner.
//
// One example would be a function that needs to also allow
// STDERR_FILENO, not just a newly-opened fd. Another example would be JNI code
// that's using a file descriptor that's actually owned by a
// ParcelFileDescriptor or whatever on the Java side, but where the JNI code
// would like to enforce this weaker sense of "temporary ownership".
//
// If you think of unique_fd as being like std::string in that represents
// ownership, borrowed_fd is like std::string_view (and int is like const
// char*).
struct LIBBINDER_EXPORTED borrowed_fd {
    /* implicit */ borrowed_fd(int fd) : fd_(fd) {}                      // NOLINT
    /* implicit */ borrowed_fd(const unique_fd& ufd) : fd_(ufd.get()) {} // NOLINT

    int get() const { return fd_; }

private:
    int fd_ = -1;
};

} // namespace android::binder

#endif // BINDER_NO_LIBBASE

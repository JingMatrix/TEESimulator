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

#include <functional>
#include <optional>

namespace android::binder::impl {

template <typename F>
class scope_guard;

template <typename F>
scope_guard<F> make_scope_guard(F f);

template <typename F>
class scope_guard {
public:
    inline ~scope_guard() {
        if (f_.has_value()) std::move(f_.value())();
    }
    inline void release() { f_.reset(); }

private:
    friend scope_guard<F> android::binder::impl::make_scope_guard<>(F);

    inline scope_guard(F&& f) : f_(std::move(f)) {}

    std::optional<F> f_;
};

template <typename F>
inline scope_guard<F> make_scope_guard(F f) {
    return scope_guard<F>(std::move(f));
}

template <typename F>
constexpr void assert_small_callable() {
    // While this buffer (std::function::__func::__buf_) is an implementation detail generally not
    // accessible to users, it's a good bet to assume its size to be around 3 pointers.
    constexpr size_t kFunctionBufferSize = 3 * sizeof(void*);

    static_assert(sizeof(F) <= kFunctionBufferSize,
                  "Supplied callable is larger than std::function optimization buffer. "
                  "Try using std::ref, but make sure lambda lives long enough to be called.");
}

template <typename T>
class SmallFunction : public std::function<T> {
public:
    template <typename F>
    SmallFunction(F&& f) : std::function<T>(f) {
        assert_small_callable<F>();
    }
};

} // namespace android::binder::impl

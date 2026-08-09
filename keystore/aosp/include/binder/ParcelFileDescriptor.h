/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/unique_fd.h>

namespace android {
namespace os {

/*
 * C++ implementation of the Java class android.os.ParcelFileDescriptor
 */
class LIBBINDER_EXPORTED ParcelFileDescriptor : public android::Parcelable {
public:
    ParcelFileDescriptor();
    explicit ParcelFileDescriptor(binder::unique_fd fd);
    ParcelFileDescriptor(ParcelFileDescriptor&& other) noexcept : mFd(std::move(other.mFd)) { }
    ParcelFileDescriptor& operator=(ParcelFileDescriptor&& other) noexcept = default;
    ~ParcelFileDescriptor() override;

    int get() const { return mFd.get(); }
    binder::unique_fd release() { return std::move(mFd); }
    void reset(binder::unique_fd fd = binder::unique_fd()) { mFd = std::move(fd); }

    // android::Parcelable override:
    android::status_t writeToParcel(android::Parcel* parcel) const override;
    android::status_t readFromParcel(const android::Parcel* parcel) override;

    inline std::string toString() const { return "ParcelFileDescriptor:" + std::to_string(get()); }
    inline bool operator!=(const ParcelFileDescriptor& rhs) const {
        return mFd.get() != rhs.mFd.get();
    }
    inline bool operator<(const ParcelFileDescriptor& rhs) const {
        return mFd.get() < rhs.mFd.get();
    }
    inline bool operator<=(const ParcelFileDescriptor& rhs) const {
        return mFd.get() <= rhs.mFd.get();
    }
    inline bool operator==(const ParcelFileDescriptor& rhs) const {
        return mFd.get() == rhs.mFd.get();
    }
    inline bool operator>(const ParcelFileDescriptor& rhs) const {
        return mFd.get() > rhs.mFd.get();
    }
    inline bool operator>=(const ParcelFileDescriptor& rhs) const {
        return mFd.get() >= rhs.mFd.get();
    }
private:
    binder::unique_fd mFd;
};

} // namespace os
} // namespace android

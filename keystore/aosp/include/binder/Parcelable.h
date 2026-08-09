/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <vector>

#include <utils/Errors.h>
#include <utils/String16.h>

#include <binder/Common.h>

namespace android {

class Parcel;

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wweak-vtables"
#endif

// Abstract interface of all parcelables.
class LIBBINDER_EXPORTED Parcelable {
public:
    virtual ~Parcelable() = default;

    Parcelable() = default;
    Parcelable(const Parcelable&) = default;

    // Write |this| parcelable to the given |parcel|.  Keep in mind that
    // implementations of writeToParcel must be manually kept in sync
    // with readFromParcel and the Java equivalent versions of these methods.
    //
    // Returns android::OK on success and an appropriate error otherwise.
    virtual status_t writeToParcel(Parcel* parcel) const = 0;

    // Read data from the given |parcel| into |this|.  After readFromParcel
    // completes, |this| should have equivalent state to the object that
    // wrote itself to the parcel.
    //
    // Returns android::OK on success and an appropriate error otherwise.
    virtual status_t readFromParcel(const Parcel* parcel) = 0;

    // WARNING: for use by auto-generated code only (AIDL). Should not be used
    // manually, or there is a risk of breaking CTS, GTS, VTS, or CTS-on-GSI
    // tests.
    enum class Stability : int32_t {
        STABILITY_LOCAL,
        STABILITY_VINTF, // corresponds to @VintfStability
    };

    // 'Stable' means this parcelable is guaranteed to be stable for multiple
    // years.
    // It must be guaranteed by setting stability field in aidl_interface.
    // WARNING: getStability() is only expected to be overridden by auto-generated
    // code. Returns true if this parcelable is stable.
    virtual Stability getStability() const { return Stability::STABILITY_LOCAL; }
};  // class Parcelable

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

}  // namespace android

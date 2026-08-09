/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <utils/String16.h>
#include <mutex>
#include <optional>
#include <tuple>

namespace android {
namespace os {
/*
 * C++ implementation of the Java class android.os.ParcelableHolder
 */
class LIBBINDER_EXPORTED ParcelableHolder : public android::Parcelable {
public:
    ParcelableHolder() = delete;
    explicit ParcelableHolder(Stability stability) : mStability(stability){}
    virtual ~ParcelableHolder() = default;
    ParcelableHolder(const ParcelableHolder& other) {
        mParcelable = other.mParcelable;
        mParcelableName = other.mParcelableName;
        if (other.mParcelPtr) {
            mParcelPtr = std::make_unique<Parcel>();
            mParcelPtr->appendFrom(other.mParcelPtr.get(), 0, other.mParcelPtr->dataSize());
        }
        mStability = other.mStability;
    }
    ParcelableHolder(ParcelableHolder&& other) = default;

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

    void reset() {
        this->mParcelable = nullptr;
        this->mParcelableName = std::nullopt;
        this->mParcelPtr = nullptr;
    }

    template <typename T>
    status_t setParcelable(T&& p) {
        using Tt = typename std::decay<T>::type;
        return setParcelable<Tt>(std::make_shared<Tt>(std::forward<T>(p)));
    }

    template <typename T>
    status_t setParcelable(std::shared_ptr<T> p) {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        if (p && this->getStability() > p->getStability()) {
            return android::BAD_VALUE;
        }
        this->mParcelable = p;
        this->mParcelableName = T::getParcelableDescriptor();
        this->mParcelPtr = nullptr;
        return android::OK;
    }

    template <typename T>
    status_t getParcelable(std::shared_ptr<T>* ret) const {
        static_assert(std::is_base_of<Parcelable, T>::value, "T must be derived from Parcelable");
        const String16& parcelableDesc = T::getParcelableDescriptor();
        if (!this->mParcelPtr) {
            if (!this->mParcelable || !this->mParcelableName) {
                ALOGD("empty ParcelableHolder");
                *ret = nullptr;
                return android::OK;
            } else if (parcelableDesc != *mParcelableName) {
                ALOGD("extension class name mismatch expected:%s actual:%s",
                      String8(*mParcelableName).c_str(), String8(parcelableDesc).c_str());
                *ret = nullptr;
                return android::BAD_VALUE;
            }
            *ret = std::static_pointer_cast<T>(mParcelable);
            return android::OK;
        }
        this->mParcelPtr->setDataPosition(0);
        status_t status = this->mParcelPtr->readString16(&this->mParcelableName);
        if (status != android::OK || parcelableDesc != this->mParcelableName) {
            this->mParcelableName = std::nullopt;
            *ret = nullptr;
            return status;
        }
        this->mParcelable = std::make_shared<T>();
        status = mParcelable.get()->readFromParcel(this->mParcelPtr.get());
        if (status != android::OK) {
            this->mParcelableName = std::nullopt;
            this->mParcelable = nullptr;
            *ret = nullptr;
            return status;
        }
        this->mParcelPtr = nullptr;
        *ret = std::static_pointer_cast<T>(mParcelable);
        return android::OK;
    }

    Stability getStability() const override { return mStability; }

    inline std::string toString() const {
        return "ParcelableHolder:" +
                (mParcelableName ? std::string(String8(mParcelableName.value()).c_str())
                                 : "<parceled>");
    }
    inline bool operator!=(const ParcelableHolder& rhs) const {
        return this != &rhs;
    }
    inline bool operator<(const ParcelableHolder& rhs) const {
        return this < &rhs;
    }
    inline bool operator<=(const ParcelableHolder& rhs) const {
        return this <= &rhs;
    }
    inline bool operator==(const ParcelableHolder& rhs) const {
        return this == &rhs;
    }
    inline bool operator>(const ParcelableHolder& rhs) const {
        return this > &rhs;
    }
    inline bool operator>=(const ParcelableHolder& rhs) const {
        return this >= &rhs;
    }

private:
    mutable std::shared_ptr<Parcelable> mParcelable;
    mutable std::optional<String16> mParcelableName;
    mutable std::unique_ptr<Parcel> mParcelPtr;
    Stability mStability;
};
} // namespace os
} // namespace android

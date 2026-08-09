/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <array>
#include <limits>
#include <map> // for legacy reasons
#include <optional>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include <binder/unique_fd.h>
#ifndef BINDER_DISABLE_NATIVE_HANDLE
#include <cutils/native_handle.h>
#endif
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <binder/Common.h>
#include <binder/IInterface.h>
#include <binder/Parcelable.h>

//NOLINTNEXTLINE(google-runtime-int) b/173188702
typedef unsigned long long binder_size_t;

struct flat_binder_object;

// ---------------------------------------------------------------------------
namespace android {

template <typename T> class Flattenable;
template <typename T> class LightFlattenable;
class IBinder;
class IPCThreadState;
class ProcessState;
class RpcSession;
class String8;
class TextOutput;
namespace binder {
class Status;
namespace debug {
class RecordedTransaction;
}
}

class Parcel {
    friend class IPCThreadState;
    friend class RpcState;

public:
    class ReadableBlob;
    class WritableBlob;

    LIBBINDER_EXPORTED Parcel();
    LIBBINDER_EXPORTED ~Parcel();

    LIBBINDER_EXPORTED const uint8_t* data() const;
    LIBBINDER_EXPORTED size_t dataSize() const;
    LIBBINDER_EXPORTED size_t dataAvail() const;
    LIBBINDER_EXPORTED size_t dataPosition() const;
    LIBBINDER_EXPORTED size_t dataCapacity() const;
    LIBBINDER_EXPORTED size_t dataBufferSize() const;

    LIBBINDER_EXPORTED status_t setDataSize(size_t size);

    // this must only be used to set a data position that was previously returned from
    // dataPosition(). If writes are made, the exact same types of writes must be made (e.g.
    // auto i = p.dataPosition(); p.writeInt32(0); p.setDataPosition(i); p.writeInt32(1);).
    // Writing over objects, such as file descriptors and binders, is not supported.
    LIBBINDER_EXPORTED void setDataPosition(size_t pos) const;
    LIBBINDER_EXPORTED status_t setDataCapacity(size_t size);

    LIBBINDER_EXPORTED status_t setData(const uint8_t* buffer, size_t len);

    LIBBINDER_EXPORTED status_t appendFrom(const Parcel* parcel, size_t start, size_t len);

    LIBBINDER_EXPORTED int compareData(const Parcel& other) const;
    LIBBINDER_EXPORTED status_t compareDataInRange(size_t thisOffset, const Parcel& other,
                                                   size_t otherOffset, size_t length,
                                                   int* result) const;

    LIBBINDER_EXPORTED bool allowFds() const;
    LIBBINDER_EXPORTED bool pushAllowFds(bool allowFds);
    LIBBINDER_EXPORTED void restoreAllowFds(bool lastValue);

    LIBBINDER_EXPORTED bool hasFileDescriptors() const;
    LIBBINDER_EXPORTED status_t hasBinders(bool* result) const;
    LIBBINDER_EXPORTED status_t hasFileDescriptorsInRange(size_t offset, size_t length,
                                                          bool* result) const;
    LIBBINDER_EXPORTED status_t hasBindersInRange(size_t offset, size_t length, bool* result) const;

    // returns all binder objects in the Parcel
    LIBBINDER_EXPORTED std::vector<sp<IBinder>> debugReadAllStrongBinders() const;
    // returns all file descriptors in the Parcel
    // does not dup
    LIBBINDER_EXPORTED std::vector<int> debugReadAllFileDescriptors() const;

    // Zeros data when reallocating. Other mitigations may be added
    // in the future.
    //
    // WARNING: some read methods may make additional copies of data.
    // In order to verify this, heap dumps should be used.
    LIBBINDER_EXPORTED void markSensitive() const;

    // For a 'data' Parcel, this should mark the Parcel as being prepared for a
    // transaction on this specific binder object. Based on this, the format of
    // the wire binder protocol may change (data is written differently when it
    // is for an RPC transaction).
    LIBBINDER_EXPORTED void markForBinder(const sp<IBinder>& binder);

    // Whenever possible, markForBinder should be preferred. This method is
    // called automatically on reply Parcels for RPC transactions.
    LIBBINDER_EXPORTED void markForRpc(const sp<RpcSession>& session);

    // Whether this Parcel is written for RPC transactions (after calls to
    // markForBinder or markForRpc).
    LIBBINDER_EXPORTED bool isForRpc() const;

    // Writes the IPC/RPC header.
    LIBBINDER_EXPORTED status_t writeInterfaceToken(const String16& interface);
    LIBBINDER_EXPORTED status_t writeInterfaceToken(const char16_t* str, size_t len);

    // Parses the RPC header, returning true if the interface name
    // in the header matches the expected interface from the caller.
    //
    // Additionally, enforceInterface does part of the work of
    // propagating the StrictMode policy mask, populating the current
    // IPCThreadState, which as an optimization may optionally be
    // passed in.
    LIBBINDER_EXPORTED bool enforceInterface(const String16& interface,
                                             IPCThreadState* threadState = nullptr) const;
    LIBBINDER_EXPORTED bool enforceInterface(const char16_t* interface, size_t len,
                                             IPCThreadState* threadState = nullptr) const;
    LIBBINDER_EXPORTED bool checkInterface(IBinder*) const;

    // Verify there are no bytes left to be read on the Parcel.
    // Returns Status(EX_BAD_PARCELABLE) when the Parcel is not consumed.
    LIBBINDER_EXPORTED binder::Status enforceNoDataAvail() const;

    // This Api is used by fuzzers to skip dataAvail checks.
    LIBBINDER_EXPORTED void setEnforceNoDataAvail(bool enforceNoDataAvail);

    // When fuzzing, we want to remove certain ABI checks that cause significant
    // lost coverage, and we also want to avoid logs that cost too much to write.
    LIBBINDER_EXPORTED void setServiceFuzzing();
    LIBBINDER_EXPORTED bool isServiceFuzzing() const;

    LIBBINDER_EXPORTED void freeData();

    LIBBINDER_EXPORTED size_t objectsCount() const;

    LIBBINDER_EXPORTED status_t errorCheck() const;
    LIBBINDER_EXPORTED void setError(status_t err);

    LIBBINDER_EXPORTED status_t write(const void* data, size_t len);
    LIBBINDER_EXPORTED void* writeInplace(size_t len);
    LIBBINDER_EXPORTED status_t writeInt32(int32_t val);
    LIBBINDER_EXPORTED status_t writeUint32(uint32_t val);
    LIBBINDER_EXPORTED status_t writeInt64(int64_t val);
    LIBBINDER_EXPORTED status_t writeUint64(uint64_t val);
    LIBBINDER_EXPORTED status_t writeFloat(float val);
    LIBBINDER_EXPORTED status_t writeDouble(double val);
    LIBBINDER_EXPORTED status_t writeCString(const char* str)
            __attribute__((deprecated("use AIDL, writeString* instead")));
    LIBBINDER_EXPORTED status_t writeString8(const String8& str);
    LIBBINDER_EXPORTED status_t writeString8(const char* str, size_t len);
    LIBBINDER_EXPORTED status_t writeString16(const String16& str);
    LIBBINDER_EXPORTED status_t writeString16(const std::optional<String16>& str);
    LIBBINDER_EXPORTED status_t writeString16(const std::unique_ptr<String16>& str)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeString16(const char16_t* str, size_t len);
    LIBBINDER_EXPORTED status_t writeStrongBinder(const sp<IBinder>& val);
    LIBBINDER_EXPORTED status_t writeInt32Array(size_t len, const int32_t* val);
    LIBBINDER_EXPORTED status_t writeByteArray(size_t len, const uint8_t* val);
    LIBBINDER_EXPORTED status_t writeBool(bool val);
    LIBBINDER_EXPORTED status_t writeChar(char16_t val);
    LIBBINDER_EXPORTED status_t writeByte(int8_t val);

    // Take a UTF8 encoded string, convert to UTF16, write it to the parcel.
    LIBBINDER_EXPORTED status_t writeUtf8AsUtf16(const std::string& str);
    LIBBINDER_EXPORTED status_t writeUtf8AsUtf16(const std::optional<std::string>& str);
    LIBBINDER_EXPORTED status_t writeUtf8AsUtf16(const std::unique_ptr<std::string>& str)
            __attribute__((deprecated("use std::optional version instead")));

    LIBBINDER_EXPORTED status_t writeByteVector(const std::optional<std::vector<int8_t>>& val);
    LIBBINDER_EXPORTED status_t writeByteVector(const std::unique_ptr<std::vector<int8_t>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeByteVector(const std::vector<int8_t>& val);
    LIBBINDER_EXPORTED status_t writeByteVector(const std::optional<std::vector<uint8_t>>& val);
    LIBBINDER_EXPORTED status_t writeByteVector(const std::unique_ptr<std::vector<uint8_t>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeByteVector(const std::vector<uint8_t>& val);
    LIBBINDER_EXPORTED status_t writeInt32Vector(const std::optional<std::vector<int32_t>>& val);
    LIBBINDER_EXPORTED status_t writeInt32Vector(const std::unique_ptr<std::vector<int32_t>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeInt32Vector(const std::vector<int32_t>& val);
    LIBBINDER_EXPORTED status_t writeInt64Vector(const std::optional<std::vector<int64_t>>& val);
    LIBBINDER_EXPORTED status_t writeInt64Vector(const std::unique_ptr<std::vector<int64_t>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeInt64Vector(const std::vector<int64_t>& val);
    LIBBINDER_EXPORTED status_t writeUint64Vector(const std::optional<std::vector<uint64_t>>& val);
    LIBBINDER_EXPORTED status_t writeUint64Vector(const std::unique_ptr<std::vector<uint64_t>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeUint64Vector(const std::vector<uint64_t>& val);
    LIBBINDER_EXPORTED status_t writeFloatVector(const std::optional<std::vector<float>>& val);
    LIBBINDER_EXPORTED status_t writeFloatVector(const std::unique_ptr<std::vector<float>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeFloatVector(const std::vector<float>& val);
    LIBBINDER_EXPORTED status_t writeDoubleVector(const std::optional<std::vector<double>>& val);
    LIBBINDER_EXPORTED status_t writeDoubleVector(const std::unique_ptr<std::vector<double>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeDoubleVector(const std::vector<double>& val);
    LIBBINDER_EXPORTED status_t writeBoolVector(const std::optional<std::vector<bool>>& val);
    LIBBINDER_EXPORTED status_t writeBoolVector(const std::unique_ptr<std::vector<bool>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeBoolVector(const std::vector<bool>& val);
    LIBBINDER_EXPORTED status_t writeCharVector(const std::optional<std::vector<char16_t>>& val);
    LIBBINDER_EXPORTED status_t writeCharVector(const std::unique_ptr<std::vector<char16_t>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeCharVector(const std::vector<char16_t>& val);
    LIBBINDER_EXPORTED status_t
    writeString16Vector(const std::optional<std::vector<std::optional<String16>>>& val);
    LIBBINDER_EXPORTED status_t
    writeString16Vector(const std::unique_ptr<std::vector<std::unique_ptr<String16>>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeString16Vector(const std::vector<String16>& val);
    LIBBINDER_EXPORTED status_t
    writeUtf8VectorAsUtf16Vector(const std::optional<std::vector<std::optional<std::string>>>& val);
    LIBBINDER_EXPORTED status_t writeUtf8VectorAsUtf16Vector(
            const std::unique_ptr<std::vector<std::unique_ptr<std::string>>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeUtf8VectorAsUtf16Vector(const std::vector<std::string>& val);

    LIBBINDER_EXPORTED status_t
    writeStrongBinderVector(const std::optional<std::vector<sp<IBinder>>>& val);
    LIBBINDER_EXPORTED status_t
    writeStrongBinderVector(const std::unique_ptr<std::vector<sp<IBinder>>>& val)
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t writeStrongBinderVector(const std::vector<sp<IBinder>>& val);

    // Write an IInterface or a vector of IInterface's
    template <typename T,
              std::enable_if_t<std::is_base_of_v<::android::IInterface, T>, bool> = true>
    status_t writeStrongBinder(const sp<T>& val) {
        return writeStrongBinder(T::asBinder(val));
    }
    template <typename T,
              std::enable_if_t<std::is_base_of_v<::android::IInterface, T>, bool> = true>
    status_t writeStrongBinderVector(const std::vector<sp<T>>& val) {
        return writeData(val);
    }
    template <typename T,
              std::enable_if_t<std::is_base_of_v<::android::IInterface, T>, bool> = true>
    status_t writeStrongBinderVector(const std::optional<std::vector<sp<T>>>& val) {
        return writeData(val);
    }

    template <typename T, size_t N>
    status_t writeFixedArray(const std::array<T, N>& val) {
        return writeData(val);
    }
    template <typename T, size_t N>
    status_t writeFixedArray(const std::optional<std::array<T, N>>& val) {
        return writeData(val);
    }

    // Write an Enum vector with underlying type int8_t.
    // Does not use padding; each byte is contiguous.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::vector<T>& val)
            { return writeData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::optional<std::vector<T>>& val)
            { return writeData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    [[deprecated("use std::optional version instead")]] //
    status_t            writeEnumVector(const std::unique_ptr<std::vector<T>>& val)
            { return writeData(val); }
    // Write an Enum vector with underlying type != int8_t.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::vector<T>& val)
            { return writeData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            writeEnumVector(const std::optional<std::vector<T>>& val)
            { return writeData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    [[deprecated("use std::optional version instead")]] //
    status_t            writeEnumVector(const std::unique_ptr<std::vector<T>>& val)
            { return writeData(val); }

    template<typename T>
    status_t            writeParcelableVector(const std::optional<std::vector<std::optional<T>>>& val)
            { return writeData(val); }
    template<typename T>
    [[deprecated("use std::optional version instead")]] //
    status_t            writeParcelableVector(const std::unique_ptr<std::vector<std::unique_ptr<T>>>& val)
            { return writeData(val); }
    template<typename T>
    [[deprecated("use std::optional version instead")]] //
    status_t            writeParcelableVector(const std::shared_ptr<std::vector<std::unique_ptr<T>>>& val)
            { return writeData(val); }
    template<typename T>
    status_t            writeParcelableVector(const std::shared_ptr<std::vector<std::optional<T>>>& val)
            { return writeData(val); }
    template<typename T>
    status_t            writeParcelableVector(const std::vector<T>& val)
            { return writeData(val); }

    template<typename T>
    status_t            writeNullableParcelable(const std::optional<T>& parcelable)
            { return writeData(parcelable); }
    template <typename T>
    status_t writeNullableParcelable(const std::unique_ptr<T>& parcelable) {
        return writeData(parcelable);
    }

    LIBBINDER_EXPORTED status_t writeParcelable(const Parcelable& parcelable);

    template<typename T>
    status_t            write(const Flattenable<T>& val);

    template<typename T>
    status_t            write(const LightFlattenable<T>& val);

    template<typename T>
    status_t            writeVectorSize(const std::vector<T>& val);
    template<typename T>
    status_t            writeVectorSize(const std::optional<std::vector<T>>& val);
    template<typename T>
    status_t            writeVectorSize(const std::unique_ptr<std::vector<T>>& val) __attribute__((deprecated("use std::optional version instead")));

#ifndef BINDER_DISABLE_NATIVE_HANDLE
    // Place a native_handle into the parcel (the native_handle's file-
    // descriptors are dup'ed, so it is safe to delete the native_handle
    // when this function returns).
    // Doesn't take ownership of the native_handle.
    LIBBINDER_EXPORTED status_t writeNativeHandle(const native_handle* handle);
#endif

    // Place a file descriptor into the parcel.  The given fd must remain
    // valid for the lifetime of the parcel.
    // The Parcel does not take ownership of the given fd unless you ask it to.
    LIBBINDER_EXPORTED status_t writeFileDescriptor(int fd, bool takeOwnership = false);

    // Place a file descriptor into the parcel.  A dup of the fd is made, which
    // will be closed once the parcel is destroyed.
    LIBBINDER_EXPORTED status_t writeDupFileDescriptor(int fd);

    // Place a Java "parcel file descriptor" into the parcel.  The given fd must remain
    // valid for the lifetime of the parcel.
    // The Parcel does not take ownership of the given fd unless you ask it to.
    LIBBINDER_EXPORTED status_t writeParcelFileDescriptor(int fd, bool takeOwnership = false);

    // Place a Java "parcel file descriptor" into the parcel.  A dup of the fd is made, which will
    // be closed once the parcel is destroyed.
    LIBBINDER_EXPORTED status_t writeDupParcelFileDescriptor(int fd);

    // Place a file descriptor into the parcel.  This will not affect the
    // semantics of the smart file descriptor. A new descriptor will be
    // created, and will be closed when the parcel is destroyed.
    LIBBINDER_EXPORTED status_t writeUniqueFileDescriptor(const binder::unique_fd& fd);

    // Place a vector of file desciptors into the parcel. Each descriptor is
    // dup'd as in writeDupFileDescriptor
    LIBBINDER_EXPORTED status_t
    writeUniqueFileDescriptorVector(const std::optional<std::vector<binder::unique_fd>>& val);
    LIBBINDER_EXPORTED status_t
    writeUniqueFileDescriptorVector(const std::vector<binder::unique_fd>& val);

    // WARNING: deprecated and incompatible with AIDL. You should use Parcelable
    // definitions outside of Parcel to represent shared memory, such as
    // IMemory or with ParcelFileDescriptor. We should remove this, or move it to be
    // external to Parcel, it's not a very encapsulated API.
    //
    // Writes a blob to the parcel.
    // If the blob is small, then it is stored in-place, otherwise it is
    // transferred by way of an anonymous shared memory region.  Prefer sending
    // immutable blobs if possible since they may be subsequently transferred between
    // processes without further copying whereas mutable blobs always need to be copied.
    // The caller should call release() on the blob after writing its contents.
    LIBBINDER_EXPORTED status_t writeBlob(size_t len, bool mutableCopy, WritableBlob* outBlob);

    // Write an existing immutable blob file descriptor to the parcel.
    // This allows the client to send the same blob to multiple processes
    // as long as it keeps a dup of the blob file descriptor handy for later.
    LIBBINDER_EXPORTED status_t writeDupImmutableBlobFileDescriptor(int fd);

    // Like Parcel.java's writeNoException().  Just writes a zero int32.
    // Currently the native implementation doesn't do any of the StrictMode
    // stack gathering and serialization that the Java implementation does.
    LIBBINDER_EXPORTED status_t writeNoException();

    LIBBINDER_EXPORTED status_t read(void* outData, size_t len) const;
    LIBBINDER_EXPORTED const void* readInplace(size_t len) const;
    LIBBINDER_EXPORTED int32_t readInt32() const;
    LIBBINDER_EXPORTED status_t readInt32(int32_t* pArg) const;
    LIBBINDER_EXPORTED uint32_t readUint32() const;
    LIBBINDER_EXPORTED status_t readUint32(uint32_t* pArg) const;
    LIBBINDER_EXPORTED int64_t readInt64() const;
    LIBBINDER_EXPORTED status_t readInt64(int64_t* pArg) const;
    LIBBINDER_EXPORTED uint64_t readUint64() const;
    LIBBINDER_EXPORTED status_t readUint64(uint64_t* pArg) const;
    LIBBINDER_EXPORTED float readFloat() const;
    LIBBINDER_EXPORTED status_t readFloat(float* pArg) const;
    LIBBINDER_EXPORTED double readDouble() const;
    LIBBINDER_EXPORTED status_t readDouble(double* pArg) const;
    LIBBINDER_EXPORTED bool readBool() const;
    LIBBINDER_EXPORTED status_t readBool(bool* pArg) const;
    LIBBINDER_EXPORTED char16_t readChar() const;
    LIBBINDER_EXPORTED status_t readChar(char16_t* pArg) const;
    LIBBINDER_EXPORTED int8_t readByte() const;
    LIBBINDER_EXPORTED status_t readByte(int8_t* pArg) const;

    // Read a UTF16 encoded string, convert to UTF8
    LIBBINDER_EXPORTED status_t readUtf8FromUtf16(std::string* str) const;
    LIBBINDER_EXPORTED status_t readUtf8FromUtf16(std::optional<std::string>* str) const;
    LIBBINDER_EXPORTED status_t readUtf8FromUtf16(std::unique_ptr<std::string>* str) const
            __attribute__((deprecated("use std::optional version instead")));

    LIBBINDER_EXPORTED const char* readCString() const
            __attribute__((deprecated("use AIDL, use readString*")));
    LIBBINDER_EXPORTED String8 readString8() const;
    LIBBINDER_EXPORTED status_t readString8(String8* pArg) const;
    LIBBINDER_EXPORTED const char* readString8Inplace(size_t* outLen) const;
    LIBBINDER_EXPORTED String16 readString16() const;
    LIBBINDER_EXPORTED status_t readString16(String16* pArg) const;
    LIBBINDER_EXPORTED status_t readString16(std::optional<String16>* pArg) const;
    LIBBINDER_EXPORTED status_t readString16(std::unique_ptr<String16>* pArg) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED const char16_t* readString16Inplace(size_t* outLen) const;
    LIBBINDER_EXPORTED sp<IBinder> readStrongBinder() const;
    LIBBINDER_EXPORTED status_t readStrongBinder(sp<IBinder>* val) const;
    LIBBINDER_EXPORTED status_t readNullableStrongBinder(sp<IBinder>* val) const;

    // Read an Enum vector with underlying type int8_t.
    // Does not use padding; each byte is contiguous.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::vector<T>* val) const
            { return readData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    [[deprecated("use std::optional version instead")]] //
    status_t            readEnumVector(std::unique_ptr<std::vector<T>>* val) const
            { return readData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::optional<std::vector<T>>* val) const
            { return readData(val); }
    // Read an Enum vector with underlying type != int8_t.
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::vector<T>* val) const
            { return readData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    [[deprecated("use std::optional version instead")]] //
    status_t            readEnumVector(std::unique_ptr<std::vector<T>>* val) const
            { return readData(val); }
    template<typename T, std::enable_if_t<std::is_enum_v<T> && !std::is_same_v<typename std::underlying_type_t<T>,int8_t>, bool> = 0>
    status_t            readEnumVector(std::optional<std::vector<T>>* val) const
            { return readData(val); }

    template<typename T>
    status_t            readParcelableVector(
                            std::optional<std::vector<std::optional<T>>>* val) const
            { return readData(val); }
    template<typename T>
    [[deprecated("use std::optional version instead")]] //
    status_t            readParcelableVector(
                            std::unique_ptr<std::vector<std::unique_ptr<T>>>* val) const
            { return readData(val); }
    template<typename T>
    status_t            readParcelableVector(std::vector<T>* val) const
            { return readData(val); }

    LIBBINDER_EXPORTED status_t readParcelable(Parcelable* parcelable) const;

    template<typename T>
    status_t            readParcelable(std::optional<T>* parcelable) const
            { return readData(parcelable); }
    template <typename T>
    status_t readParcelable(std::unique_ptr<T>* parcelable) const {
        return readData(parcelable);
    }

    // If strong binder would be nullptr, readStrongBinder() returns an error.
    // TODO: T must be derived from IInterface, fix for clarity.
    template<typename T>
    status_t            readStrongBinder(sp<T>* val) const;

    template<typename T>
    status_t            readNullableStrongBinder(sp<T>* val) const;

    LIBBINDER_EXPORTED status_t
    readStrongBinderVector(std::optional<std::vector<sp<IBinder>>>* val) const;
    LIBBINDER_EXPORTED status_t
    readStrongBinderVector(std::unique_ptr<std::vector<sp<IBinder>>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readStrongBinderVector(std::vector<sp<IBinder>>* val) const;
    template <typename T,
              std::enable_if_t<std::is_base_of_v<::android::IInterface, T>, bool> = true>
    status_t readStrongBinderVector(std::vector<sp<T>>* val) const {
        return readData(val);
    }
    template <typename T,
              std::enable_if_t<std::is_base_of_v<::android::IInterface, T>, bool> = true>
    status_t readStrongBinderVector(std::optional<std::vector<sp<T>>>* val) const {
        return readData(val);
    }

    LIBBINDER_EXPORTED status_t readByteVector(std::optional<std::vector<int8_t>>* val) const;
    LIBBINDER_EXPORTED status_t readByteVector(std::unique_ptr<std::vector<int8_t>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readByteVector(std::vector<int8_t>* val) const;
    LIBBINDER_EXPORTED status_t readByteVector(std::optional<std::vector<uint8_t>>* val) const;
    LIBBINDER_EXPORTED status_t readByteVector(std::unique_ptr<std::vector<uint8_t>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readByteVector(std::vector<uint8_t>* val) const;
    LIBBINDER_EXPORTED status_t readInt32Vector(std::optional<std::vector<int32_t>>* val) const;
    LIBBINDER_EXPORTED status_t readInt32Vector(std::unique_ptr<std::vector<int32_t>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readInt32Vector(std::vector<int32_t>* val) const;
    LIBBINDER_EXPORTED status_t readInt64Vector(std::optional<std::vector<int64_t>>* val) const;
    LIBBINDER_EXPORTED status_t readInt64Vector(std::unique_ptr<std::vector<int64_t>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readInt64Vector(std::vector<int64_t>* val) const;
    LIBBINDER_EXPORTED status_t readUint64Vector(std::optional<std::vector<uint64_t>>* val) const;
    LIBBINDER_EXPORTED status_t readUint64Vector(std::unique_ptr<std::vector<uint64_t>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readUint64Vector(std::vector<uint64_t>* val) const;
    LIBBINDER_EXPORTED status_t readFloatVector(std::optional<std::vector<float>>* val) const;
    LIBBINDER_EXPORTED status_t readFloatVector(std::unique_ptr<std::vector<float>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readFloatVector(std::vector<float>* val) const;
    LIBBINDER_EXPORTED status_t readDoubleVector(std::optional<std::vector<double>>* val) const;
    LIBBINDER_EXPORTED status_t readDoubleVector(std::unique_ptr<std::vector<double>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readDoubleVector(std::vector<double>* val) const;
    LIBBINDER_EXPORTED status_t readBoolVector(std::optional<std::vector<bool>>* val) const;
    LIBBINDER_EXPORTED status_t readBoolVector(std::unique_ptr<std::vector<bool>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readBoolVector(std::vector<bool>* val) const;
    LIBBINDER_EXPORTED status_t readCharVector(std::optional<std::vector<char16_t>>* val) const;
    LIBBINDER_EXPORTED status_t readCharVector(std::unique_ptr<std::vector<char16_t>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readCharVector(std::vector<char16_t>* val) const;
    LIBBINDER_EXPORTED status_t
    readString16Vector(std::optional<std::vector<std::optional<String16>>>* val) const;
    LIBBINDER_EXPORTED status_t
    readString16Vector(std::unique_ptr<std::vector<std::unique_ptr<String16>>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readString16Vector(std::vector<String16>* val) const;
    LIBBINDER_EXPORTED status_t readUtf8VectorFromUtf16Vector(
            std::optional<std::vector<std::optional<std::string>>>* val) const;
    LIBBINDER_EXPORTED status_t readUtf8VectorFromUtf16Vector(
            std::unique_ptr<std::vector<std::unique_ptr<std::string>>>* val) const
            __attribute__((deprecated("use std::optional version instead")));
    LIBBINDER_EXPORTED status_t readUtf8VectorFromUtf16Vector(std::vector<std::string>* val) const;

    template <typename T, size_t N>
    status_t readFixedArray(std::array<T, N>* val) const {
        return readData(val);
    }
    template <typename T, size_t N>
    status_t readFixedArray(std::optional<std::array<T, N>>* val) const {
        return readData(val);
    }

    template<typename T>
    status_t            read(Flattenable<T>& val) const;

    template<typename T>
    status_t            read(LightFlattenable<T>& val) const;

    // resizeOutVector is used to resize AIDL out vector parameters.
    template<typename T>
    status_t            resizeOutVector(std::vector<T>* val) const;
    template<typename T>
    status_t            resizeOutVector(std::optional<std::vector<T>>* val) const;
    template<typename T>
    status_t            resizeOutVector(std::unique_ptr<std::vector<T>>* val) const __attribute__((deprecated("use std::optional version instead")));

    // Like Parcel.java's readExceptionCode().  Reads the first int32
    // off of a Parcel's header, returning 0 or the negative error
    // code on exceptions, but also deals with skipping over rich
    // response headers.  Callers should use this to read & parse the
    // response headers rather than doing it by hand.
    LIBBINDER_EXPORTED int32_t readExceptionCode() const;

#ifndef BINDER_DISABLE_NATIVE_HANDLE
    // Retrieve native_handle from the parcel. This returns a copy of the
    // parcel's native_handle (the caller takes ownership). The caller
    // must free the native_handle with native_handle_close() and
    // native_handle_delete().
    LIBBINDER_EXPORTED native_handle* readNativeHandle() const;
#endif

    // Retrieve a file descriptor from the parcel.  This returns the raw fd
    // in the parcel, which you do not own -- use dup() to get your own copy.
    LIBBINDER_EXPORTED int readFileDescriptor() const;

    // Retrieve a Java "parcel file descriptor" from the parcel.  This returns the raw fd
    // in the parcel, which you do not own -- use dup() to get your own copy.
    LIBBINDER_EXPORTED int readParcelFileDescriptor() const;

    // Retrieve a smart file descriptor from the parcel.
    LIBBINDER_EXPORTED status_t readUniqueFileDescriptor(binder::unique_fd* val) const;

    // Retrieve a Java "parcel file descriptor" from the parcel.
    LIBBINDER_EXPORTED status_t readUniqueParcelFileDescriptor(binder::unique_fd* val) const;

    // Retrieve a vector of smart file descriptors from the parcel.
    LIBBINDER_EXPORTED status_t
    readUniqueFileDescriptorVector(std::optional<std::vector<binder::unique_fd>>* val) const;
    LIBBINDER_EXPORTED status_t
    readUniqueFileDescriptorVector(std::vector<binder::unique_fd>* val) const;

    // WARNING: deprecated and incompatible with AIDL. You should use Parcelable
    // definitions outside of Parcel to represent shared memory, such as
    // IMemory or with ParcelFileDescriptor. We should remove this, or move it to be
    // external to Parcel, it's not a very encapsulated API.
    //
    // Reads a blob from the parcel.
    // The caller should call release() on the blob after reading its contents.
    LIBBINDER_EXPORTED status_t readBlob(size_t len, ReadableBlob* outBlob) const;

    LIBBINDER_EXPORTED const flat_binder_object* readObject(bool nullMetaData) const;

    // Debugging: get metrics on current allocations.
    LIBBINDER_EXPORTED static size_t getGlobalAllocSize();
    LIBBINDER_EXPORTED static size_t getGlobalAllocCount();

    LIBBINDER_EXPORTED bool replaceCallingWorkSourceUid(uid_t uid);
    // Returns the work source provided by the caller. This can only be trusted for trusted calling
    // uid.
    LIBBINDER_EXPORTED uid_t readCallingWorkSourceUid() const;

    LIBBINDER_EXPORTED void print(std::ostream& to, uint32_t flags = 0) const;

private:
    // Close all file descriptors in the parcel at object positions >= newObjectsSize.
    void closeFileDescriptors(size_t newObjectsSize);

    // `objects` and `objectsSize` always 0 for RPC Parcels.
    typedef void (*release_func)(const uint8_t* data, size_t dataSize, const binder_size_t* objects,
                                 size_t objectsSize);

    uintptr_t           ipcData() const;
    size_t              ipcDataSize() const;
    uintptr_t           ipcObjects() const;
    size_t              ipcObjectsCount() const;
    void ipcSetDataReference(const uint8_t* data, size_t dataSize, const binder_size_t* objects,
                             size_t objectsCount, release_func relFunc);
    // Takes ownership even when an error is returned.
    status_t rpcSetDataReference(
            const sp<RpcSession>& session, const uint8_t* data, size_t dataSize,
            const uint32_t* objectTable, size_t objectTableSize,
            std::vector<std::variant<binder::unique_fd, binder::borrowed_fd>>&& ancillaryFds,
            release_func relFunc);

    status_t            finishWrite(size_t len);
    void                releaseObjects();
    void                acquireObjects();
    status_t            growData(size_t len);
    // Clear the Parcel and set the capacity to `desired`.
    // Doesn't reset the RPC session association.
    status_t            restartWrite(size_t desired);
    // Set the capacity to `desired`, truncating the Parcel if necessary.
    status_t            continueWrite(size_t desired);
    status_t truncateRpcObjects(size_t newObjectsSize);
    status_t writeObject(const flat_binder_object& val, bool nullMetaData);
    status_t            writePointer(uintptr_t val);
    status_t            readPointer(uintptr_t *pArg) const;
    uintptr_t           readPointer() const;
    void                freeDataNoInit();
    void                initState();
    void                scanForFds() const;
    status_t scanForBinders(bool* result) const;

    status_t            validateReadData(size_t len) const;

    void                updateWorkSourceRequestHeaderPosition() const;

    status_t            finishFlattenBinder(const sp<IBinder>& binder);
    status_t            finishUnflattenBinder(const sp<IBinder>& binder, sp<IBinder>* out) const;
    status_t            flattenBinder(const sp<IBinder>& binder);
    status_t            unflattenBinder(sp<IBinder>* out) const;

    LIBBINDER_EXPORTED status_t readOutVectorSizeWithCheck(size_t elmSize, int32_t* size) const;

    template<class T>
    status_t            readAligned(T *pArg) const;

    template<class T>   T readAligned() const;

    template<class T>
    status_t            writeAligned(T val);

    status_t            writeRawNullableParcelable(const Parcelable*
                                                   parcelable);

    //-----------------------------------------------------------------------------
    // Generic type read and write methods for Parcel:
    //
    // readData(T *value) will read a value from the Parcel.
    // writeData(const T& value) will write a value to the Parcel.
    //
    // Our approach to parceling is based on two overloaded functions
    // readData() and writeData() that generate parceling code for an
    // object automatically based on its type. The code from templates are generated at
    // compile time (if constexpr), and decomposes an object through a call graph matching
    // recursive descent of the template typename.
    //
    // This approach unifies handling of complex objects,
    // resulting in fewer lines of code, greater consistency,
    // extensibility to nested types, efficiency (decisions made at compile time),
    // and better code maintainability and optimization.
    //
    // Design decision: Incorporate the read and write code into Parcel rather than
    // as a non-intrusive serializer that emits a byte stream, as we have
    // active objects, alignment, legacy code, and historical idiosyncrasies.
    //
    // --- Overview
    //
    // Parceling is a way of serializing objects into a sequence of bytes for communication
    // between processes, as part of marshaling data for remote procedure calls.
    //
    // The Parcel instance contains objects serialized as bytes, such as the following:
    //
    // 1) Ordinary primitive data such as int, float.
    // 2) Established structured data such as String16, std::string.
    // 3) Parcelables, which are C++ objects that derive from Parcelable (and thus have a
    //    readFromParcel and writeToParcel method).  (Similar for Java)
    // 4) A std::vector<> of such data.
    // 5) Nullable objects contained in std::optional, std::unique_ptr, or std::shared_ptr.
    //
    // And active objects from the Android ecosystem such as:
    // 6) File descriptors, unique_fd (kernel object handles)
    // 7) Binder objects, sp<IBinder> (active Android RPC handles)
    //
    // Objects from (1) through (5) serialize into the mData buffer.
    // Active objects (6) and (7) serialize into both mData and mObjects buffers.
    //
    // --- Data layout details
    //
    // Data is read or written to the parcel by recursively decomposing the type of the parameter
    // type T through readData() and writeData() methods.
    //
    // We focus on writeData() here in our explanation of the data layout.
    //
    // 1) Alignment
    // Implementation detail: Regardless of the parameter type, writeData() calls are designed
    // to finish at a multiple of 4 bytes, the default alignment of the Parcel.
    //
    // Writes of single uint8_t, int8_t, enums based on types of size 1, char16_t, etc
    // will result in 4 bytes being written.  The data is widened to int32 and then written;
    // hence the position of the nonzero bytes depend on the native endianness of the CPU.
    //
    // Writes of primitive values with 8 byte size, double, int64_t, uint64_t,
    // are stored with 4 byte alignment.  The ARM and x86/x64 permit unaligned reads
    // and writes (albeit with potential latency/throughput penalty) which may or may
    // not be observable unless the process is IO bound.
    //
    // 2) Parcelables
    // Parcelables are detected by the type's base class, and implemented through calling
    // into the Parcelable type's readFromParcel() or writeToParcel() methods.
    // Historically, due to null object detection, a (int32_t) 1 is prepended to the data written.
    // Parcelables must have a default constructor (i.e. one that takes no arguments).
    //
    // 3) Arrays
    // Arrays of uint8_t and int8_t, and enums based on size 1 are written as
    // a contiguous packed byte stream.  Hidden zero padding is applied at the end of the byte
    // stream to make a multiple of 4 bytes (and prevent info leakage when writing).
    //
    // All other array writes can be conceptually thought of as recursively calling
    // writeData on the individual elements (though may be implemented differently for speed).
    // As discussed in (1), alignment rules are therefore applied for each element
    // write (not as an aggregate whole), so the wire representation of data can be
    // substantially larger.
    //
    // Historical Note:
    // Because of element-wise alignment, CharVector and BoolVector are expanded
    // element-wise into integers even though they could have been optimized to be packed
    // just like uint8_t, int8_t (size 1 data).
    //
    // 3.1) Arrays accessed by the std::vector type.  This is the default for AIDL.
    //
    // 4) Nullables
    // std::optional, std::unique_ptr, std::shared_ptr are all parceled identically
    // (i.e. result in identical byte layout).
    // The target of the std::optional, std::unique_ptr, or std::shared_ptr
    // can either be a std::vector, String16, std::string, or a Parcelable.
    //
    // Detection of null relies on peeking the first int32 data and checking if the
    // the peeked value is considered invalid for the object:
    // (-1 for vectors, String16, std::string) (0 for Parcelables).  If the peeked value
    // is invalid, then a null is returned.
    //
    // Application Note: When to use each nullable type:
    //
    // std::optional: Embeds the object T by value rather than creating a new instance
    // by managed pointer as std::unique_ptr or std::shared_ptr.  This will save a malloc
    // when creating an optional instance.
    //
    // Use of std::optionals by value can result in copies of the underlying value stored in it,
    // so a std::move may be used to move in and move out (for example) a vector value into
    // the std::optional or for the std::optional itself.
    //
    // std::unique_ptr, std::shared_ptr: These are preferred when the lifetime of the object is
    // already managed by the application.  This reduces unnecessary copying of data
    // especially when the calls are local in-proc (rather than via binder rpc).
    //
    // 5) StrongBinder (sp<IBinder>)
    // StrongBinder objects are written regardless of null. When read, null StrongBinder values
    // will be interpreted as UNKNOWN_ERROR if the type is a single argument <sp<T>>
    // or in a vector argument <std::vector<sp<T>>. However, they will be read without an error
    // if present in a std::optional, std::unique_ptr, or std::shared_ptr vector, e.g.
    // <std::optional<std::vector<sp<T>>>.
    //
    // See AIDL annotation @Nullable, readStrongBinder(), and readNullableStrongBinder().
    //
    // Historical Note: writing a vector of StrongBinder objects <std::vector<sp<T>>
    // containing a null will not cause an error. However reading such a vector will cause
    // an error _and_ early termination of the read.

    //  --- Examples
    //
    // Using recursive parceling, we can parcel complex data types so long
    // as they obey the rules described above.
    //
    // Example #1
    // Parceling of a 3D vector
    //
    // std::vector<std::vector<std::vector<int32_t>>> v1 {
    //     { {1}, {2, 3}, {4} },
    //     {},
    //     { {10}, {20}, {30, 40} },
    // };
    // Parcel p1;
    // p1.writeData(v1);
    // decltype(v1) v2;
    // p1.setDataPosition(0);
    // p1.readData(&v2);
    // ASSERT_EQ(v1, v2);
    //
    // Example #2
    // Parceling of mixed shared pointers
    //
    // Parcel p1;
    // auto sp1 = std::make_shared<std::vector<std::shared_ptr<std::vector<int>>>>(3);
    // (*sp1)[2] = std::make_shared<std::vector<int>>(3);
    // (*(*sp1)[2])[2] = 2;
    // p1.writeData(sp1);
    // decltype(sp1) sp2;
    // p1.setDataPosition(0);
    // p1.readData(&sp2);
    // ASSERT_EQ((*sp1)[0], (*sp2)[0]); // nullptr
    // ASSERT_EQ((*sp1)[1], (*sp2)[1]); // nullptr
    // ASSERT_EQ(*(*sp1)[2], *(*sp2)[2]); // { 0, 0, 2}

    //  --- Helper Methods
    // TODO: move this to a utils header.
    //
    // Determine if a type is a specialization of a templated type
    // Example: is_specialization_v<T, std::vector>

    template <typename Test, template <typename...> class Ref>
    struct is_specialization : std::false_type {};

    template <template <typename...> class Ref, typename... Args>
    struct is_specialization<Ref<Args...>, Ref>: std::true_type {};

    template <typename Test, template <typename...> class Ref>
    static inline constexpr bool is_specialization_v = is_specialization<Test, Ref>::value;

    // Get the first template type from a container, the T from MyClass<T, ...>.
    template<typename T> struct first_template_type;

    template <template <typename ...> class V, typename T, typename... Args>
    struct first_template_type<V<T, Args...>> {
        using type_t = T;
    };

    template <typename T>
    using first_template_type_t = typename first_template_type<T>::type_t;

    // For static assert(false) we need a template version to avoid early failure.
    template <typename T>
    static inline constexpr bool dependent_false_v = false;

    // primitive types that we consider packed and trivially copyable as an array
    template <typename T>
    static inline constexpr bool is_pointer_equivalent_array_v =
            std::is_same_v<T, int8_t>
            || std::is_same_v<T, uint8_t>
            // We could support int16_t and uint16_t, but those aren't currently AIDL types.
            || std::is_same_v<T, int32_t>
            || std::is_same_v<T, uint32_t>
            || std::is_same_v<T, float>
            // are unaligned reads and write support is assumed.
            || std::is_same_v<T, uint64_t>
            || std::is_same_v<T, int64_t>
            || std::is_same_v<T, double>
            || (std::is_enum_v<T> && (sizeof(T) == 1 || sizeof(T) == 4)); // size check not type

    // allowed "nullable" types
    // These are nonintrusive containers std::optional, std::unique_ptr, std::shared_ptr.
    template <typename T>
    static inline constexpr bool is_parcel_nullable_type_v =
            is_specialization_v<T, std::optional>
            || is_specialization_v<T, std::unique_ptr>
            || is_specialization_v<T, std::shared_ptr>;

    // Tells if T is a fixed-size array.
    template <typename T>
    struct is_fixed_array : std::false_type {};

    template <typename T, size_t N>
    struct is_fixed_array<std::array<T, N>> : std::true_type {};

    template <typename T>
    static inline constexpr bool is_fixed_array_v = is_fixed_array<T>::value;

    // special int32 value to indicate NonNull or Null parcelables
    // This is fixed to be only 0 or 1 by contract, do not change.
    static constexpr int32_t kNonNullParcelableFlag = 1;
    static constexpr int32_t kNullParcelableFlag = 0;

    // special int32 size representing a null vector, when applicable in Nullable data.
    // This fixed as -1 by contract, do not change.
    static constexpr int32_t kNullVectorSize = -1;

    // --- readData and writeData methods.
    // We choose a mixture of function and template overloads to improve code readability.
    // TODO: Consider C++20 concepts when they become available.

    // writeData function overloads.
    // Implementation detail: Function overloading improves code readability over
    // template overloading, but prevents writeData<T> from being used for those types.

    status_t writeData(bool t) {
        return writeBool(t);  // this writes as int32_t
    }

    status_t writeData(int8_t t) {
        return writeByte(t);  // this writes as int32_t
    }

    status_t writeData(uint8_t t) {
        return writeByte(static_cast<int8_t>(t));  // this writes as int32_t
    }

    status_t writeData(char16_t t) {
        return writeChar(t);  // this writes as int32_t
    }

    status_t writeData(int32_t t) {
        return writeInt32(t);
    }

    status_t writeData(uint32_t t) {
        return writeUint32(t);
    }

    status_t writeData(int64_t t) {
        return writeInt64(t);
    }

    status_t writeData(uint64_t t) {
        return writeUint64(t);
    }

    status_t writeData(float t) {
        return writeFloat(t);
    }

    status_t writeData(double t) {
        return writeDouble(t);
    }

    status_t writeData(const String16& t) {
        return writeString16(t);
    }

    status_t writeData(const std::string& t) {
        return writeUtf8AsUtf16(t);
    }

    status_t writeData(const binder::unique_fd& t) { return writeUniqueFileDescriptor(t); }

    status_t writeData(const Parcelable& t) {  // std::is_base_of_v<Parcelable, T>
        // implemented here. writeParcelable() calls this.
        status_t status = writeData(static_cast<int32_t>(kNonNullParcelableFlag));
        if (status != OK) return status;
        return t.writeToParcel(this);
    }

    // writeData<T> template overloads.
    // Written such that the first template type parameter is the complete type
    // of the first function parameter.
    template <typename T,
            typename std::enable_if_t<std::is_enum_v<T>, bool> = true>
    status_t writeData(const T& t) {
        // implemented here. writeEnum() calls this.
        using UT = std::underlying_type_t<T>;
        return writeData(static_cast<UT>(t)); // recurse
    }

    template <typename T,
            typename std::enable_if_t<is_specialization_v<T, sp>, bool> = true>
    status_t writeData(const T& t) {
        return writeStrongBinder(t);
    }

    // std::optional, std::unique_ptr, std::shared_ptr special case.
    template <typename CT,
            typename std::enable_if_t<is_parcel_nullable_type_v<CT>, bool> = true>
    status_t writeData(const CT& c) {
        using T = first_template_type_t<CT>;  // The T in CT == C<T, ...>
        if constexpr (is_specialization_v<T, std::vector>
                || std::is_same_v<T, String16>
                || std::is_same_v<T, std::string>) {
            if (!c) return writeData(static_cast<int32_t>(kNullVectorSize));
        } else if constexpr (std::is_base_of_v<Parcelable, T>) {
            if (!c) return writeData(static_cast<int32_t>(kNullParcelableFlag));
        } else if constexpr (is_fixed_array_v<T>) {
            if (!c) return writeData(static_cast<int32_t>(kNullVectorSize));
        } else /* constexpr */ { // could define this, but raise as error.
            static_assert(dependent_false_v<CT>);
        }
        return writeData(*c);
    }

    template <typename CT,
            typename std::enable_if_t<is_specialization_v<CT, std::vector>, bool> = true>
    status_t writeData(const CT& c) {
        using T = first_template_type_t<CT>;  // The T in CT == C<T, ...>
        if (c.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) return BAD_VALUE;
        const auto size = static_cast<int32_t>(c.size());
        writeData(size);
        if constexpr (is_pointer_equivalent_array_v<T>) {
            constexpr size_t limit = std::numeric_limits<size_t>::max() / sizeof(T);
            if (c.size() > limit) return BAD_VALUE;
            // is_pointer_equivalent types do not have gaps which could leak info,
            // which is only a concern when writing through binder.

            // TODO: Padding of the write is suboptimal when the length of the
            // data is not a multiple of 4.  Consider improving the write() method.
            return write(c.data(), c.size() * sizeof(T));
        } else if constexpr (std::is_same_v<T, bool>
                || std::is_same_v<T, char16_t>) {
            // reserve data space to write to
            auto data = reinterpret_cast<int32_t*>(writeInplace(c.size() * sizeof(int32_t)));
            if (data == nullptr) return BAD_VALUE;
            for (const auto t: c) {
                *data++ = static_cast<int32_t>(t);
            }
        } else /* constexpr */ {
            for (const auto &t : c) {
                const status_t status = writeData(t);
                if (status != OK) return status;
            }
        }
        return OK;
    }

    template <typename T, size_t N>
    status_t writeData(const std::array<T, N>& val) {
        static_assert(N <= std::numeric_limits<int32_t>::max());
        status_t status = writeData(static_cast<int32_t>(N));
        if (status != OK) return status;
        if constexpr (is_pointer_equivalent_array_v<T>) {
            static_assert(N <= std::numeric_limits<size_t>::max() / sizeof(T));
            return write(val.data(), val.size() * sizeof(T));
        } else /* constexpr */ {
            for (const auto& t : val) {
                status = writeData(t);
                if (status != OK) return status;
            }
            return OK;
        }
    }

    // readData function overloads.
    // Implementation detail: Function overloading improves code readability over
    // template overloading, but prevents readData<T> from being used for those types.

    status_t readData(bool* t) const {
        return readBool(t);  // this reads as int32_t
    }

    status_t readData(int8_t* t) const {
        return readByte(t);  // this reads as int32_t
    }

    status_t readData(uint8_t* t) const {
        return readByte(reinterpret_cast<int8_t*>(t));  // NOTE: this reads as int32_t
    }

    status_t readData(char16_t* t) const {
        return readChar(t);  // this reads as int32_t
    }

    status_t readData(int32_t* t) const {
        return readInt32(t);
    }

    status_t readData(uint32_t* t) const {
        return readUint32(t);
    }

    status_t readData(int64_t* t) const {
        return readInt64(t);
    }

    status_t readData(uint64_t* t) const {
        return readUint64(t);
    }

    status_t readData(float* t) const {
        return readFloat(t);
    }

    status_t readData(double* t) const {
        return readDouble(t);
    }

    status_t readData(String16* t) const {
        return readString16(t);
    }

    status_t readData(std::string* t) const {
        return readUtf8FromUtf16(t);
    }

    status_t readData(binder::unique_fd* t) const { return readUniqueFileDescriptor(t); }

    status_t readData(Parcelable* t) const { // std::is_base_of_v<Parcelable, T>
        // implemented here. readParcelable() calls this.
        int32_t present;
        status_t status = readData(&present);
        if (status != OK) return status;
        if (present != kNonNullParcelableFlag) return UNEXPECTED_NULL;
        return t->readFromParcel(this);
    }

    // readData<T> template overloads.
    // Written such that the first template type parameter is the complete type
    // of the first function parameter.

    template <typename T,
            typename std::enable_if_t<std::is_enum_v<T>, bool> = true>
    status_t readData(T* t) const {
        // implemented here. readEnum() calls this.
        using UT = std::underlying_type_t<T>;
        return readData(reinterpret_cast<UT*>(t));
    }

    template <typename T,
            typename std::enable_if_t<is_specialization_v<T, sp>, bool> = true>
    status_t readData(T* t) const {
        return readStrongBinder(t);  // Note: on null, returns failure
    }


    template <typename CT,
            typename std::enable_if_t<is_parcel_nullable_type_v<CT>, bool> = true>
    status_t readData(CT* c) const {
        using T = first_template_type_t<CT>;  // The T in CT == C<T, ...>
        const size_t startPos = dataPosition();
        int32_t peek;
        status_t status = readData(&peek);
        if (status != OK) return status;
        if constexpr (is_specialization_v<T, std::vector> || is_fixed_array_v<T> ||
                      std::is_same_v<T, String16> || std::is_same_v<T, std::string>) {
            if (peek == kNullVectorSize) {
                c->reset();
                return OK;
            }
        } else if constexpr (std::is_base_of_v<Parcelable, T>) {
            if (peek == kNullParcelableFlag) {
                c->reset();
                return OK;
            }
        } else /* constexpr */ { // could define this, but raise as error.
            static_assert(dependent_false_v<CT>);
        }
        // create a new object.
        if constexpr (is_specialization_v<CT, std::optional>) {
            // Call default constructor explicitly
            // - Clang bug: https://bugs.llvm.org/show_bug.cgi?id=35748
            //   std::optional::emplace() doesn't work with nested types.
            c->emplace(T());
        } else /* constexpr */ {
            T* const t = new (std::nothrow) T;  // contents read from Parcel below.
            if (t == nullptr) return NO_MEMORY;
            c->reset(t);
        }
        // rewind data ptr to reread (this is pretty quick), otherwise we could
        // pass an optional argument to readData to indicate a peeked value.
        setDataPosition(startPos);
        if constexpr (is_specialization_v<T, std::vector> || is_fixed_array_v<T>) {
            return readData(&**c, READ_FLAG_SP_NULLABLE);  // nullable sp<> allowed now
        } else {
            return readData(&**c);
        }
    }

    // std::vector special case, incorporating flags whether the vector
    // accepts nullable sp<> to be read.
    enum ReadFlags {
        READ_FLAG_NONE = 0,
        READ_FLAG_SP_NULLABLE = 1 << 0,
    };

    template <typename CT,
            typename std::enable_if_t<is_specialization_v<CT, std::vector>, bool> = true>
    status_t readData(CT* c, ReadFlags readFlags = READ_FLAG_NONE) const {
        using T = first_template_type_t<CT>;  // The T in CT == C<T, ...>
        int32_t size;
        status_t status = readInt32(&size);
        if (status != OK) return status;
        if (size < 0) return UNEXPECTED_NULL;
        const size_t availableBytes = dataAvail();  // coarse bound on vector size.
        if (static_cast<size_t>(size) > availableBytes) return BAD_VALUE;
        c->clear(); // must clear before resizing/reserving otherwise move ctors may be called.
        if constexpr (is_pointer_equivalent_array_v<T>) {
            // could consider POD without gaps and alignment of 4.
            size_t dataLen;
            if (__builtin_mul_overflow(size, sizeof(T), &dataLen)) {
                return -EOVERFLOW;
            }
            auto data = readInplace(dataLen);
            if (data == nullptr) return BAD_VALUE;
            // std::vector::insert and similar methods will require type-dependent
            // byte alignment when inserting from a const iterator such as `data`,
            // e.g. 8 byte alignment for int64_t, and so will not work if `data`
            // is 4 byte aligned (which is all Parcel guarantees). Copying
            // the contents into the vector directly, where possible, circumvents
            // this.
            c->resize(size);
            memcpy(c->data(), data, dataLen);
        } else if constexpr (std::is_same_v<T, bool>
                || std::is_same_v<T, char16_t>) {
            c->reserve(size); // avoids default initialization
            auto data = reinterpret_cast<const int32_t*>(
                    readInplace(static_cast<size_t>(size) * sizeof(int32_t)));
            if (data == nullptr) return BAD_VALUE;
            for (int32_t i = 0; i < size; ++i) {
                c->emplace_back(static_cast<T>(*data++));
            }
        } else if constexpr (is_specialization_v<T, sp>) {
            c->resize(size); // calls ctor
            if (readFlags & READ_FLAG_SP_NULLABLE) {
                for (auto &t : *c) {
                    status = readNullableStrongBinder(&t);  // allow nullable
                    if (status != OK) return status;
                }
            } else {
                for (auto &t : *c) {
                    status = readStrongBinder(&t);
                    if (status != OK) return status;
                }
            }
        } else /* constexpr */ {
            c->resize(size); // calls ctor
            for (auto &t : *c) {
                status = readData(&t);
                if (status != OK) return status;
            }
        }
        return OK;
    }

    template <typename T, size_t N>
    status_t readData(std::array<T, N>* val, ReadFlags readFlags = READ_FLAG_NONE) const {
        static_assert(N <= std::numeric_limits<int32_t>::max());
        int32_t size;
        status_t status = readInt32(&size);
        if (status != OK) return status;
        if (size < 0) return UNEXPECTED_NULL;
        if (size != static_cast<int32_t>(N)) return BAD_VALUE;
        if constexpr (is_pointer_equivalent_array_v<T>) {
            auto data = reinterpret_cast<const T*>(readInplace(N * sizeof(T)));
            if (data == nullptr) return BAD_VALUE;
            memcpy(val->data(), data, N * sizeof(T));
        } else if constexpr (is_specialization_v<T, sp>) {
            for (auto& t : *val) {
                if (readFlags & READ_FLAG_SP_NULLABLE) {
                    status = readNullableStrongBinder(&t); // allow nullable
                } else {
                    status = readStrongBinder(&t);
                }
                if (status != OK) return status;
            }
        } else if constexpr (is_fixed_array_v<T>) { // pass readFlags down to nested arrays
            for (auto& t : *val) {
                status = readData(&t, readFlags);
                if (status != OK) return status;
            }
        } else /* constexpr */ {
            for (auto& t : *val) {
                status = readData(&t);
                if (status != OK) return status;
            }
        }
        return OK;
    }

    //-----------------------------------------------------------------------------
    private:

    status_t            mError;
    uint8_t*            mData;
    size_t              mDataSize;
    size_t              mDataCapacity;
    mutable size_t mDataPos;

    // Fields only needed when parcelling for "kernel Binder".
    struct KernelFields {
        KernelFields() {}
        binder_size_t* mObjects = nullptr;
        size_t mObjectsSize = 0;
        size_t mObjectsCapacity = 0;
        mutable size_t mNextObjectHint = 0;

        mutable size_t mWorkSourceRequestHeaderPosition = 0;
        mutable bool mRequestHeaderPresent = false;

        mutable bool mObjectsSorted = false;
        mutable bool mFdsKnown = true;
        mutable bool mHasFds = false;
    };
    // Fields only needed when parcelling for RPC Binder.
    struct RpcFields {
        RpcFields(const sp<RpcSession>& session);

        // Should always be non-null.
        const sp<RpcSession> mSession;

        enum ObjectType : int32_t {
            TYPE_BINDER_NULL = 0,
            TYPE_BINDER = 1,
            // FD to be passed via native transport (Trusty IPC or UNIX domain socket).
            TYPE_NATIVE_FILE_DESCRIPTOR = 2,
        };

        // Sorted.
        std::vector<uint32_t> mObjectPositions;

        // File descriptors referenced by the parcel data. Should be indexed
        // using the offsets in the parcel data. Don't assume the list is in the
        // same order as `mObjectPositions`.
        //
        // Boxed to save space. Lazy allocated.
        std::unique_ptr<std::vector<std::variant<binder::unique_fd, binder::borrowed_fd>>> mFds;
    };
    std::variant<KernelFields, RpcFields> mVariantFields;

    // Pointer to KernelFields in mVariantFields if present.
    KernelFields* maybeKernelFields() { return std::get_if<KernelFields>(&mVariantFields); }
    const KernelFields* maybeKernelFields() const {
        return std::get_if<KernelFields>(&mVariantFields);
    }
    // Pointer to RpcFields in mVariantFields if present.
    RpcFields* maybeRpcFields() { return std::get_if<RpcFields>(&mVariantFields); }
    const RpcFields* maybeRpcFields() const { return std::get_if<RpcFields>(&mVariantFields); }

    bool                mAllowFds;

    // if this parcelable is involved in a secure transaction, force the
    // data to be overridden with zero when deallocated
    mutable bool        mDeallocZero;

    // Set this to false to skip dataAvail checks.
    bool mEnforceNoDataAvail;
    bool mServiceFuzzing;

    release_func        mOwner;

    size_t mReserved;

    class Blob {
    public:
        LIBBINDER_EXPORTED Blob();
        LIBBINDER_EXPORTED ~Blob();

        LIBBINDER_EXPORTED void clear();
        LIBBINDER_EXPORTED void release();
        LIBBINDER_EXPORTED inline size_t size() const { return mSize; }
        LIBBINDER_EXPORTED inline int fd() const { return mFd; }
        LIBBINDER_EXPORTED inline bool isMutable() const { return mMutable; }

    protected:
        void init(int fd, void* data, size_t size, bool isMutable);

        int mFd; // owned by parcel so not closed when released
        void* mData;
        size_t mSize;
        bool mMutable;
    };

    #if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wweak-vtables"
    #endif

    // FlattenableHelperInterface and FlattenableHelper avoid generating a vtable entry in objects
    // following Flattenable template/protocol.
    class LIBBINDER_EXPORTED FlattenableHelperInterface {
    protected:
        ~FlattenableHelperInterface() { }
    public:
        virtual size_t getFlattenedSize() const = 0;
        virtual size_t getFdCount() const = 0;
        virtual status_t flatten(void* buffer, size_t size, int* fds, size_t count) const = 0;
        virtual status_t unflatten(void const* buffer, size_t size, int const* fds, size_t count) = 0;
    };

    #if defined(__clang__)
    #pragma clang diagnostic pop
    #endif

    // Concrete implementation of FlattenableHelperInterface that delegates virtual calls to the
    // specified class T implementing the Flattenable protocol. It "virtualizes" a compile-time
    // protocol.
    template<typename T>
    class FlattenableHelper : public FlattenableHelperInterface {
        friend class Parcel;
        const Flattenable<T>& val;
        explicit FlattenableHelper(const Flattenable<T>& _val) : val(_val) { }

    protected:
        ~FlattenableHelper() = default;
    public:
        virtual size_t getFlattenedSize() const {
            return val.getFlattenedSize();
        }
        virtual size_t getFdCount() const {
            return val.getFdCount();
        }
        virtual status_t flatten(void* buffer, size_t size, int* fds, size_t count) const {
            return val.flatten(buffer, size, fds, count);
        }
        virtual status_t unflatten(void const* buffer, size_t size, int const* fds, size_t count) {
            return const_cast<Flattenable<T>&>(val).unflatten(buffer, size, fds, count);
        }
    };
    LIBBINDER_EXPORTED status_t write(const FlattenableHelperInterface& val);
    LIBBINDER_EXPORTED status_t read(FlattenableHelperInterface& val) const;

public:
    class ReadableBlob : public Blob {
        friend class Parcel;
    public:
        LIBBINDER_EXPORTED inline const void* data() const { return mData; }
        LIBBINDER_EXPORTED inline void* mutableData() { return isMutable() ? mData : nullptr; }
    };

    class WritableBlob : public Blob {
        friend class Parcel;
    public:
        LIBBINDER_EXPORTED inline void* data() { return mData; }
    };

    /**
     * Returns the total amount of ashmem memory owned by this object.
     *
     * Note: for historical reasons, this does not include ashmem memory which
     * is referenced by this Parcel, but which this parcel doesn't own (e.g.
     * writeFileDescriptor is called without 'takeOwnership' true).
     *
     * WARNING: you should not use this, but rather, unparcel, and inspect
     * each FD independently. This counts ashmem size, but there may be
     * other resources used for non-ashmem FDs, such as other types of
     * shared memory, files, etc..
     */
    LIBBINDER_EXPORTED size_t getOpenAshmemSize() const;

private:
    // Needed so that we can save object metadata to the disk
    friend class android::binder::debug::RecordedTransaction;
};

// ---------------------------------------------------------------------------

template<typename T>
status_t Parcel::write(const Flattenable<T>& val) {
    const FlattenableHelper<T> helper(val);
    return write(helper);
}

template<typename T>
status_t Parcel::write(const LightFlattenable<T>& val) {
    size_t size(val.getFlattenedSize());
    if (!val.isFixedSize()) {
        if (size > INT32_MAX) {
            return BAD_VALUE;
        }
        status_t err = writeInt32(static_cast<int32_t>(size));
        if (err != NO_ERROR) {
            return err;
        }
    }
    if (size) {
        void* buffer = writeInplace(size);
        if (buffer == nullptr)
            return NO_MEMORY;
        return val.flatten(buffer, size);
    }
    return NO_ERROR;
}

template<typename T>
status_t Parcel::read(Flattenable<T>& val) const {
    FlattenableHelper<T> helper(val);
    return read(helper);
}

template<typename T>
status_t Parcel::read(LightFlattenable<T>& val) const {
    size_t size;
    if (val.isFixedSize()) {
        size = val.getFlattenedSize();
    } else {
        int32_t s;
        status_t err = readInt32(&s);
        if (err != NO_ERROR) {
            return err;
        }
        size = static_cast<size_t>(s);
    }
    if (size) {
        void const* buffer = readInplace(size);
        return buffer == nullptr ? NO_MEMORY :
                val.unflatten(buffer, size);
    }
    return NO_ERROR;
}

template<typename T>
status_t Parcel::writeVectorSize(const std::vector<T>& val) {
    if (val.size() > INT32_MAX) {
        return BAD_VALUE;
    }
    return writeInt32(static_cast<int32_t>(val.size()));
}

template<typename T>
status_t Parcel::writeVectorSize(const std::optional<std::vector<T>>& val) {
    if (!val) {
        return writeInt32(-1);
    }

    return writeVectorSize(*val);
}

template<typename T>
status_t Parcel::writeVectorSize(const std::unique_ptr<std::vector<T>>& val) {
    if (!val) {
        return writeInt32(-1);
    }

    return writeVectorSize(*val);
}

template<typename T>
status_t Parcel::resizeOutVector(std::vector<T>* val) const {
    int32_t size;
    status_t err = readOutVectorSizeWithCheck(sizeof(T), &size);
    if (err != NO_ERROR) {
        return err;
    }

    if (size < 0) {
        return UNEXPECTED_NULL;
    }
    val->resize(size_t(size));
    return OK;
}

template<typename T>
status_t Parcel::resizeOutVector(std::optional<std::vector<T>>* val) const {
    int32_t size;
    status_t err = readOutVectorSizeWithCheck(sizeof(T), &size);
    if (err != NO_ERROR) {
        return err;
    }

    val->reset();
    if (size >= 0) {
        val->emplace(size_t(size));
    }

    return OK;
}

template<typename T>
status_t Parcel::resizeOutVector(std::unique_ptr<std::vector<T>>* val) const {
    int32_t size;
    status_t err = readOutVectorSizeWithCheck(sizeof(T), &size);
    if (err != NO_ERROR) {
        return err;
    }

    val->reset();
    if (size >= 0) {
        val->reset(new std::vector<T>(size_t(size)));
    }

    return OK;
}

template<typename T>
status_t Parcel::readStrongBinder(sp<T>* val) const {
    sp<IBinder> tmp;
    status_t ret = readStrongBinder(&tmp);

    if (ret == OK) {
        *val = interface_cast<T>(tmp);

        if (val->get() == nullptr) {
            return UNKNOWN_ERROR;
        }
    }

    return ret;
}

template<typename T>
status_t Parcel::readNullableStrongBinder(sp<T>* val) const {
    sp<IBinder> tmp;
    status_t ret = readNullableStrongBinder(&tmp);

    if (ret == OK) {
        *val = interface_cast<T>(tmp);

        if (val->get() == nullptr && tmp.get() != nullptr) {
            ret = UNKNOWN_ERROR;
        }
    }

    return ret;
}

// ---------------------------------------------------------------------------

inline std::ostream& operator<<(std::ostream& to, const Parcel& parcel) {
    parcel.print(to);
    return to;
}

} // namespace android

// ---------------------------------------------------------------------------

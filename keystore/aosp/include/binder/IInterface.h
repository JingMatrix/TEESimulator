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

#include <binder/Binder.h>
#include <binder/Common.h>

#include <assert.h>

namespace android {

// ----------------------------------------------------------------------

class LIBBINDER_EXPORTED IInterface : public virtual RefBase {
public:
            IInterface();
            static sp<IBinder>  asBinder(const IInterface*);
            static sp<IBinder>  asBinder(const sp<IInterface>&);

protected:
    virtual                     ~IInterface();
    virtual IBinder*            onAsBinder() = 0;
};

// ----------------------------------------------------------------------

/**
 * If this is a local object and the descriptor matches, this will return the
 * actual local object which is implementing the interface. Otherwise, this will
 * return a proxy to the interface without checking the interface descriptor.
 * This means that subsequent calls may fail with BAD_TYPE.
 */
template<typename INTERFACE>
inline sp<INTERFACE> interface_cast(const sp<IBinder>& obj)
{
    return INTERFACE::asInterface(obj);
}

/**
 * This is the same as interface_cast, except that it always checks to make sure
 * the descriptor matches, and if it doesn't match, it will return nullptr.
 */
template<typename INTERFACE>
inline sp<INTERFACE> checked_interface_cast(const sp<IBinder>& obj)
{
    if (obj->getInterfaceDescriptor() != INTERFACE::descriptor) {
        return nullptr;
    }

    return interface_cast<INTERFACE>(obj);
}

// ----------------------------------------------------------------------

template <typename INTERFACE>
class LIBBINDER_EXPORTED BnInterface : public INTERFACE, public BBinder {
public:
    virtual sp<IInterface>      queryLocalInterface(const String16& _descriptor);
    virtual const String16&     getInterfaceDescriptor() const;
    typedef INTERFACE BaseInterface;

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

template <typename INTERFACE>
class LIBBINDER_EXPORTED BpInterface : public INTERFACE, public BpRefBase {
public:
    explicit                    BpInterface(const sp<IBinder>& remote);
    typedef INTERFACE BaseInterface;

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

#define DECLARE_META_INTERFACE(INTERFACE)                                                         \
public:                                                                                           \
    static const ::android::String16 descriptor;                                                  \
    static ::android::sp<I##INTERFACE> asInterface(const ::android::sp<::android::IBinder>& obj); \
    virtual const ::android::String16& getInterfaceDescriptor() const;                            \
    I##INTERFACE();                                                                               \
    virtual ~I##INTERFACE();                                                                      \
    static bool setDefaultImpl(::android::sp<I##INTERFACE> impl);                                 \
    static const ::android::sp<I##INTERFACE>& getDefaultImpl();                                   \
                                                                                                  \
private:                                                                                          \
    static ::android::sp<I##INTERFACE> default_impl;                                              \
                                                                                                  \
public:

#define __IINTF_CONCAT(x, y) (x ## y)

#ifndef DO_NOT_CHECK_MANUAL_BINDER_INTERFACES

#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    static_assert(internal::allowedManualInterface(NAME),               \
                  "b/64223827: Manually written binder interfaces are " \
                  "considered error prone and frequently have bugs. "   \
                  "The preferred way to add interfaces is to define "   \
                  "an .aidl file to auto-generate the interface. If "   \
                  "an interface must be manually written, add its "     \
                  "name to the allowlist.");                            \
    DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(INTERFACE, NAME)

#else

#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(INTERFACE, NAME)    \

#endif

// Macro to be used by both IMPLEMENT_META_INTERFACE and IMPLEMENT_META_NESTED_INTERFACE
#define DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE0(ITYPE, INAME, BPTYPE)                     \
    const ::android::String16& ITYPE::getInterfaceDescriptor() const { return ITYPE::descriptor; } \
    ::android::sp<ITYPE> ITYPE::asInterface(const ::android::sp<::android::IBinder>& obj) {        \
        ::android::sp<ITYPE> intr;                                                                 \
        if (obj != nullptr) {                                                                      \
            intr = ::android::sp<ITYPE>::cast(obj->queryLocalInterface(ITYPE::descriptor));        \
            if (intr == nullptr) {                                                                 \
                intr = ::android::sp<BPTYPE>::make(obj);                                           \
            }                                                                                      \
        }                                                                                          \
        return intr;                                                                               \
    }                                                                                              \
    ::android::sp<ITYPE> ITYPE::default_impl;                                                      \
    bool ITYPE::setDefaultImpl(::android::sp<ITYPE> impl) {                                        \
        /* Only one user of this interface can use this function     */                            \
        /* at a time. This is a heuristic to detect if two different */                            \
        /* users in the same process use this function.              */                            \
        assert(!ITYPE::default_impl);                                                              \
        if (impl) {                                                                                \
            ITYPE::default_impl = std::move(impl);                                                 \
            return true;                                                                           \
        }                                                                                          \
        return false;                                                                              \
    }                                                                                              \
    const ::android::sp<ITYPE>& ITYPE::getDefaultImpl() { return ITYPE::default_impl; }            \
    ITYPE::INAME() {}                                                                              \
    ITYPE::~INAME() {}

// Macro for an interface type.
#define DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                        \
    const ::android::StaticString16 I##INTERFACE##_descriptor_static_str16(                     \
            __IINTF_CONCAT(u, NAME));                                                           \
    const ::android::String16 I##INTERFACE::descriptor(I##INTERFACE##_descriptor_static_str16); \
    DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE0(I##INTERFACE, I##INTERFACE, Bp##INTERFACE)

// Macro for "nested" interface type.
// For example,
//   class Parent .. { class INested .. { }; };
// DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_NESTED_INTERFACE(Parent, Nested, "Parent.INested")
#define DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_NESTED_INTERFACE(PARENT, INTERFACE, NAME)  \
    const ::android::String16 PARENT::I##INTERFACE::descriptor(NAME);                    \
    DO_NOT_DIRECTLY_USE_ME_IMPLEMENT_META_INTERFACE0(PARENT::I##INTERFACE, I##INTERFACE, \
                                                     PARENT::Bp##INTERFACE)

#define CHECK_INTERFACE(interface, data, reply)                         \
    do {                                                                \
      if (!(data).checkInterface(this)) { return PERMISSION_DENIED; }   \
    } while (false)                                                     \


// ----------------------------------------------------------------------
// No user-serviceable parts after this...

template<typename INTERFACE>
inline sp<IInterface> BnInterface<INTERFACE>::queryLocalInterface(
        const String16& _descriptor)
{
    if (_descriptor == INTERFACE::descriptor) return sp<IInterface>::fromExisting(this);
    return nullptr;
}

template<typename INTERFACE>
inline const String16& BnInterface<INTERFACE>::getInterfaceDescriptor() const
{
    return INTERFACE::getInterfaceDescriptor();
}

template<typename INTERFACE>
IBinder* BnInterface<INTERFACE>::onAsBinder()
{
    return this;
}

template<typename INTERFACE>
inline BpInterface<INTERFACE>::BpInterface(const sp<IBinder>& remote)
    : BpRefBase(remote)
{
}

template<typename INTERFACE>
inline IBinder* BpInterface<INTERFACE>::onAsBinder()
{
    return remote();
}

// ----------------------------------------------------------------------

namespace internal {
constexpr const char* const kManualInterfaces[] = {
        "android.app.IActivityManager",
        "android.app.IUidObserver",
        "android.gfx.tests.ICallback",
        "android.gfx.tests.IIPCTest",
        "android.gfx.tests.ISafeInterfaceTest",
        "android.graphicsenv.IGpuService",
        "android.gui.IConsumerListener",
        "android.gui.IGraphicBufferConsumer",
        "android.gui.ITransactionComposerListener",
        "android.gui.SensorEventConnection",
        "android.gui.SensorServer",
        "android.hardware.ICamera",
        "android.hardware.ICameraClient",
        "android.hardware.ICameraRecordingProxy",
        "android.hardware.ICameraRecordingProxyListener",
        "android.hardware.IOMXObserver",
        "android.hardware.IStreamListener",
        "android.hardware.IStreamSource",
        "android.media.IAudioService",
        "android.media.IDataSource",
        "android.media.IMediaCodecList",
        "android.media.IMediaExtractor",
        "android.media.IMediaHTTPConnection",
        "android.media.IMediaHTTPService",
        "android.media.IMediaLogService",
        "android.media.IMediaMetadataRetriever",
        "android.media.IMediaPlayer",
        "android.media.IMediaPlayerClient",
        "android.media.IMediaPlayerService",
        "android.media.IMediaRecorder",
        "android.media.IMediaRecorderClient",
        "android.media.IMediaResourceMonitor",
        "android.media.IMediaSource",
        "android.media.IRemoteDisplay",
        "android.media.IRemoteDisplayClient",
        "android.os.IPermissionController",
        "android.os.IProcessInfoService",
        "android.os.ISchedulingPolicyService",
        "android.os.storage.IObbActionListener",
        "android.os.storage.IStorageEventListener",
        "android.os.storage.IStorageManager",
        "android.os.storage.IStorageShutdownObserver",
        "android.ui.ISurfaceComposer",
        "android.utils.IMemory",
        "android.utils.IMemoryHeap",
        "com.android.car.procfsinspector.IProcfsInspector",
        "com.android.internal.app.IAppOpsCallback",
        "com.android.internal.app.IAppOpsService",
        "com.android.internal.app.IBatteryStats",
        "com.android.internal.os.IResultReceiver",
        "com.android.internal.os.IShellCallback",
        "drm.IDrmManagerService",
        "drm.IDrmServiceListener",
        nullptr,
};

constexpr const char* const kDownstreamManualInterfaces[] = {
  // Add downstream interfaces here.
  nullptr,
};

constexpr bool equals(const char* a, const char* b) {
  if (*a != *b) return false;
  if (*a == '\0') return true;
  return equals(a + 1, b + 1);
}

constexpr bool inList(const char* a, const char* const* allowlist) {
  if (*allowlist == nullptr) return false;
  if (equals(a, *allowlist)) return true;
  return inList(a, allowlist + 1);
}

constexpr bool allowedManualInterface(const char* name) {
  return inList(name, kManualInterfaces) ||
         inList(name, kDownstreamManualInterfaces);
}

} // namespace internal
} // namespace android

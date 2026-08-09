/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <binder/IBinder.h>
#include <string>

class BinderStabilityIntegrationTest_ExpectedStabilityForItsPartition_Test;

namespace android {

class BpBinder;
class ProcessState;

namespace internal {

// Stability encodes how a binder changes over time. There are two levels of
// stability:
// 1). the interface stability - this is how a particular set of API calls (a
//   particular ordering of things like writeInt32/readInt32) are changed over
//   time. If one release, we have 'writeInt32' and the next release, we have
//   'writeInt64', then this interface doesn't have a very stable
//   Stability::Level. Usually this ordering is controlled by a .aidl file.
// 2). the wire format stability - this is how these API calls map to actual
//   bytes that are written to the wire (literally, this is how they are written
//   to the kernel inside of IBinder::transact, but it may be expanded to other
//   wires in the future). For instance, writeInt32 in binder translates to
//   writing a 4-byte little-endian integer in two's complement. You can imagine
//   in the future, we change writeInt32/readInt32 to instead write 8-bytes with
//   that integer and some check bits. In this case, the wire format changes,
//   but as long as a client libbinder knows to keep on writing a 4-byte value
//   to old servers, and new servers know how to interpret the 8-byte result,
//   they can still communicate.
//
// This class is specifically about (1). (2) is not currently tracked by
// libbinder for regular binder calls, and everything on the system uses the
// same copy of libbinder.

class Stability final {
public:
    // Given a binder interface at a certain stability, there may be some
    // requirements associated with that higher stability level. For instance, a
    // VINTF stability binder is required to be in the VINTF manifest. This API
    // can be called to use that same interface within the local partition.
    LIBBINDER_EXPORTED static void forceDowngradeToLocalStability(const sp<IBinder>& binder);

    // WARNING: Below APIs are only ever expected to be called by auto-generated code.
    //     Instead of calling them, you should set the stability of a .aidl interface

    // WARNING: The only client of
    //      - forceDowngradeToSystemStability() and;
    //      - korceDowngradeToVendorStability()
    //  should be AIBinder_forceDowngradeToLocalStability().
    //
    // getLocalLevel() in libbinder returns Level::SYSTEM when called
    // from libbinder_ndk (even on vendor partition). So we explicitly provide
    // these methods for use by the NDK API:
    //      AIBinder_forceDowngradeToLocalStability().
    //
    // This allows correctly downgrading the binder's stability to either system/vendor,
    // depending on the partition.

    // Given a binder interface at a certain stability, there may be some
    // requirements associated with that higher stability level. For instance, a
    // VINTF stability binder is required to be in the VINTF manifest. This API
    // can be called to use that same interface within the vendor partition.
    LIBBINDER_EXPORTED static void forceDowngradeToVendorStability(const sp<IBinder>& binder);

    // Given a binder interface at a certain stability, there may be some
    // requirements associated with that higher stability level. For instance, a
    // VINTF stability binder is required to be in the VINTF manifest. This API
    // can be called to use that same interface within the system partition.
    LIBBINDER_EXPORTED static void forceDowngradeToSystemStability(const sp<IBinder>& binder);

    // WARNING: This is only ever expected to be called by auto-generated code. You likely want to
    // change or modify the stability class of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder compilation unit
    LIBBINDER_EXPORTED static void markCompilationUnit(IBinder* binder);
    // WARNING: This is only ever expected to be called by auto-generated code. You likely want to
    // change or modify the stability class of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder_ndk or Java SDK AND the interface
    //     expressed here is guaranteed to be stable for multiple years (Stable AIDL)
    LIBBINDER_EXPORTED static void markVintf(IBinder* binder);

    // WARNING: for debugging only
    LIBBINDER_EXPORTED static std::string debugToString(const sp<IBinder>& binder);

    // WARNING: This is only ever expected to be called by auto-generated code or tests.
    // You likely want to change or modify the stability of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder_ndk or Java SDK AND the interface
    //     expressed here is guaranteed to be stable for multiple years (Stable AIDL)
    // If this is called when __ANDROID_VNDK__ is not defined, then it is UB and will likely
    // break the device during GSI or other tests.
    LIBBINDER_EXPORTED static void markVndk(IBinder* binder);

    // Returns true if the binder needs to be declared in the VINTF manifest or
    // else false if the binder is local to the current partition.
    LIBBINDER_EXPORTED static bool requiresVintfDeclaration(const sp<IBinder>& binder);

private:
    // Parcel needs to read/write stability level in an unstable format.
    friend ::android::Parcel;

    // only expose internal APIs inside of libbinder, for checking stability
    friend ::android::BpBinder;

    // so that it can mark the context object (only the root object doesn't go
    // through Parcel)
    friend ::android::ProcessState;

    friend ::BinderStabilityIntegrationTest_ExpectedStabilityForItsPartition_Test;

    static void tryMarkCompilationUnit(IBinder* binder);

    // Currently, we use int16_t for Level so that it can fit in BBinder.
    // However, on the wire, we have 4 bytes reserved for stability, so whenever
    // we ingest a Level, we always accept an int32_t.
    enum Level : int16_t {
        UNDECLARED = 0,

        VENDOR = 0b000011,
        SYSTEM = 0b001100,
        VINTF = 0b111111,
    };

    // returns the stability according to how this was built
    static Level getLocalLevel();

    // Downgrades binder stability to the specified level.
    static void forceDowngradeToStability(const sp<IBinder>& binder, Level level);

    enum {
      REPR_NONE = 0,
      REPR_LOG = 1,
      REPR_ALLOW_DOWNGRADE = 2,
    };
    // applies stability to binder if stability level is known
    __attribute__((warn_unused_result)) static status_t setRepr(IBinder* binder, int32_t setting,
                                                                uint32_t flags);

    // get stability information as encoded on the wire
    LIBBINDER_EXPORTED static int16_t getRepr(IBinder* binder);

    // whether a transaction on binder is allowed, if the transaction
    // is done from a context with a specific stability level
    LIBBINDER_EXPORTED static bool check(int16_t provided, Level required);

    static bool isDeclaredLevel(int32_t level);
    static std::string levelString(int32_t level);

    Stability();
};

}  // namespace internal
}  // namespace android

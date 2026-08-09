/*
 * Copyright (C) 2021 The Android Open Source Project
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

// Wraps the transport layer of RPC. Implementation may use plain sockets or TLS.

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <utils/Errors.h>

#include <binder/Common.h>
#include <binder/Functional.h>
#include <binder/RpcCertificateFormat.h>
#include <binder/RpcThreads.h>
#include <binder/unique_fd.h>

#include <sys/uio.h>

namespace android {

class FdTrigger;
struct RpcTransportFd;

// for 'friend'
class RpcTransportRaw;
class RpcTransportTls;
class RpcTransportTipcAndroid;
class RpcTransportTipcTrusty;
class RpcTransportCtxRaw;
class RpcTransportCtxTls;
class RpcTransportCtxTipcAndroid;
class RpcTransportCtxTipcTrusty;

// Represents a socket connection.
// No thread-safety is guaranteed for these APIs.
class LIBBINDER_EXPORTED RpcTransport {
public:
    virtual ~RpcTransport() = default;

    /**
     * Poll the transport to check whether there is any data ready to read.
     *
     * Return:
     *   OK - There is data available on this transport
     *   WOULDBLOCK - No data is available
     *   error - any other error
     */
    [[nodiscard]] virtual status_t pollRead(void) = 0;

    /**
     * Read (or write), but allow to be interrupted by a trigger.
     *
     * iovs - array of iovecs to perform the operation on. The elements
     * of the array may be modified by this method.
     *
     * altPoll - function to be called instead of polling, when needing to wait
     * to read/write data. If this returns an error, that error is returned from
     * this function.
     *
     * ancillaryFds - FDs to be sent via UNIX domain dockets or Trusty IPC. When
     * reading, if `ancillaryFds` is null, any received FDs will be silently
     * dropped and closed (by the OS). Appended values will always be unique_fd,
     * the variant type is used to avoid extra copies elsewhere.
     *
     * Return:
     *   OK - succeeded in completely processing 'size'
     *   error - interrupted (failure or trigger)
     */
    [[nodiscard]] virtual status_t interruptableWriteFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<binder::impl::SmallFunction<status_t()>>& altPoll,
            const std::vector<std::variant<binder::unique_fd, binder::borrowed_fd>>*
                    ancillaryFds) = 0;
    [[nodiscard]] virtual status_t interruptableReadFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<binder::impl::SmallFunction<status_t()>>& altPoll,
            std::vector<std::variant<binder::unique_fd, binder::borrowed_fd>>* ancillaryFds) = 0;

    /**
     *  Check whether any threads are blocked while polling the transport
     *  for read operations
     *  Return:
     *    True - Specifies that there is active polling on transport.
     *    False - No active polling on transport
     */
    [[nodiscard]] virtual bool isWaiting() = 0;

private:
    // limit the classes which can implement RpcTransport. Being able to change this
    // interface is important to allow development of RPC binder. In the past, we
    // changed this interface to use iovec for efficiency, and we added FDs to the
    // interface. If another transport is needed, it should be added directly here.
    // non-socket FDs likely also need changes in RpcSession in order to get
    // connected, and similarly to how addrinfo was type-erased from RPC binder
    // interfaces when RpcTransportTipc* was added, other changes may be needed
    // to add more transports.

    friend class ::android::RpcTransportRaw;
    friend class ::android::RpcTransportTls;
    friend class ::android::RpcTransportTipcAndroid;
    friend class ::android::RpcTransportTipcTrusty;

    RpcTransport() = default;
};

// Represents the context that generates the socket connection.
// All APIs are thread-safe. See RpcTransportCtxRaw and RpcTransportCtxTls for details.
class LIBBINDER_EXPORTED RpcTransportCtx {
public:
    virtual ~RpcTransportCtx() = default;

    // Create a new RpcTransport object.
    //
    // Implementation details: for TLS, this function may incur I/O. |fdTrigger| may be used
    // to interrupt I/O. This function blocks until handshake is finished.
    [[nodiscard]] virtual std::unique_ptr<RpcTransport> newTransport(
            android::RpcTransportFd fd, FdTrigger *fdTrigger) const = 0;

    // Return the preconfigured certificate of this context.
    //
    // Implementation details:
    // - For raw sockets, this always returns empty string.
    // - For TLS, this returns the certificate. See RpcTransportTls for details.
    [[nodiscard]] virtual std::vector<uint8_t> getCertificate(
            RpcCertificateFormat format) const = 0;

private:
    // see comment on RpcTransport
    friend class ::android::RpcTransportCtxRaw;
    friend class ::android::RpcTransportCtxTls;
    friend class ::android::RpcTransportCtxTipcAndroid;
    friend class ::android::RpcTransportCtxTipcTrusty;

    RpcTransportCtx() = default;
};

// A factory class that generates RpcTransportCtx.
// All APIs are thread-safe.
class LIBBINDER_EXPORTED RpcTransportCtxFactory {
public:
    virtual ~RpcTransportCtxFactory() = default;
    // Creates server context.
    [[nodiscard]] virtual std::unique_ptr<RpcTransportCtx> newServerCtx() const = 0;

    // Creates client context.
    [[nodiscard]] virtual std::unique_ptr<RpcTransportCtx> newClientCtx() const = 0;

    // Return a short description of this transport (e.g. "raw"). For logging / debugging / testing
    // only.
    [[nodiscard]] virtual const char *toCString() const = 0;

protected:
    RpcTransportCtxFactory() = default;
};

struct LIBBINDER_EXPORTED RpcTransportFd final {
private:
    mutable bool isPolling{false};

    void setPollingState(bool state) const { isPolling = state; }

public:
    binder::unique_fd fd;

    RpcTransportFd() = default;
    explicit RpcTransportFd(binder::unique_fd&& descriptor)
          : isPolling(false), fd(std::move(descriptor)) {}

    RpcTransportFd(RpcTransportFd &&transportFd) noexcept
          : isPolling(transportFd.isPolling), fd(std::move(transportFd.fd)) {}

    RpcTransportFd &operator=(RpcTransportFd &&transportFd) noexcept {
        fd = std::move(transportFd.fd);
        isPolling = transportFd.isPolling;
        return *this;
    }

    RpcTransportFd& operator=(binder::unique_fd&& descriptor) noexcept {
        fd = std::move(descriptor);
        isPolling = false;
        return *this;
    }

    bool isInPollingState() const { return isPolling; }
    friend class FdTrigger;
};

} // namespace android

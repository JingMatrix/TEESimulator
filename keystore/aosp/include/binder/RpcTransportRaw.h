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

// Wraps the transport layer of RPC. Implementation uses plain sockets.
// Note: don't use directly. You probably want newServerRpcTransportCtx / newClientRpcTransportCtx.

#pragma once

#include <memory>

#include <binder/Common.h>
#include <binder/RpcTransport.h>

namespace android {

// RpcTransportCtxFactory with TLS disabled.
class RpcTransportCtxFactoryRaw : public RpcTransportCtxFactory {
public:
    LIBBINDER_EXPORTED static std::unique_ptr<RpcTransportCtxFactory> make();

    LIBBINDER_EXPORTED std::unique_ptr<RpcTransportCtx> newServerCtx() const override;
    LIBBINDER_EXPORTED std::unique_ptr<RpcTransportCtx> newClientCtx() const override;
    LIBBINDER_EXPORTED const char* toCString() const override;

private:
    RpcTransportCtxFactoryRaw() = default;
};

} // namespace android

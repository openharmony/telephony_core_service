/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef I_NETWORK_SEARCH_CALLBACK_STUB_H
#define I_NETWORK_SEARCH_CALLBACK_STUB_H

#include <cstdint>
#include "i_network_search_callback.h"
#include "iremote_stub.h"
#include "network_search_result.h"

namespace OHOS {
namespace Telephony {
class INetworkSearchCallbackStub : public IRemoteStub<INetworkSearchCallback> {
public:
    static const int32_t DEFAULT_ERROR = -1;
    static const int32_t DEFAULT_RESULT = 0;
    INetworkSearchCallbackStub() = default;
    virtual ~INetworkSearchCallbackStub() = default;
    int32_t OnNetworkSearchCallback(NetworkSearchCallback requestId, MessageParcel &data) override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override final;
    virtual void OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode);
    virtual void OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode);
    virtual void OnSetRadioStateCallback(const bool setResult, const int32_t errorCode);
    virtual void OnGetRadioStateCallback(const bool setResult, const int32_t errorCode);
    virtual void OnGetNetworkSearchInformation(
        const sptr<NetworkSearchResult> &networkSearchResult, const int32_t errorCode);
    virtual void OnSetPreferredNetworkCallback(const bool result, const int32_t errorCode);
    virtual void OnGetPreferredNetworkCallback(const int32_t networkMode, const int32_t errorCode);
    virtual void OnSetPsAttachStatusCallback(const int32_t psAttachStatus, const int32_t errorCode);

private:
    void OnSetNetworkModeCallback(MessageParcel &data);
    void OnGetNetworkModeCallback(MessageParcel &data);
    void OnSetRadioStateCallback(MessageParcel &data);
    void OnGetRadioStateCallback(MessageParcel &data);
    void OnGetNetworkSearchInformation(MessageParcel &data);
    void OnSetPreferredNetworkCallback(MessageParcel &data);
    void OnGetPreferredNetworkCallback(MessageParcel &data);
    void OnSetPsAttachStatusCallback(MessageParcel &data);
};
} // namespace Telephony
} // namespace OHOS
#endif // I_NETWORK_SEARCH_CALLBACK_STUB_H
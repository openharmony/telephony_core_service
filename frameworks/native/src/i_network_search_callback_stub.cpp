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

#include "i_network_search_callback_stub.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
int32_t INetworkSearchCallbackStub::OnNetworkSearchCallback(NetworkSearchCallback requestId, MessageParcel &data)
{
    auto callbackType = requestId;
    TELEPHONY_LOGI("INetworkSearchCallbackStub::OnNetworkSearchCallback requestId:%{public}d", callbackType);
    switch (callbackType) {
        case INetworkSearchCallback::NetworkSearchCallback::GET_AVAILABLE_RESULT: {
            OnGetNetworkSearchInformation(data);
            break;
        }
        case INetworkSearchCallback::NetworkSearchCallback::GET_NETWORK_MODE_RESULT: {
            OnGetNetworkModeCallback(data);
            break;
        }
        case INetworkSearchCallback::NetworkSearchCallback::SET_NETWORK_MODE_RESULT: {
            OnSetNetworkModeCallback(data);
            break;
        }
        case INetworkSearchCallback::NetworkSearchCallback::GET_RADIO_STATUS_RESULT: {
            OnGetRadioStateCallback(data);
            break;
        }
        case INetworkSearchCallback::NetworkSearchCallback::SET_RADIO_STATUS_RESULT: {
            OnSetRadioStateCallback(data);
            break;
        }
        case INetworkSearchCallback::NetworkSearchCallback::GET_PREFERRED_NETWORK_MODE_RESULT: {
            OnGetPreferredNetworkCallback(data);
            break;
        }
        case INetworkSearchCallback::NetworkSearchCallback::SET_PREFERRED_NETWORK_MODE_RESULT: {
            OnSetPreferredNetworkCallback(data);
            break;
        }
        default: {
            return DEFAULT_ERROR;
        }
    }
    return DEFAULT_RESULT;
}

void INetworkSearchCallbackStub::OnSetNetworkModeCallback(MessageParcel &data)
{
    bool result = data.ReadBool();
    int32_t error = data.ReadInt32();
    OnSetNetworkModeCallback(result, error);
}

void INetworkSearchCallbackStub::OnGetNetworkModeCallback(MessageParcel &data)
{
    int32_t selectionMode = data.ReadInt32();
    int32_t error = data.ReadInt32();
    OnGetNetworkModeCallback(selectionMode, error);
}

void INetworkSearchCallbackStub::OnSetRadioStateCallback(MessageParcel &data)
{
    bool result = data.ReadBool();
    int32_t error = data.ReadInt32();
    OnSetRadioStateCallback(result, error);
}

void INetworkSearchCallbackStub::OnGetRadioStateCallback(MessageParcel &data)
{
    bool result = data.ReadBool();
    int32_t error = data.ReadInt32();
    OnGetRadioStateCallback(result, error);
}

void INetworkSearchCallbackStub::OnGetNetworkSearchInformation(MessageParcel &data)
{
    sptr<NetworkSearchResult> callback = NetworkSearchResult::Unmarshalling(data);
    int32_t error = data.ReadInt32();
    OnGetNetworkSearchInformation(callback, error);
}

void INetworkSearchCallbackStub::OnSetPreferredNetworkCallback(MessageParcel &data)
{
    bool result = data.ReadBool();
    int32_t error = data.ReadInt32();
    OnSetPreferredNetworkCallback(result, error);
}

void INetworkSearchCallbackStub::OnGetPreferredNetworkCallback(MessageParcel &data)
{
    int32_t networkMode = data.ReadInt32();
    int32_t error = data.ReadInt32();
    OnGetPreferredNetworkCallback(networkMode, error);
}

void INetworkSearchCallbackStub::OnGetNetworkSearchInformation(
    const sptr<NetworkSearchResult> &networkSearchResult, const int32_t errorCode)
{}

void INetworkSearchCallbackStub::OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnSetRadioStateCallback(const bool setResult, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnGetRadioStateCallback(const bool setResult, const int32_t errorCode) {}

int INetworkSearchCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return OnNetworkSearchCallback(static_cast<NetworkSearchCallback>(code), data);
}

void INetworkSearchCallbackStub::OnSetPreferredNetworkCallback(const bool result, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnGetPreferredNetworkCallback(const int32_t networkMode, const int32_t errorCode)
{}
} // namespace Telephony
} // namespace OHOS
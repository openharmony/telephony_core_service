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
    auto callbackType = static_cast<int32_t>(requestId);
    TELEPHONY_LOGI("INetworkSearchCallbackStub::OnNetworkSearchCallback requestId:%{public}d", callbackType);
    switch (callbackType) {
        case GET_AVAILABLE_RESULT: {
            TELEPHONY_LOGI("OnNetworkSearchCallback case GET_AVAILABLE_RESULT");
            sptr<NetworkSearchResult> callback = NetworkSearchResult::Unmarshalling(data);
            int32_t error = data.ReadInt32();
            TELEPHONY_LOGI("OnNetworkSearchCallback before OnGetNetworkSearchResult");
            OnGetNetworkSearchResult(callback, error);
            TELEPHONY_LOGI("OnNetworkSearchCallback case GET_AVAILABLE_RESULT end");
            break;
        }
        case GET_NETWORK_MODE_RESULT: {
            int32_t selectionMode = data.ReadInt32();
            int32_t error = data.ReadInt32();
            OnGetNetworkModeCallback(selectionMode, error);
            break;
        }
        case SET_NETWORK_MODE_RESULT: {
            bool result = data.ReadBool();
            int32_t error = data.ReadInt32();
            OnSetNetworkModeCallback(result, error);
            break;
        }
        case GET_RADIO_STATUS_RESULT: {
            bool result = data.ReadBool();
            int32_t error = data.ReadInt32();
            OnGetRadioStatusCallback(result, error);
            break;
        }
        case SET_RADIO_STATUS_RESULT: {
            bool result = data.ReadBool();
            int32_t error = data.ReadInt32();
            OnSetRadioStatusCallback(result, error);
            break;
        }
        default: {
            return DEFAULT_ERROR;
        }
    }
    return DEFAULT_RESULT;
}

void INetworkSearchCallbackStub::OnGetNetworkSearchResult(
    const sptr<NetworkSearchResult> &networkSearchResult, const int32_t errorCode)
{}

void INetworkSearchCallbackStub::OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnSetRadioStatusCallback(const bool setResult, const int32_t errorCode) {}

void INetworkSearchCallbackStub::OnGetRadioStatusCallback(const bool setResult, const int32_t errorCode) {}

int INetworkSearchCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return OnNetworkSearchCallback(static_cast<NetworkSearchCallback>(code), data);
}
} // namespace Telephony
} // namespace OHOS
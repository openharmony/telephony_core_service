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

#include "network_search_test_callback_stub.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
void NetworkSearchTestCallbackStub::OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnGetNetworkModeCallback success searchModel:%{public}d, "
        "errorCode:%{public}d",
        searchModel, errorCode);
}
void NetworkSearchTestCallbackStub::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnSetNetworkModeCallback success setResult:%{public}d, "
        "errorCode:%{public}d",
        setResult, errorCode);
}

void NetworkSearchTestCallbackStub::OnSetRadioStateCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnSetRadioStateCallback success setResult:%{public}d, "
        "errorCode:%{public}d",
        setResult, errorCode);
}

void NetworkSearchTestCallbackStub::OnGetRadioStateCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnGetRadioStateCallback success setResult:%{public}d, "
        "errorCode:%{public}d",
        setResult, errorCode);
}

void NetworkSearchTestCallbackStub::OnGetNetworkSearchInformation(
    const sptr<NetworkSearchResult> &nsResult, const int32_t errorCode)
{
    if (errorCode == 0) {
        TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnGetNetworkSearchInformation success");
        sptr<NetworkSearchResult> networkSearchResult = nsResult;
        if (networkSearchResult != nullptr) {
            std::vector<NetworkInformation> networkStates = networkSearchResult->GetNetworkSearchInformation();
            if (!networkStates.empty()) {
                for (auto &networkState : networkStates) {
                    TELEPHONY_LOGI(
                        "NetworkSearchTestCallbackStub OnGetNetworkSearchInformation plmnNumeric:%{public}s,"
                        " shortOperatorName:%{public}s, rat_:%{public}d",
                        networkState.GetOperatorNumeric().c_str(), networkState.GetOperatorShortName().c_str(),
                        networkState.GetRadioTech());
                }
            }
        }
    } else {
        TELEPHONY_LOGE(
            "NetworkSearchTestCallbackStub OnGetNetworkSearchInformation fail errorCode:%{public}d", errorCode);
    }
}

void NetworkSearchTestCallbackStub::OnSetPreferredNetworkCallback(const bool result, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnSetPreferredNetworkCallback success, result:%{public}d, "
        "errorCode:%{public}d",
        result, errorCode);
}

void NetworkSearchTestCallbackStub::OnGetPreferredNetworkCallback(
    const int32_t networkMode, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnGetPreferredNetworkCallback success, result:%{public}d, "
        "errorCode:%{public}d",
        networkMode, errorCode);
}

void NetworkSearchTestCallbackStub::OnSetPsAttachStatusCallback(
    const int32_t psAttachStatus, const int32_t errorCode)
{
    TELEPHONY_LOGI(
        "NetworkSearchTestCallbackStub OnSetPsAttachStatusCallback success, result:%{public}d, "
        "errorCode:%{public}d",
        psAttachStatus, errorCode);
}
} // namespace Telephony
} // namespace OHOS
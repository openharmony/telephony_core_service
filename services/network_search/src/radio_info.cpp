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

#include "radio_info.h"

#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "hril_types.h"

namespace OHOS {
namespace Telephony {
RadioInfo::RadioInfo() {}

RadioInfo::RadioInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void RadioInfo::ProcessGetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::unique_ptr<HRilRadioStateInfo> object = event->GetUniqueObject<HRilRadioStateInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if ((responseInfo == nullptr && object == nullptr) || nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState object is nullptr!");
        return;
    }
    int64_t index = 0;
    bool state = false;
    MessageParcel data;
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState false");
        index = responseInfo->flag;
        state = false;
        if (!data.WriteBool(state) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState WriteBool slotId is false");
            nsm->RemoveCallbackFromMap(index);
            return;
        }
    }

    if (object != nullptr) {
        index = object->flag;
        int32_t RadioState = object->state;
        TELEPHONY_LOGI("RadioInfo::ProcessGetRadioState RadioState is:%{public}d", RadioState);
        if (RadioState == static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_ON)) {
            state = true;
        }
        nsm->SetRadioStateValue((ModemPowerState)RadioState);

        if (!data.WriteBool(state) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState WriteBool slotId is false");
            nsm->RemoveCallbackFromMap(index);
            return;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = nsm->FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr &&
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::GET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGI("RadioInfo::ProcessGetRadioState callback success");
        }
        nsm->RemoveCallbackFromMap(index);
    }
}

void RadioInfo::ProcessSetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::unique_ptr<HRilRadioStateInfo> object = event->GetUniqueObject<HRilRadioStateInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if ((responseInfo == nullptr && object == nullptr) || nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState object is nullptr!");
        return;
    }
    MessageParcel data;
    int64_t index = 0;
    bool result = true;
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState false");
        index = responseInfo->flag;
        result = (static_cast<int32_t>(responseInfo->error) ==
                     static_cast<int32_t>(HRilErrno::HRIL_ERR_REPEAT_STATUS)) ?
            true :
            false;
        if (!data.WriteBool(result) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState WriteBool result is false");
            nsm->RemoveCallbackFromMap(index);
            return;
        }
    }

    if (object != nullptr) {
        TELEPHONY_LOGI("RadioInfo::ProcessSetRadioState ok");
        index = object->flag;
        result = true;
        if (!data.WriteBool(result) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState WriteBool result is false");
            nsm->RemoveCallbackFromMap(index);
            return;
        }
    }

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = nsm->FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        if (result) {
            nsm->SetRadioStateValue((ModemPowerState)(callbackInfo->param_));
        }
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr &&
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::SET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGI("RadioInfo::ProcessSetRadioState callback success");
        }
        nsm->RemoveCallbackFromMap(index);
    }
}

void RadioInfo::ProcessRadioChange() const
{
    SetToTheSuitableState();
}

void RadioInfo::ProcessGetImei(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGI("RadioInfo::ProcessGetImei");
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei event is nullptr");
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult nsm is nullptr");
        return;
    }

    std::shared_ptr<std::string> imeiID = event->GetSharedObject<std::string>();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei networkSearchManager_ is nullptr");
        return;
    }
    nsm->SetImei(Str8ToStr16(*imeiID));
}

void RadioInfo::SetToTheSuitableState() const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult nsm is nullptr");
        return;
    }
    if (nsm != nullptr) {
        ModemPowerState rdState = nsm->GetRadioStateValue();
        switch (rdState) {
            case ModemPowerState::CORE_SERVICE_POWER_OFF: {
                nsm->SetRadioState(false, 0);
                break;
            }
            case ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE: {
                break;
            }
            default:
                break;
        }
    }
}
} // namespace Telephony
} // namespace OHOS

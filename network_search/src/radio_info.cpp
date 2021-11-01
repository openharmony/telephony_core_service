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
#include "telephony_log_wrapper.h"
#include "hril_types.h"

namespace OHOS {
namespace Telephony {
RadioInfo::RadioInfo() {}

RadioInfo::RadioInfo(std::shared_ptr<NetworkSearchManager> const &networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void RadioInfo::ProcessGetRadioStatus(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::unique_ptr<HRilRadioStateInfo> object = event->GetUniqueObject<HRilRadioStateInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((responseInfo == nullptr && object == nullptr) || networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioStatus object is nullptr!");
        return;
    }
    int64_t index = 0;
    bool state = false;
    MessageParcel data;
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioStatus false");
        index = responseInfo->flag;
        state = false;
        if (!data.WriteBool(state) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetRadioStatus WriteBool slotId is false");
            networkSearchManager_->RemoveCallbackFromMap(index);
            return;
        }
    }

    if (object != nullptr) {
        index = object->flag;
        int32_t radioStatus = object->state;
        TELEPHONY_LOGI("RadioInfo::ProcessGetRadioStatus RadioStatus is:%{public}d", radioStatus);
        if (radioStatus == CORE_SERVICE_POWER_ON) {
            state = true;
        }
        if (radioStatus == CORE_SERVICE_POWER_ON || radioStatus == CORE_SERVICE_POWER_OFF) {
            networkSearchManager_->SetRadioStatusValue((ModemPowerState)radioStatus);
        } else {
            networkSearchManager_->SetRadioStatusValue(CORE_SERVICE_POWER_NOT_AVAILABLE);
        }

        if (!data.WriteBool(state) || !data.WriteInt32(0)) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetRadioStatus WriteBool slotId is false");
            networkSearchManager_->RemoveCallbackFromMap(index);
            return;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        networkSearchManager_->FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchCacheItem_;
        if (callback != nullptr &&
            callback->OnNetworkSearchCallback(INetworkSearchCallback::GET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGD("RadioInfo::ProcessGetRadioStatus callback success");
        }
        networkSearchManager_->RemoveCallbackFromMap(index);
    }
}

void RadioInfo::ProcessSetRadioStatus(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::unique_ptr<HRilRadioStateInfo> object = event->GetUniqueObject<HRilRadioStateInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((responseInfo == nullptr && object == nullptr) || networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioStatus object is nullptr!");
        return;
    }
    MessageParcel data;
    int64_t index = 0;
    bool result = true;
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioStatus false");
        index = responseInfo->flag;
        result = (static_cast<int>(responseInfo->error) == HRilErrno::HRIL_ERR_REPEAT_STATUS) ? true : false;
        if (!data.WriteBool(result) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("RadioInfo::ProcessSetRadioStatus WriteBool result is false");
            networkSearchManager_->RemoveCallbackFromMap(index);
            return;
        }
    }

    if (object != nullptr) {
        TELEPHONY_LOGI("RadioInfo::ProcessSetRadioStatus ok");
        index = object->flag;
        result = true;
        if (!data.WriteBool(result) || !data.WriteInt32(0)) {
            TELEPHONY_LOGE("RadioInfo::ProcessSetRadioStatus WriteBool result is false");
            networkSearchManager_->RemoveCallbackFromMap(index);
            return;
        }
    }

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        networkSearchManager_->FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        if (result) {
            networkSearchManager_->SetRadioStatusValue((ModemPowerState)(callbackInfo->param_));
        }
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchCacheItem_;
        if (callback != nullptr &&
            callback->OnNetworkSearchCallback(INetworkSearchCallback::SET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGD("RadioInfo::ProcessSetRadioStatus callback success");
        }
        networkSearchManager_->RemoveCallbackFromMap(index);
    } else {
        TELEPHONY_LOGD("RadioInfo::ProcessSetRadioStatus callback not found");
    }
}

void RadioInfo::ProcessRadioChange() const
{
    SetToTheSuitableState();
}

void RadioInfo::SetToTheSuitableState() const
{
    if (networkSearchManager_ != nullptr) {
        ModemPowerState rdState = networkSearchManager_->GetRadioStatusValue();
        switch (rdState) {
            case CORE_SERVICE_POWER_OFF: {
                networkSearchManager_->SetRadioState(false, 0);
                break;
            }
            case CORE_SERVICE_POWER_NOT_AVAILABLE: {
                break;
            }
            default:
                break;
        }
    }
}

void RadioInfo::ProcessGetImei(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGE("RadioInfo::ProcessGetImei");
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei event is nullptr");
        return;
    }
    std::shared_ptr<std::string> imeiID = event->GetSharedObject<std::string>();
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei networkSearchManager_ is nullptr");
        return;
    }
    networkSearchManager_->SetImei(Str8ToStr16(*imeiID));
}
} // namespace Telephony
} // namespace OHOS

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
#include "core_manager.h"
#include "hril_types.h"
#include "hril_modem_parcel.h"

namespace OHOS {
namespace Telephony {
PhoneType RadioInfo::RadioTechToPhoneType(RadioTech radioTech) const
{
    PhoneType phoneType = PhoneType::PHONE_TYPE_IS_NONE;
    switch (radioTech) {
        case RadioTech::RADIO_TECHNOLOGY_GSM:
        case RadioTech::RADIO_TECHNOLOGY_WCDMA:
        case RadioTech::RADIO_TECHNOLOGY_HSPA:
        case RadioTech::RADIO_TECHNOLOGY_HSPAP:
        case RadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
        case RadioTech::RADIO_TECHNOLOGY_LTE:
        case RadioTech::RADIO_TECHNOLOGY_LTE_CA:
        case RadioTech::RADIO_TECHNOLOGY_NR:
            phoneType = PhoneType::PHONE_TYPE_IS_GSM;
            break;
        case RadioTech::RADIO_TECHNOLOGY_1XRTT:
        case RadioTech::RADIO_TECHNOLOGY_EVDO:
        case RadioTech::RADIO_TECHNOLOGY_EHRPD:
            phoneType = PhoneType::PHONE_TYPE_IS_CDMA;
            break;
        case RadioTech::RADIO_TECHNOLOGY_UNKNOWN:
        default:
            phoneType = PhoneType::PHONE_TYPE_IS_NONE;
            break;
    }
    return phoneType;
}

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
        if (RadioState == CORE_SERVICE_POWER_ON) {
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
    } else {
        if (nsm->GetRadioState() != ModemPowerState::CORE_SERVICE_POWER_ON &&
            !nsm->GetAirplaneMode()) {
            nsm->SetRadioState(static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
        }
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
                     static_cast<int32_t>(HRilErrNumber::HRIL_ERR_REPEAT_STATUS)) ?
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
        TELEPHONY_LOGE("NetworkSelection::ProcessGetImei nsm is nullptr");
        return;
    }

    std::shared_ptr<std::string> imeiID = event->GetSharedObject<std::string>();
    if (imeiID == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei imei is nullptr");
        return;
    }
    nsm->SetImei(Str8ToStr16(*imeiID));
}

void RadioInfo::ProcessGetMeid(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGI("RadioInfo::ProcessGetMeid");
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid event is nullptr");
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessGetMeid nsm is nullptr");
        return;
    }

    std::shared_ptr<std::string> meid = event->GetSharedObject<std::string>();
    if (meid == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid meid is nullptr");
        return;
    }
    nsm->SetMeid(Str8ToStr16(*meid));
}

void RadioInfo::SetToTheSuitableState() const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult nsm is nullptr");
        return;
    }
    if (nsm != nullptr) {
        ModemPowerState rdState = static_cast<ModemPowerState>(nsm->GetRadioState());
        switch (rdState) {
            case CORE_SERVICE_POWER_OFF: {
                nsm->SetRadioState(false, 0);
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

void RadioInfo::ProcessSetRadioCapability(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("RadioInfo::ProcessSetRadioCapability ok");
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioCapability event is nullptr");
        return;
    }
    std::shared_ptr<RadioCapabilityInfo> object = event->GetSharedObject<RadioCapabilityInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo == nullptr && object == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioCapability object is nullptr!");
        return;
    }
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioCapability false %{public}d %{public}d", responseInfo->error,
            responseInfo->flag);
    }
    if (object != nullptr) {
        TELEPHONY_LOGI("RadioInfo::ProcessGetRadioState ratfamily is:%{public}d", object->ratfamily);
    }
}

void RadioInfo::ProcessGetRadioCapability(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGI("RadioInfo::ProcessGetRadioCapability");
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioCapability event is nullptr");
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessGetRadioCapability nsm is nullptr");
        return;
    }

    std::shared_ptr<RadioCapabilityInfo> rc = event->GetSharedObject<RadioCapabilityInfo>();
    if (rc == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioCapability rc is nullptr");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetRadioCapability RadioCapability : %{public}d", rc->ratfamily);
    nsm->SetCapability(0, *rc);
}

void RadioInfo::SetPhoneType(PhoneType phoneType)
{
    phoneType_ = phoneType;
}

PhoneType RadioInfo::GetPhoneType() const
{
    return phoneType_;
}

void RadioInfo::UpdatePhone(RadioTech csRadioTech)
{
    TELEPHONY_LOGI("NetworkType::UpdatePhone");
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork networkSearchManager is nullptr\n");
        return;
    }
    PhoneType phoneType = RadioTechToPhoneType(csRadioTech);
    if (phoneType_ == phoneType) {
        TELEPHONY_LOGI("NetworkType::UpdatePhone No Change");
        return;
    }
    if (phoneType == PhoneType::PHONE_TYPE_IS_NONE) {
        TELEPHONY_LOGE("NetworkType::UpdatePhone phoneType is UNKNOWN");
        return;
    }
    TELEPHONY_LOGI("NetworkType::UpdatePhone SetPhoneType is success %{public}d", phoneType);
    SetPhoneType(phoneType);

    int radioState = networkSearchManager->GetRadioState();
    if (static_cast<ModemPowerState>(radioState) != CORE_SERVICE_POWER_NOT_AVAILABLE) {
        networkSearchManager->GetRadioCapability(CoreManager::DEFAULT_SLOT_ID);
        networkSearchManager->GetImei(CoreManager::DEFAULT_SLOT_ID);
        networkSearchManager->GetMeid(CoreManager::DEFAULT_SLOT_ID);
        if (static_cast<ModemPowerState>(radioState) == CORE_SERVICE_POWER_ON) {
            networkSearchManager->GetVoiceTech();
        }
    }
}

void RadioInfo::ProcessVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NetworkType::ProcessVoiceTechChange ok");
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessVoiceTechChange event is nullptr");
        return;
    }
    std::shared_ptr<VoiceRadioTechnology> radioTech = event->GetSharedObject<VoiceRadioTechnology>();
    if (radioTech == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessVoiceTechChange radioTech is nullptr");
        return;
    }
    UpdatePhone(static_cast<RadioTech>(radioTech->actType));
}
} // namespace Telephony
} // namespace OHOS

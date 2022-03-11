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

#include "hril_types.h"
#include "hril_modem_parcel.h"
#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
RadioInfo::RadioInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

void RadioInfo::ProcessGetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::unique_ptr<HRilRadioStateInfo> object = event->GetUniqueObject<HRilRadioStateInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if ((responseInfo == nullptr && object == nullptr) || nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState object is nullptr slotId:%{public}d", slotId_);
        return;
    }
    int64_t index = 0;
    bool state = false;
    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState false slotId:%{public}d", slotId_);
        index = responseInfo->flag;
        state = false;
        if (!data.WriteBool(state) || !data.WriteInt32((int32_t)responseInfo->error)) {
            NetworkUtils::RemoveCallbackFromMap(index);
            return;
        }
    }
    if (object != nullptr) {
        index = object->flag;
        int32_t radioState = object->state;
        TELEPHONY_LOGI(
            "RadioInfo::ProcessGetRadioState RadioState is:%{public}d slotId:%{public}d", radioState, slotId_);
        state = (radioState == ModemPowerState::CORE_SERVICE_POWER_ON) ? true : false;
        nsm->SetRadioStateValue(slotId_, (ModemPowerState)radioState);
        if (!data.WriteBool(state) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            NetworkUtils::RemoveCallbackFromMap(index);
            return;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr && callback->OnNetworkSearchCallback(
            INetworkSearchCallback::NetworkSearchCallback::GET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState callback fail slotId:%{public}d", slotId_);
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    } else {
        if (nsm->GetRadioState(slotId_) != ModemPowerState::CORE_SERVICE_POWER_ON && !nsm->GetAirplaneMode()) {
            nsm->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
        }
        if (nsm->GetRadioState(slotId_) == ModemPowerState::CORE_SERVICE_POWER_ON) {
            nsm->TriggerSimRefresh(slotId_);
        }
    }
}

void RadioInfo::ProcessSetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::unique_ptr<HRilRadioStateInfo> object = event->GetUniqueObject<HRilRadioStateInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if ((responseInfo == nullptr && object == nullptr) || nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState object is nullptr slotId:%{public}d", slotId_);
        return;
    }
    MessageParcel data;
    int64_t index = 0;
    bool result = true;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState false slotId:%{public}d", slotId_);
        index = responseInfo->flag;
        int32_t error = static_cast<int32_t>(responseInfo->error);
        int32_t status = static_cast<int32_t>(HRilErrNumber::HRIL_ERR_REPEAT_STATUS);
        result = (error == status) ? true : false;
        if (!data.WriteBool(result) || !data.WriteInt32((int32_t)responseInfo->error)) {
            NetworkUtils::RemoveCallbackFromMap(index);
            return;
        }
    }
    if (object != nullptr) {
        TELEPHONY_LOGI("RadioInfo::ProcessSetRadioState ok slotId:%{public}d", slotId_);
        index = object->flag;
        result = true;
        if (!data.WriteBool(result) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            NetworkUtils::RemoveCallbackFromMap(index);
            return;
        }
    }

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        if (result) {
            nsm->SetRadioStateValue(slotId_, (ModemPowerState)(callbackInfo->param_));
        }
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr && callback->OnNetworkSearchCallback(
            INetworkSearchCallback::NetworkSearchCallback::SET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState callback fail slotId:%{public}d", slotId_);
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    } else {
        int32_t networkMode = nsm->GetPreferredNetworkValue(slotId_);
        nsm->SetPreferredNetwork(slotId_, networkMode);
        nsm->SetLocateUpdate(slotId_);
    }
}

void RadioInfo::ProcessGetImei(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGI("RadioInfo::ProcessGetImei slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessGetImei nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<HRilStringParcel> imeiID = event->GetSharedObject<HRilStringParcel>();
    if (imeiID == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei imei is nullptr slotId:%{public}d", slotId_);
        nsm->SetImei(slotId_, u"");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetImei get imei success");
    nsm->SetImei(slotId_, Str8ToStr16(imeiID->data));
}

void RadioInfo::ProcessGetMeid(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGI("RadioInfo::ProcessGetMeid slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessGetMeid nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<HRilStringParcel> meid = event->GetSharedObject<HRilStringParcel>();
    if (meid == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid meid is nullptr slotId:%{public}d", slotId_);
        nsm->SetMeid(slotId_, u"");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetMeid success");
    nsm->SetMeid(slotId_, Str8ToStr16(meid->data));
}

void RadioInfo::ProcessGetRadioCapability(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGI("RadioInfo::ProcessGetRadioCapability slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioCapability event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessGetRadioCapability nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<RadioCapabilityInfo> rc = event->GetSharedObject<RadioCapabilityInfo>();
    if (rc == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioCapability rc is nullptr slotId:%{public}d", slotId_);
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetRadioCapability RadioCapability : %{public}d slotId:%{public}d",
        rc->ratFamily, slotId_);
    nsm->SetCapability(slotId_, *rc);
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

    int radioState = networkSearchManager->GetRadioState(slotId_);
    if (static_cast<ModemPowerState>(radioState) != CORE_SERVICE_POWER_NOT_AVAILABLE) {
        if (phoneType == PhoneType::PHONE_TYPE_IS_GSM) {
            networkSearchManager->GetImei(slotId_);
            networkSearchManager->SetMeid(slotId_, u"");
        } else {
            networkSearchManager->GetMeid(slotId_);
            networkSearchManager->SetImei(slotId_, u"");
        }
        networkSearchManager->GetRadioCapability(slotId_);
        if (static_cast<ModemPowerState>(radioState) == CORE_SERVICE_POWER_ON) {
            networkSearchManager->GetVoiceTech(slotId_);
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
} // namespace Telephony
} // namespace OHOS

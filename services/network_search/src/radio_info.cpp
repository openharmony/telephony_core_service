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

#include "core_service_hisysevent.h"
#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const int32_t INVALID_SLOT_ID = -1;

RadioInfo::RadioInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

void RadioInfo::ProcessGetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::unique_ptr<RadioStateInfo> object = event->GetUniqueObject<RadioStateInfo>();
    std::shared_ptr<RadioResponseInfo> responseInfo = event->GetSharedObject<RadioResponseInfo>();
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if ((responseInfo == nullptr && object == nullptr) || nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState object is nullptr slotId:%{public}d", slotId_);
        return;
    }
    int64_t index = 0;
    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRadioState false slotId:%{public}d", slotId_);
        if (!WriteRadioStateResponseInfo(index, data, false, responseInfo)) {
            return;
        }
    }
    if (object != nullptr) {
        TELEPHONY_LOGI("ProcessGetRadioState RadioState is:%{public}d slotId:%{public}d", object->state, slotId_);
        bool state = (object->state == ModemPowerState::CORE_SERVICE_POWER_ON) ? true : false;
        nsm->SetRadioStateValue(slotId_, static_cast<ModemPowerState>(object->state));
        if (!WriteRadioStateObject(index, data, state, object)) {
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
        bool isAirplaneModeOn = false;
        nsm->GetAirplaneMode(isAirplaneModeOn);
        if (nsm->GetRadioState(slotId_) == ModemPowerState::CORE_SERVICE_POWER_OFF && !isAirplaneModeOn) {
            nsm->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
        }
        if (nsm->GetRadioState(slotId_) == ModemPowerState::CORE_SERVICE_POWER_ON) {
            nsm->TriggerSimRefresh(slotId_);
        }
    }
}

void RadioInfo::ProcessSetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::unique_ptr<RadioStateInfo> object = event->GetUniqueObject<RadioStateInfo>();
    std::shared_ptr<RadioResponseInfo> responseInfo = event->GetSharedObject<RadioResponseInfo>();
    if (responseInfo == nullptr && object == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState object is nullptr slotId:%{public}d", slotId_);
        return;
    }
    MessageParcel data;
    int64_t index = 0;
    bool result = true;
    ModemPowerState radioState = ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState false slotId:%{public}d", slotId_);
        int32_t error = static_cast<int32_t>(responseInfo->error);
        int32_t status = static_cast<int32_t>(ErrType::ERR_REPEAT_STATUS);
        result = (error == status) ? true : false;
        if (!WriteRadioStateResponseInfo(index, data, result, responseInfo)) {
            return;
        }
    }
    if (object != nullptr) {
        TELEPHONY_LOGI("RadioInfo::ProcessSetRadioState ok slotId:%{public}d", slotId_);
        radioState = static_cast<ModemPowerState>(object->flag);
        result = true;
        if (!WriteRadioStateObject(index, data, result, object)) {
            return;
        }
    }
    UpdateInfoOfSetRadioState(radioState, result, data, index);
}

void RadioInfo::RadioFirstPowerOn(std::shared_ptr<NetworkSearchManager> &nsm, ModemPowerState radioState) const
{
    TELEPHONY_LOGI(
        "RadioInfo::RadioFirstPowerOn radioState:%{public}d, slotId:%{public}d", static_cast<int>(radioState), slotId_);
    if (radioState != ModemPowerState::CORE_SERVICE_POWER_ON) {
        return;
    }
    if (!nsm->IsRadioFirstPowerOn(slotId_)) {
        return;
    }
    nsm->SetRadioFirstPowerOn(slotId_, false);
}

void RadioInfo::ProcessGetImei(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<StringParcel> imeiID = event->GetSharedObject<StringParcel>();
    if (imeiID == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImei imei is nullptr slotId:%{public}d", slotId_);
        nsm->SetImei(slotId_, u"");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetImei get imei success slotId:%{public}d", slotId_);
    nsm->SetImei(slotId_, Str8ToStr16(imeiID->data));
}

void RadioInfo::ProcessGetImeiSv(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImeiSv event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImeiSv nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<StringParcel> imeiSvID = event->GetSharedObject<StringParcel>();
    if (imeiSvID == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetImeiSv imeiSv is nullptr slotId:%{public}d", slotId_);
        nsm->SetImeiSv(slotId_, u"");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetImeiSv get imeiSv success slotId:%{public}d", slotId_);
    nsm->SetImeiSv(slotId_, Str8ToStr16(imeiSvID->data));
}

void RadioInfo::ProcessGetMeid(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<StringParcel> meid = event->GetSharedObject<StringParcel>();
    if (meid == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetMeid meid is nullptr slotId:%{public}d", slotId_);
        nsm->SetMeid(slotId_, u"");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::ProcessGetMeid success slotId:%{public}d", slotId_);
    nsm->SetMeid(slotId_, Str8ToStr16(meid->data));
}

void RadioInfo::SetPhoneType(PhoneType phoneType)
{
    phoneType_ = phoneType;
}

PhoneType RadioInfo::GetPhoneType() const
{
    return phoneType_;
}

void RadioInfo::UpdatePhone(RadioTech csRadioTech, const RadioTech &psRadioTech)
{
    TELEPHONY_LOGI("RadioInfo::UpdatePhone");
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("RadioInfo::UpdatePhone networkSearchManager is nullptr");
        return;
    }
    PhoneType phoneType = RadioTechToPhoneType(csRadioTech, psRadioTech);
    if (phoneType_ == phoneType) {
        TELEPHONY_LOGI("RadioInfo::UpdatePhone No Change");
        return;
    }
    if (phoneType == PhoneType::PHONE_TYPE_IS_NONE) {
        TELEPHONY_LOGE("RadioInfo::UpdatePhone phoneType is UNKNOWN");
        return;
    }
    TELEPHONY_LOGI("RadioInfo::UpdatePhone SetPhoneType is success %{public}d", phoneType);
    SetPhoneType(phoneType);

    int radioState = networkSearchManager->GetRadioState(slotId_);
    if (static_cast<ModemPowerState>(radioState) != CORE_SERVICE_POWER_NOT_AVAILABLE) {
        networkSearchManager->InitSimRadioProtocol(slotId_);
        std::u16string meid = u"";
        std::u16string imei = u"";
        std::u16string imeiSv = u"";
        std::string basebandVersion = "";
        networkSearchManager->SetImei(slotId_, imei);
        networkSearchManager->SetImeiSv(slotId_, imeiSv);
        networkSearchManager->SetMeid(slotId_, meid);
        networkSearchManager->SetBasebandVersion(slotId_, basebandVersion);
        networkSearchManager->GetImei(slotId_, imei);
        networkSearchManager->GetImeiSv(slotId_, imeiSv);
        networkSearchManager->GetMeid(slotId_, meid);
        networkSearchManager->GetBasebandVersion(slotId_, basebandVersion);
        if (static_cast<ModemPowerState>(radioState) == CORE_SERVICE_POWER_ON) {
            networkSearchManager->GetVoiceTech(slotId_);
        }
    }
}

void RadioInfo::ProcessVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessVoiceTechChange event is nullptr");
        return;
    }
    std::shared_ptr<VoiceRadioTechnology> csRadioTech = event->GetSharedObject<VoiceRadioTechnology>();
    if (csRadioTech == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessVoiceTechChange csRadioTech is nullptr");
        return;
    }
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessVoiceTechChange networkSearchManager is nullptr");
        return;
    }
    int32_t psRadioTech = 0;
    networkSearchManager->GetPsRadioTech(slotId_, psRadioTech);
    UpdatePhone(static_cast<RadioTech>(csRadioTech->actType), static_cast<RadioTech>(psRadioTech));
}

PhoneType RadioInfo::RadioTechToPhoneType(RadioTech csRadioTech, const RadioTech &psRadioTech) const
{
    PhoneType phoneType = PhoneType::PHONE_TYPE_IS_NONE;
    switch (csRadioTech) {
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
            if (psRadioTech == RadioTech::RADIO_TECHNOLOGY_LTE || psRadioTech == RadioTech::RADIO_TECHNOLOGY_LTE_CA ||
                psRadioTech == RadioTech::RADIO_TECHNOLOGY_NR) {
                phoneType = PhoneType::PHONE_TYPE_IS_GSM;
            }
            break;
    }
    return phoneType;
}

void RadioInfo::AirplaneModeChange()
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    bool isAirplaneModeOn = false;
    if (nsm->GetAirplaneMode(isAirplaneModeOn) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("AirplaneModeChange GetAirplaneMode fail slotId:%{public}d", slotId_);
    }
    CoreServiceHiSysEvent::WriteAirplaneModeChangeEvent(isAirplaneModeOn);
    bool lastAirplaneMode = false;
    nsm->GetLocalAirplaneMode(slotId_, lastAirplaneMode);
    if (isAirplaneModeOn == lastAirplaneMode) {
        TELEPHONY_LOGE("airplaneMode is not change, slotId:%{public}d", slotId_);
        return;
    }
    if (nsm->GetRadioState(slotId_) == ModemPowerState::CORE_SERVICE_POWER_OFF && isAirplaneModeOn == false) {
        TELEPHONY_LOGI("radio is off, airplaneMode is closed, slotId:%{public}d", slotId_);
        SetRadioOnIfNeeded();
    }
    if (nsm->GetRadioState(slotId_) == ModemPowerState::CORE_SERVICE_POWER_ON && isAirplaneModeOn == true) {
        TELEPHONY_LOGI("radio is on, airplaneMode is opened, slotId:%{public}d", slotId_);
        sptr<NetworkSearchCallBackBase> cellularData = nsm->GetCellularDataCallBack();
        if (cellularData) {
            cellularData->ClearCellularDataConnections(slotId_);
        }
        sptr<NetworkSearchCallBackBase> cellularCall = nsm->GetCellularCallCallBack();
        if (cellularCall) {
            cellularCall->ClearCellularCallList(slotId_);
        }
        nsm->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_OFF), 0);
    }
    nsm->SetLocalAirplaneMode(slotId_, isAirplaneModeOn);
    TELEPHONY_LOGI("airplaneMode:%{public}d, slotId:%{public}d", isAirplaneModeOn, slotId_);
}

void RadioInfo::SetRadioOnIfNeeded()
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    auto simManager = nsm->GetSimManager();
    if (simManager == nullptr) {
        TELEPHONY_LOGE("get simManager failed");
        return;
    }
    bool isActive = simManager->IsSimActive(slotId_);
    bool hasSim = false;
    simManager->HasSimCard(slotId_, hasSim);
    int32_t primarySlot = INVALID_SLOT_ID;
    simManager->GetPrimarySlotId(primarySlot);
    if (isActive || (!hasSim && slotId_ == primarySlot)) {
        TELEPHONY_LOGI("need set radio on. isActive:%{public}d, hasSim:%{public}d, primarySlot:%{public}d",
            isActive, hasSim, primarySlot);
        nsm->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    }
}

int32_t RadioInfo::ProcessGetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    TELEPHONY_LOGD("RadioInfo::ProcessGetBasebandVersion slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetBasebandVersion event is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetBasebandVersion nsm is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<StringParcel> version = event->GetSharedObject<StringParcel>();
    if (version == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetBasebandVersion version is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGD("RadioInfo::ProcessGetBasebandVersion success");
    nsm->SetBasebandVersion(slotId_, version->data);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t RadioInfo::ProcessGetRrcConnectionState(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("start slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRrcConnectionState event is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRrcConnectionState nsm is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    auto object = event->GetSharedObject<Int32Parcel>();
    if (object == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetRrcConnectionState object is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("rrc state[%{public}d] notify success, slotId:%{public}d", object->data, slotId_);
    int32_t result = nsm->HandleRrcStateChanged(slotId_, object->data);
    if (result != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("Do not need notify, result:%{public}d, slotId:%{public}d", result, slotId_);
        return result;
    }
    nsm->ProcessNotifyStateChangeEvent(slotId_);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t RadioInfo::ProcessSetNrOptionMode(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("start slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetNrOptionMode event is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<RadioResponseInfo> responseInfo = event->GetSharedObject<RadioResponseInfo>();
    if (responseInfo == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetNrOptionMode responseInfo is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetNrOptionMode nsm is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int64_t index = responseInfo->flag;
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetNrOptionMode callbackInfo is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    bool success = responseInfo->error == ErrType::NONE;
    if (success) {
        nsm->UpdateNrOptionMode(slotId_, static_cast<NrMode>(callbackInfo->param_));
    }
    sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
    if (callback == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetNrOptionMode callback is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (!data.WriteBool(success) ||
        !data.WriteInt32(success ? TELEPHONY_SUCCESS : static_cast<int32_t>(responseInfo->error))) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetNrOptionMode write date fail slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    callback->OnNetworkSearchCallback(INetworkSearchCallback::NetworkSearchCallback::SET_NR_OPTION_MODE_RESULT, data);
    NetworkUtils::RemoveCallbackFromMap(index);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t RadioInfo::ProcessGetNrOptionMode(const AppExecFwk::InnerEvent::Pointer &event) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (event == nullptr || nsm == nullptr) {
        TELEPHONY_LOGE("event or nsm is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<NrModeInfo> nrModeInfo = event->GetSharedObject<NrModeInfo>();
    if (TELEPHONY_EXT_WRAPPER.getNrOptionModeExt_ != nullptr && nrModeInfo != nullptr) {
        TELEPHONY_EXT_WRAPPER.getNrOptionModeExt_(slotId_, nrModeInfo->nrMode);
    }
    std::shared_ptr<RadioResponseInfo> responseInfo = event->GetSharedObject<RadioResponseInfo>();
    if (responseInfo == nullptr && nrModeInfo == nullptr) {
        TELEPHONY_LOGE("responseInfo and mode is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    int64_t index = -1;
    int32_t nrMode = static_cast<int32_t>(NrMode::NR_MODE_UNKNOWN);
    if (nrModeInfo != nullptr) {
        nrMode = nrModeInfo->nrMode;
        index = nrModeInfo->flag;
        nsm->UpdateNrOptionMode(slotId_, static_cast<NrMode>(nrMode));
        if (!data.WriteInt32(nrMode) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetNrOptionMode WriteInt32 nrMode is false");
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    } else if (responseInfo != nullptr) {
        index = responseInfo->flag;
        if (!data.WriteInt32(nrMode) || !data.WriteInt32(static_cast<int32_t>(responseInfo->error))) {
            TELEPHONY_LOGE("RadioInfo::ProcessGetNrOptionMode WriteInt32 nrMode is false");
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetNrOptionMode callbackInfo is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
    if (callback == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessGetNrOptionMode callback is nullptr slotId:%{public}d", slotId_);
        NetworkUtils::RemoveCallbackFromMap(index);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callback->OnNetworkSearchCallback(INetworkSearchCallback::NetworkSearchCallback::GET_NR_OPTION_MODE_RESULT, data);
    NetworkUtils::RemoveCallbackFromMap(index);
    return TELEPHONY_ERR_SUCCESS;
}

bool RadioInfo::WriteRadioStateResponseInfo(
    int64_t &index, MessageParcel &data, bool result, std::shared_ptr<RadioResponseInfo> &responseInfo) const
{
    index = responseInfo->flag;
    if (!data.WriteBool(result) || !data.WriteInt32(static_cast<int32_t>(responseInfo->error))) {
        NetworkUtils::RemoveCallbackFromMap(index);
        return false;
    }
    return true;
}

bool RadioInfo::WriteRadioStateObject(
    int64_t &index, MessageParcel &data, bool state, std::unique_ptr<RadioStateInfo> &object) const
{
    index = object->flag;
    if (!data.WriteBool(state) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
        NetworkUtils::RemoveCallbackFromMap(index);
        return false;
    }
    return true;
}

void RadioInfo::UpdateInfoOfSetRadioState(
    ModemPowerState &radioState, bool result, MessageParcel &data, int64_t index) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState NetworkSearchManager is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        if (result) {
            nsm->SetRadioStateValue(slotId_, static_cast<ModemPowerState>(callbackInfo->param_));
            radioState = static_cast<ModemPowerState>(callbackInfo->param_);
        }
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr && callback->OnNetworkSearchCallback(
            INetworkSearchCallback::NetworkSearchCallback::SET_RADIO_STATUS_RESULT, data)) {
            TELEPHONY_LOGE("RadioInfo::ProcessSetRadioState callback fail slotId:%{public}d", slotId_);
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    } else {
        nsm->SetLocateUpdate(slotId_);
    }
    if (result) {
        RadioFirstPowerOn(nsm, radioState);
    }
}
} // namespace Telephony
} // namespace OHOS

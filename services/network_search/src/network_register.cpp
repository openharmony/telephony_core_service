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

#include "network_register.h"
#include <cinttypes>

#include "hril_modem_parcel.h"
#include "hril_network_parcel.h"
#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "i_network_search_callback.h"

namespace OHOS {
namespace Telephony {
NetworkRegister::NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState,
    std::weak_ptr<NetworkSearchManager> networkSearchManager)
    : networkSearchState_(networkSearchState), networkSearchManager_(networkSearchManager)
{}

void NetworkRegister::ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister networkSearchManager is nullptr");
        return;
    }
    networkSearchManager->decMsgNum();
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister event is nullptr");
        return;
    }
    std::shared_ptr<CsRegStatusInfo> csRegStateResult = event->GetSharedObject<CsRegStatusInfo>();
    if (csRegStateResult == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister csRegStateResult is nullptr\n");
        return;
    }
    RilRegister registrationStatus = static_cast<RilRegister>(csRegStateResult->regStatus);
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister networkSearchState_ is nullptr\n");
        return;
    }
    networkSearchState_->SetNetworkState(regStatus, DomainType::DOMAIN_TYPE_CS);
    RadioTech tech = ConvertTechFromRil(static_cast<HRiRadioTechnology>(csRegStateResult->radioTechnology));
    networkSearchState_->SetNetworkType(tech, DomainType::DOMAIN_TYPE_CS);
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DomainType::DOMAIN_TYPE_CS);
    TELEPHONY_LOGI("ProcessCsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d",
        registrationStatus, csRegStateResult->radioTechnology, roam);
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister nsm is nullptr");
        return;
    }
    nsm->UpdateCellLocation(static_cast<int32_t>(tech), csRegStateResult->cellId, csRegStateResult->lacCode);
    networkSearchState_->CsRadioTechChange();
    if (networkSearchManager->CheckIsNeedNotify()) {
        networkSearchState_->NotifyStateChange();
    }
}

void NetworkRegister::ProcessRestrictedState(const AppExecFwk::InnerEvent::Pointer &event) const {}

void NetworkRegister::ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister networkSearchManager is nullptr");
        return;
    }
    networkSearchManager->decMsgNum();
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister event is nullptr");
        return;
    }

    std::shared_ptr<PsRegStatusResultInfo> psRegStatusResult = event->GetSharedObject<PsRegStatusResultInfo>();
    if (psRegStatusResult == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister psRegStatusResult is nullptr\n");
        return;
    }
    RilRegister registrationStatus = static_cast<RilRegister>(psRegStatusResult->regStatus);
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister networkSearchState_ is nullptr\n");
        return;
    }
    networkSearchState_->SetNetworkState(regStatus, DomainType::DOMAIN_TYPE_PS);
    RadioTech tech = ConvertTechFromRil(static_cast<HRiRadioTechnology>(psRegStatusResult->radioTechnology));
    networkSearchState_->SetNetworkType(tech, DomainType::DOMAIN_TYPE_PS);
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DomainType::DOMAIN_TYPE_PS);
    TELEPHONY_LOGI("ProcessPsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d",
        registrationStatus, psRegStatusResult->radioTechnology, roam);

    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister nsm is nullptr");
        return;
    }
    nsm->UpdateCellLocation(static_cast<int32_t>(tech), psRegStatusResult->cellId, psRegStatusResult->lacCode);
    if (networkSearchManager->CheckIsNeedNotify()) {
        networkSearchState_->NotifyStateChange();
    }
}

void NetworkRegister::ProcessPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("NetworkRegister::ProcessPsAttachStatus ok");
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsAttachStatus event is nullptr");
        return;
    }

    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsAttachStatus nsm is nullptr");
        return;
    }

    MessageParcel data;
    int64_t index = 0;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsAttachStatus HRilRadioResponseInfo error is %{public}d",
            responseInfo->error);
        index = responseInfo->flag;
        if (!data.WriteBool(false) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("NetworkRegister::ProcessPsAttachStatus WriteBool slotId is false");
            nsm->RemoveCallbackFromMap(index);
            return;
        }
    } else {
        index = event->GetParam();
        TELEPHONY_LOGI("NetworkRegister::ProcessPsAttachStatus index:(%{public}" PRId64 ")", index);
        if (!data.WriteBool(true) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("NetworkRegister::ProcessPsAttachStatus WriteBool slotId is false");
            nsm->RemoveCallbackFromMap(index);
            return;
        }
    }

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
            nsm->FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        int32_t psAttachStatus = callbackInfo->param_;
        TELEPHONY_LOGI(
            "NetworkRegister::ProcessPsAttachStatus psAttachStatus is:%{public}d", psAttachStatus);
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::SET_PS_ATTACH_STATUS_RESULT, data);
            TELEPHONY_LOGI("NetworkRegister::ProcessPsAttachStatus callback success");
        }
        nsm->RemoveCallbackFromMap(index);
    }
}

RegServiceState NetworkRegister::ConvertRegFromRil(RilRegister code) const
{
    switch (code) {
        case RilRegister::REG_STATE_SEARCH:
            return RegServiceState::REG_STATE_SEARCH;
        case RilRegister::REG_STATE_NOT_REG:
        case RilRegister::REG_STATE_NO_SERVICE:
            return RegServiceState::REG_STATE_NO_SERVICE;
        case RilRegister::REG_STATE_INVALID:
            return RegServiceState::REG_STATE_UNKNOWN;
        case RilRegister::REG_STATE_ROAMING:
        case RilRegister::REG_STATE_HOME_ONLY:
            return RegServiceState::REG_STATE_IN_SERVICE;
        case RilRegister::REG_STATE_EMERGENCY_ONLY:
            return RegServiceState::REG_STATE_EMERGENCY_ONLY;
        default:
            return RegServiceState::REG_STATE_NO_SERVICE;
    }
}

RadioTech NetworkRegister::ConvertTechFromRil(HRiRadioTechnology code) const
{
    switch (code) {
        case HRiRadioTechnology::HRIL_RADIO_GSM:
        case HRiRadioTechnology::HRIL_RADIO_GSM_COMPACT:
        case HRiRadioTechnology::HRIL_RADIO_EGPRS:
            return RadioTech::RADIO_TECHNOLOGY_GSM;
        case HRiRadioTechnology::HRIL_RADIO_HSDPA_HSUPA:
        case HRiRadioTechnology::HRIL_RADIO_HSDPA:
        case HRiRadioTechnology::HRIL_RADIO_HSUPA:
            return RadioTech::RADIO_TECHNOLOGY_WCDMA;
        case HRiRadioTechnology::HRIL_RADIO_EUTRAN:
            return RadioTech::RADIO_TECHNOLOGY_LTE;
        default:
            return RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    }
}
} // namespace Telephony
} // namespace OHOS

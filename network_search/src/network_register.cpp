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
#include "hril_modem_parcel.h"
#include "hril_network_parcel.h"
#include "network_search_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkRegister::NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState)
    : networkSearchState_(networkSearchState)
{}

void NetworkRegister::ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister event is nullptr");
        return;
    }

    std::shared_ptr<CsRegStatusInfo> csRegStateResult = event->GetSharedObject<CsRegStatusInfo>();
    if (csRegStateResult == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister csRegStateResult is nullptr\n");
        return;
    }
    int registrationStatus = csRegStateResult->regStatus;
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister networkSearchState_ is nullptr\n");
        return;
    }
    networkSearchState_->SetNetworkState(regStatus, DOMAIN_TYPE_CS);
    RadioTech tech = ConvertTechFromRil(csRegStateResult->radioTechnology);
    networkSearchState_->SetNetworkType(tech, DOMAIN_TYPE_CS);
    RoamingType roam = ROAMING_STATE_UNKNOWN;
    if (registrationStatus == REG_STATE_ROAMING) {
        roam = ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DOMAIN_TYPE_CS);
    TELEPHONY_LOGD("ProcessCsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d",
        registrationStatus, csRegStateResult->radioTechnology, roam);
    networkSearchState_->NotifyStateChange();
}

void NetworkRegister::ProcessRestrictedState(const AppExecFwk::InnerEvent::Pointer &event) const {}

void NetworkRegister::ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister event is nullptr");
        return;
    }

    std::shared_ptr<PsRegStatusResultInfo> psRegStatusResult = event->GetSharedObject<PsRegStatusResultInfo>();
    if (psRegStatusResult == nullptr) {
        TELEPHONY_LOGI("NetworkRegister::ProcessPsRegister psRegStatusResult is nullptr\n");
        return;
    }
    int registrationStatus = psRegStatusResult->regStatus;
    RegServiceState regStatus = ConvertRegFromRil(psRegStatusResult->regStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister networkSearchState_ is nullptr\n");
        return;
    }
    networkSearchState_->SetNetworkState(regStatus, DOMAIN_TYPE_PS);
    RadioTech tech = ConvertTechFromRil(psRegStatusResult->radioTechnology);
    networkSearchState_->SetNetworkType(tech, DOMAIN_TYPE_PS);
    RoamingType roam = ROAMING_STATE_UNKNOWN;
    if (registrationStatus == REG_STATE_ROAMING) {
        roam = ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DOMAIN_TYPE_PS);
    TELEPHONY_LOGD("ProcessPsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d",
        registrationStatus, psRegStatusResult->radioTechnology, roam);
    networkSearchState_->NotifyStateChange();
}

RegServiceState NetworkRegister::ConvertRegFromRil(int code) const
{
    switch (code) {
        case RilRegister::REG_STATE_SEARCH:
            return RegServiceState::REG_STATE_SEARCH;
        case RilRegister::REG_STATE_NOT_REG:
        case RilRegister::REG_STATE_NO_SERVICE:
        case RilRegister::REG_STATE_INVALID:
            return RegServiceState::REG_STATE_NO_SERVICE;
        case RilRegister::REG_STATE_ROAMING:
        case RilRegister::REG_STATE_HOME_ONLY:
            return RegServiceState::REG_STATE_IN_SERVICE;
        default:
            return RegServiceState::REG_STATE_NO_SERVICE;
    }
}

RadioTech NetworkRegister::ConvertTechFromRil(int code) const
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

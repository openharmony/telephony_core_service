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

#include "hilog_network_search.h"
#include "network_search_manager.h"

namespace OHOS {
NetworkRegister::NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState)
    : networkSearchState_(networkSearchState), phone_()
{}

void NetworkRegister::ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<CsRegStatusInfo> csRegStateResult = event->GetSharedObject<CsRegStatusInfo>();
    if (!csRegStateResult) {
        HILOG_INFO("NetworkRegister::ProcessCsRegister csRegStateResult is nullptr\n");
        return;
    }

    int registrationStatus = csRegStateResult->regStatus;
    RegServiceState regStatus = ConvertRegToNetworkState(registrationStatus);
    networkSearchState_->SetNetworkState(regStatus, DOMAIN_TYPE_CS);
    networkSearchState_->SetNetworkType((RadioTech)csRegStateResult->radioTechnology, DOMAIN_TYPE_CS);
    if (phone_.PhoneTypeGsmOrNot()) {
        if ((registrationStatus >= REG_STATE_EMERGENCY_NOT_REG) &&
            (registrationStatus <= REG_STATE_EMERGENCY_UNKNOWN)) {
            pressingOnly_ = true;
        } else {
            pressingOnly_ = false;
        }
    }
    networkSearchState_->SetEmergency(pressingOnly_);
    HILOG_INFO("ProcessCsRegister: regStatus= %{public}d radioTechnology= %{public}d", registrationStatus,
        csRegStateResult->radioTechnology);

    networkSearchState_->NotifyStateChange();
}

void NetworkRegister::ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<PsRegStatusResultInfo> psRegStatusResult = event->GetSharedObject<PsRegStatusResultInfo>();
    if (!psRegStatusResult) {
        HILOG_INFO("NetworkRegister::ProcessPsRegister psRegStatusResult is nullptr\n");
        return;
    }

    int registrationStatus = psRegStatusResult->regStatus;
    RegServiceState regStatus = ConvertRegToNetworkState(psRegStatusResult->regStatus);
    networkSearchState_->SetNetworkState(regStatus, DOMAIN_TYPE_PS);
    networkSearchState_->SetNetworkType((RadioTech)psRegStatusResult->radioTechnology, DOMAIN_TYPE_PS);
    HILOG_INFO("ProcessPsRegister: regStatus= %{public}d radioTechnology= %{public}d", registrationStatus,
        psRegStatusResult->radioTechnology);

    networkSearchState_->NotifyStateChange();
}

RegServiceState NetworkRegister::ConvertRegToNetworkState(int code)
{
    switch (code) {
        case RilRegister::REG_STATE_SEARCH:
            return RegServiceState::REG_STATE_SEARCH;
        case RilRegister::REG_STATE_NOT_REG:
        case RilRegister::REG_STATE_NO_SERVICE:
        case RilRegister::REG_STATE_INVALID:
            return RegServiceState::REG_STATE_NO_SERVICE;
        case RilRegister::REG_STATE_HOME_ONLY:
            return RegServiceState::REG_STATE_IN_SERVICE;
        case RilRegister::REG_STATE_EMERGENCY_NOT_REG:
        case RilRegister::REG_STATE_EMERGENCY_UNKNOWN:
            return RegServiceState::REG_STATE_EMERGENCY_ONLY;
        default:
            return RegServiceState::REG_STATE_NO_SERVICE;
    }
}
} // namespace OHOS

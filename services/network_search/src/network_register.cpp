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

#include "parameter.h"
#include "string_ex.h"
#include "hril_modem_parcel.h"
#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "i_network_search_callback.h"
#include "resource_utils.h"

namespace OHOS {
namespace Telephony {
const char *TELEPHONY_NR_CONVERSION_CONFIG_INDEX = "persist.telephony.nr.config.index"; // "A/B/C/D"
/**
 * System configuration format
 * NOT_SUPPORT：4g,NO_DETECT:4g,CONNECTED_DETECT:4g,IDLE_DETECT:4g,DUAL_CONNECTED:5g,SA_ATTACHED:5g
 */
const char *TELEPHONY_NR_CONVERSION_CONFIG_A = "persist.telephony.nr.config.a";
const char *TELEPHONY_NR_CONVERSION_CONFIG_B = "persist.telephony.nr.config.b";
const char *TELEPHONY_NR_CONVERSION_CONFIG_C = "persist.telephony.nr.config.c";
const char *TELEPHONY_NR_CONVERSION_CONFIG_D = "persist.telephony.nr.config.d";
const int32_t SYS_PARAMETER_SIZE = 256;
const int32_t NR_STATE_NUM = 6;
const int32_t KEY_VALUE_NUM = 2;

NetworkRegister::NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState,
    std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchState_(networkSearchState), networkSearchManager_(networkSearchManager), slotId_(slotId)
{
    ResourceUtils::Get().GetValueByName<bool>(ResourceUtils::IS_CS_CAPABLE, isCsCapable_);
}

void NetworkRegister::InitNrConversionConfig()
{
    char prase[SYS_PARAMETER_SIZE] = {0};
    int code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG_INDEX, "A", prase, SYS_PARAMETER_SIZE);
    if (code <= 0 || prase[0] > 'D' || prase[0] < 'A') {
        TELEPHONY_LOGE(
            "Failed to get system properties %{public}s. err:%{public}d slotId:%{public}d", prase, code, slotId_);
        return;
    }

    switch (prase[0]) {
        case 'A':
            code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG_A, "", prase, SYS_PARAMETER_SIZE);
            break;
        case 'B':
            code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG_B, "", prase, SYS_PARAMETER_SIZE);
            break;
        case 'C':
            code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG_C, "", prase, SYS_PARAMETER_SIZE);
            break;
        case 'D':
            code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG_D, "", prase, SYS_PARAMETER_SIZE);
            break;
        default:
            break;
    }

    std::string strNrConfig = "";
    strNrConfig = prase;
    if (code <= 0 || strNrConfig.empty()) {
        TELEPHONY_LOGI("Failed to get system properties err:%{public}d use default config a", code);
        strNrConfig =
            "NOT_SUPPORT:4g,NO_DETECT:4g,CONNECTED_DETECT:4g,"
            "IDLE_DETECT:4g,DUAL_CONNECTED:5g,SA_ATTACHED:5g";
    }
    NrConfigParse(strNrConfig);
}

void NetworkRegister::ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE(
            "NetworkRegister::ProcessCsRegister networkSearchManager is nullptr slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->decMsgNum(slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<CsRegStatusInfo> csRegStateResult = event->GetSharedObject<CsRegStatusInfo>();
    if (csRegStateResult == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister csRegStateResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    RilRegister registrationStatus = static_cast<RilRegister>(csRegStateResult->regStatus);
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE(
            "NetworkRegister::ProcessCsRegister networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    networkSearchState_->SetNetworkState(regStatus, DomainType::DOMAIN_TYPE_CS);
    networkSearchState_->SetEmergency((regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY) && isCsCapable_);
    RadioTech tech = ConvertTechFromRil(static_cast<HRilRadioTech>(csRegStateResult->radioTechnology));
    networkSearchState_->SetNetworkType(tech, DomainType::DOMAIN_TYPE_CS);
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DomainType::DOMAIN_TYPE_CS);
    TELEPHONY_LOGI(
        "ProcessCsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d slotId:%{public}d",
        registrationStatus, csRegStateResult->radioTechnology, roam, slotId_);
    networkSearchManager->UpdateCellLocation(
        slotId_, static_cast<int32_t>(tech), csRegStateResult->cellId, csRegStateResult->lacCode);
    if (networkSearchManager->CheckIsNeedNotify(slotId_) || networkSearchState_->IsEmergency()) {
        networkSearchState_->NotifyStateChange();
    }
}

void NetworkRegister::ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister networkSearchManager is nullptr");
        return;
    }
    networkSearchManager->decMsgNum(slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister event is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<PsRegStatusResultInfo> psRegStatusResult = event->GetSharedObject<PsRegStatusResultInfo>();
    if (psRegStatusResult == nullptr) {
        TELEPHONY_LOGE(
            "NetworkRegister::ProcessPsRegister psRegStatusResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    RilRegister registrationStatus = static_cast<RilRegister>(psRegStatusResult->regStatus);
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE(
            "NetworkRegister::ProcessPsRegister networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    networkSearchState_->SetNetworkState(regStatus, DomainType::DOMAIN_TYPE_PS);
    networkSearchState_->SetEmergency((regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY) && isCsCapable_);
    RadioTech tech = ConvertTechFromRil(static_cast<HRilRadioTech>(psRegStatusResult->radioTechnology));
    networkSearchState_->SetNetworkType(tech, DomainType::DOMAIN_TYPE_PS);
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DomainType::DOMAIN_TYPE_PS);

    endcSupport_ = psRegStatusResult->isEnDcAvailable;
    dcNrRestricted_ = psRegStatusResult->isDcNrRestricted;
    nrSupport_ = psRegStatusResult->isNrAvailable;
    UpdateNrState();
    UpdateCfgTech();

    TELEPHONY_LOGI(
        "ProcessPsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d slotId:%{public}d",
        registrationStatus, psRegStatusResult->radioTechnology, roam, slotId_);
    if (networkSearchManager->CheckIsNeedNotify(slotId_) || networkSearchState_->IsEmergency()) {
        networkSearchState_->NotifyStateChange();
    }
}

void NetworkRegister::ProcessChannelConfigInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<ChannelConfigInfoList> channelConfigInfoList = event->GetSharedObject<ChannelConfigInfoList>();
    if (channelConfigInfoList == nullptr) {
        TELEPHONY_LOGE(
            "NetworkRegister::ProcessChannelConfigInfo psRegStatusResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    int32_t size = channelConfigInfoList->itemNum;
    TELEPHONY_LOGI(
        "NetworkRegister::ProcessChannelConfigInfo num size:%{public}d slotId:%{public}d", size, slotId_);
    if (channelConfigInfoList->channelConfigInfos.size() > 0 &&
        static_cast<int32_t>(channelConfigInfoList->channelConfigInfos.size()) == size) {
        std::vector<PhysicalChannelConfig> &configs = channelConfigInfoList->channelConfigInfos;
        channelConfigInfos_.clear();
        channelConfigInfos_.insert(channelConfigInfos_.begin(), configs.begin(), configs.end());
    } else {
        TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo data error slotId:%{public}d", slotId_);
        return;
    }

    bool isNrSecondaryCell = false;
    for (int i = 0; i < size; ++i) {
        if (static_cast<RadioTech>(channelConfigInfos_[i].ratType) == RadioTech::RADIO_TECHNOLOGY_NR &&
            static_cast<ConnectServiceCell>(channelConfigInfos_[i].cellConnStatus) ==
            ConnectServiceCell::CONNECTION_SECONDARY_CELL) {
            isNrSecondaryCell = true;
            break;
        }
    }
    NotifyNrFrequencyChanged();
    if (isNrSecondaryCell_ != isNrSecondaryCell) {
        isNrSecondaryCell_ = isNrSecondaryCell;
        UpdateNrState();
        UpdateCfgTech();
    }
}

void NetworkRegister::NotifyNrFrequencyChanged()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo networkSearchManager is nullptr");
        return;
    }
    bool isFreqChanged = false;
    FrequencyType curFreqType = FrequencyType::FREQ_TYPE_UNKNOWN;

    sptr<NetworkSearchCallBackBase> cellularData = networkSearchManager->GetCellularDataCallBack();
    if (cellularData == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo cellularData callback is nullptr");
        return;
    }
    int32_t size = channelConfigInfos_.size();
    for (int i = 0; i < size; ++i) {
        std::vector<int32_t> &cids = channelConfigInfos_[i].contextIds;
        if (!isFreqChanged) {
            for (auto &cid : cids) {
                if (cellularData->HasInternetCapability(slotId_, cid)) {
                    curFreqType = static_cast<FrequencyType>(channelConfigInfos_[i].freqRange);
                    isFreqChanged = true;
                    break;
                }
            }
        }
        if (isFreqChanged) {
            break;
        }
    }

    if (freqType_ != curFreqType) {
        freqType_ = curFreqType;
        networkSearchManager->NotifyNrFrequencyChanged(slotId_);
        networkSearchManager->SetFrequencyType(slotId_, freqType_);
    }
}

void NetworkRegister::DcPhysicalLinkActiveUpdate(bool isActive)
{
    TELEPHONY_LOGI("NetworkRegister::DcPhysicalLinkActiveUpdate isActive:%{public}s slotId:%{public}d",
        isActive ? "true" : "false", slotId_);
    isPhysicalLinkActive_ = isActive;
    UpdateNrState();
    UpdateCfgTech();
}

void NetworkRegister::UpdateNrState()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr || networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::UpdateNrState error slotId:%{public}d", slotId_);
        return;
    }

    // update NR mode and NR state
    NrMode nrMode = NrMode::NR_MODE_UNKNOWN;
    nrState_ = NrState::NR_STATE_NOT_SUPPORT;
    RadioTech rat = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();
    if (rat == RadioTech::RADIO_TECHNOLOGY_NR) {
        nrMode = NrMode::NR_MODE_SA_ONLY;
        nrState_ = NrState::NR_NSA_STATE_SA_ATTACHED;
    }

    if (endcSupport_ && (rat == RadioTech::RADIO_TECHNOLOGY_LTE || rat == RadioTech::RADIO_TECHNOLOGY_LTE_CA)) {
        nrMode = NrMode::NR_MODE_NSA_ONLY;

        if (dcNrRestricted_) {
            nrState_ = NrState::NR_STATE_NOT_SUPPORT;
        }
        if (!dcNrRestricted_ && !nrSupport_) {
            nrState_ = NrState::NR_NSA_STATE_NO_DETECT;
        }
        if (!dcNrRestricted_ && nrSupport_ && !isPhysicalLinkActive_ && !isNrSecondaryCell_) {
            nrState_ = NrState::NR_NSA_STATE_IDLE_DETECT;
        }
        if (isNrSecondaryCell_ || (!dcNrRestricted_ && nrSupport_ && isPhysicalLinkActive_)) {
            if (rat == RadioTech::RADIO_TECHNOLOGY_LTE) {
                nrState_ = NrState::NR_NSA_STATE_CONNECTED_DETECT;
            }
            if (rat == RadioTech::RADIO_TECHNOLOGY_LTE_CA) {
                nrState_ = NrState::NR_NSA_STATE_DUAL_CONNECTED;
            }
        }
    }
    networkSearchManager->SetNrOptionMode(slotId_, nrMode);
    networkSearchState_->SetNrState(nrState_);
}

void NetworkRegister::UpdateCfgTech()
{
    if (nrConfigMap_.find(nrState_) == nrConfigMap_.end()) {
        TELEPHONY_LOGE("NetworkRegister::UpdateCfgTech not find nr state slotId:%{public}d", slotId_);
        return;
    }
    RadioTech cfgTech = nrConfigMap_[nrState_];
    if (cfgTech != RadioTech::RADIO_TECHNOLOGY_NR) {
        cfgTech = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();
    }
    networkSearchState_->SetCfgTech(cfgTech);
}

void NetworkRegister::ProcessRestrictedState(const AppExecFwk::InnerEvent::Pointer &event) const {}

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

RadioTech NetworkRegister::ConvertTechFromRil(HRilRadioTech code) const
{
    switch (code) {
        case HRilRadioTech::RADIO_TECHNOLOGY_GSM:
            return RadioTech::RADIO_TECHNOLOGY_GSM;
        case HRilRadioTech::RADIO_TECHNOLOGY_1XRTT:
            return RadioTech::RADIO_TECHNOLOGY_1XRTT;
        case HRilRadioTech::RADIO_TECHNOLOGY_HSPA:
            return RadioTech::RADIO_TECHNOLOGY_HSPA;
        case HRilRadioTech::RADIO_TECHNOLOGY_HSPAP:
            return RadioTech::RADIO_TECHNOLOGY_HSPAP;
        case HRilRadioTech::RADIO_TECHNOLOGY_WCDMA:
            return RadioTech::RADIO_TECHNOLOGY_WCDMA;
        case HRilRadioTech::RADIO_TECHNOLOGY_LTE:
            return RadioTech::RADIO_TECHNOLOGY_LTE;
        case HRilRadioTech::RADIO_TECHNOLOGY_EVDO:
            return RadioTech::RADIO_TECHNOLOGY_EVDO;
        case HRilRadioTech::RADIO_TECHNOLOGY_EHRPD:
            return RadioTech::RADIO_TECHNOLOGY_EHRPD;
        case HRilRadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            return RadioTech::RADIO_TECHNOLOGY_TD_SCDMA;
        case HRilRadioTech::RADIO_TECHNOLOGY_LTE_CA:
            return RadioTech::RADIO_TECHNOLOGY_LTE_CA;
        case HRilRadioTech::RADIO_TECHNOLOGY_NR:
            return RadioTech::RADIO_TECHNOLOGY_NR;
        default:
            return RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    }
}

void NetworkRegister::NrConfigParse(std::string &cfgStr)
{
    /**
     * parse string
     * NOT_SUPPORT：4g,NO_DETECT:4g,CONNECTED_DETECT:4g,IDLE_DETECT:4g,DUAL_CONNECTED:5g,SA_ATTACHED:5g
    */
    std::string strSep = ",";
    std::vector<std::string> strsRet;
    SplitStr(cfgStr, strSep, strsRet);
    if (static_cast<int>(strsRet.size()) != NR_STATE_NUM) {
        TELEPHONY_LOGE("NetworkRegister::NrConfigParse string error slotId:%{public}d", slotId_);
        return;
    }

    std::string strNrFlag = "";
    std::vector<std::string> nrStateKv;
    for (auto &state : strsRet) {
        strSep = ":";
        SplitStr(state, strSep, nrStateKv);
        if (static_cast<int>(nrStateKv.size()) != KEY_VALUE_NUM) {
            TELEPHONY_LOGE("NetworkRegister::NrConfigParse key value string error slotId:%{public}d",
                slotId_);
            return;
        }
        NrState nrState = ConvertStringToNrState(nrStateKv[0]);
        RadioTech tech = RadioTech::RADIO_TECHNOLOGY_NR;
        if (nrStateKv[1].compare("5g") != 0) {
            tech = RadioTech::RADIO_TECHNOLOGY_LTE;
        }
        nrConfigMap_.insert(std::make_pair(nrState, tech));
    }
}

NrState NetworkRegister::ConvertStringToNrState(std::string &strState) const
{
    if (strState.compare("NOT_SUPPORT") == 0) {
        return NrState::NR_STATE_NOT_SUPPORT;
    } else if (strState.compare("NO_DETECT") == 0) {
        return NrState::NR_NSA_STATE_NO_DETECT;
    } else if (strState.compare("CONNECTED_DETECT") == 0) {
        return NrState::NR_NSA_STATE_CONNECTED_DETECT;
    } else if (strState.compare("IDLE_DETECT") == 0) {
        return NrState::NR_NSA_STATE_IDLE_DETECT;
    } else if (strState.compare("DUAL_CONNECTED") == 0) {
        return NrState::NR_NSA_STATE_DUAL_CONNECTED;
    } else if (strState.compare("SA_ATTACHED") == 0) {
        return NrState::NR_NSA_STATE_SA_ATTACHED;
    } else {
        return NrState::NR_STATE_NOT_SUPPORT;
    }
}
} // namespace Telephony
} // namespace OHOS

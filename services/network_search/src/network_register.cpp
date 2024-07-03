/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "core_service_hisysevent.h"
#include "enum_convert.h"
#include "i_network_search_callback.h"
#include "network_search_manager.h"
#include "parameter.h"
#include "resource_utils.h"
#include "string_ex.h"
#include "tel_ril_modem_parcel.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr const char *TELEPHONY_NR_CONVERSION_CONFIG = "persist.telephony.nr.config";
constexpr const char *TELEPHONY_NR_CONFIG_A = "ConfigA";
constexpr const char *TELEPHONY_NR_CONFIG_B = "ConfigB";
constexpr const char *TELEPHONY_NR_CONFIG_C = "ConfigC";
constexpr const char *TELEPHONY_NR_CONFIG_D = "ConfigD";
constexpr const char *TELEPHONY_NR_CONFIG_AD = "ConfigAD";
constexpr int32_t SYS_PARAMETER_SIZE = 256;
constexpr int32_t MAX_SIZE = 100;
constexpr int32_t CS_TYPE = 0;
constexpr int32_t IMS_TYPE = 1;

NetworkRegister::NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState,
    std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchState_(networkSearchState), networkSearchManager_(networkSearchManager), slotId_(slotId)
{
    ResourceUtils::Get().GetBooleanValueByName(ResourceUtils::IS_CS_CAPABLE, isCsCapable_);
}

void NetworkRegister::InitNrConversionConfig()
{
    GetSystemPropertiesConfig(systemPropertiesConfig_);
    if (systemPropertiesConfig_ == TELEPHONY_NR_CONFIG_AD) {
        int32_t rrcState = 0;
        GetRrcConnectionState(rrcState);
        if (rrcState == RRC_CONNECTED_STATUS) {
            currentNrConfig_ = TELEPHONY_NR_CONFIG_A;
        } else {
            currentNrConfig_ = TELEPHONY_NR_CONFIG_D;
        }
    } else {
        currentNrConfig_ = systemPropertiesConfig_;
    }
}

void NetworkRegister::UpdateNetworkSearchState(RegServiceState regStatus,
                                               RadioTech tech,
                                               RoamingType roam,
                                               DomainType type)
{
    regStatusResult_ = regStatus;
    networkSearchState_->SetNetworkState(regStatus, type);
    networkSearchState_->SetEmergency(
        (regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY) && isCsCapable_);
    networkSearchState_->SetNetworkType(tech, type);
    networkSearchState_->SetNetworkStateToRoaming(roam, type);
}

void NetworkRegister::ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister networkSearchManager is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<CsRegStatusInfo> csRegStateResult = event->GetSharedObject<CsRegStatusInfo>();
    if (csRegStateResult == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister csRegStateResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (csRegStateResult->flag != networkSearchManager->GetSerialNum(slotId_)) {
        TELEPHONY_LOGI("Aborting outdated cs registration event slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->decMsgNum(slotId_);
    RilRegister registrationStatus = static_cast<RilRegister>(csRegStateResult->regStatus);
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessCsRegister networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    UpdateCellularCall(regStatus, CS_TYPE);
    RadioTech tech = ConvertTechFromRil(static_cast<TelRilRadioTech>(csRegStateResult->radioTechnology));
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    UpdateNetworkSearchState(regStatus, tech, roam, DomainType::DOMAIN_TYPE_CS);
    auto iter = rilRegisterStateMap_.find(static_cast<int32_t>(registrationStatus));
    TELEPHONY_LOGI("regStatus= %{public}s(%{public}d) radioTechnology=%{public}d roam=%{public}d slotId:%{public}d",
        iter->second.c_str(), registrationStatus, csRegStateResult->radioTechnology, roam, slotId_);
    if (networkSearchManager->CheckIsNeedNotify(slotId_) || networkSearchState_->IsEmergency()) {
        TELEPHONY_LOGI("cs domain change, slotId:%{public}d", slotId_);
        networkSearchManager->ProcessNotifyStateChangeEvent(slotId_);
    }
    CoreServiceHiSysEvent::WriteNetworkStateBehaviorEvent(slotId_, static_cast<int32_t>(DomainType::DOMAIN_TYPE_CS),
        static_cast<int32_t>(tech), static_cast<int32_t>(regStatus));
}

void NetworkRegister::UpdateCellularCall(const RegServiceState &regStatus, const int32_t callType)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is nullptr");
        return;
    }
    if (regStatus == RegServiceState::REG_STATE_IN_SERVICE || regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY) {
        sptr<NetworkSearchCallBackBase> cellularCall = networkSearchManager->GetCellularCallCallBack();
        if (cellularCall) {
            cellularCall->SetReadyToCall(slotId_, callType, true);
        }
    }
}

void NetworkRegister::ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister networkSearchManager is nullptr");
        return;
    }
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<PsRegStatusResultInfo> psRegStatusResult = event->GetSharedObject<PsRegStatusResultInfo>();
    if (psRegStatusResult == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister psRegStatusResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (psRegStatusResult->flag != networkSearchManager->GetSerialNum(slotId_)) {
        TELEPHONY_LOGI("Aborting outdated ps registration event slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->decMsgNum(slotId_);
    RilRegister registrationStatus = static_cast<RilRegister>(psRegStatusResult->regStatus);
    RegServiceState regStatus = ConvertRegFromRil(registrationStatus);
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessPsRegister networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    UpdateCellularCall(regStatus, IMS_TYPE);
    RadioTech tech = ConvertTechFromRil(static_cast<TelRilRadioTech>(psRegStatusResult->radioTechnology));
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    UpdateNetworkSearchState(regStatus, tech, roam, DomainType::DOMAIN_TYPE_PS);
    endcSupport_ = psRegStatusResult->isEnDcAvailable;
    dcNrRestricted_ = psRegStatusResult->isDcNrRestricted;
    nrSupport_ = psRegStatusResult->isNrAvailable;
    UpdateNrState();
    UpdateCfgTech();
    auto iter = rilRegisterStateMap_.find(static_cast<int32_t>(registrationStatus));
    TELEPHONY_LOGI("regStatus= %{public}s(%{public}d) radioTechnology=%{public}d roam=%{public}d slotId:%{public}d",
        iter->second.c_str(), registrationStatus, psRegStatusResult->radioTechnology, roam, slotId_);
    if (networkSearchManager->CheckIsNeedNotify(slotId_) || networkSearchState_->IsEmergency()) {
        TELEPHONY_LOGI("ps domain change, slotId:%{public}d", slotId_);
        networkSearchManager->ProcessNotifyStateChangeEvent(slotId_);
    }
    CoreServiceHiSysEvent::WriteNetworkStateBehaviorEvent(slotId_, static_cast<int32_t>(DomainType::DOMAIN_TYPE_PS),
        static_cast<int32_t>(tech), static_cast<int32_t>(regStatus));
}

int32_t NetworkRegister::RevertLastTechnology()
{
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    RadioTech lastCfgTech = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    RadioTech lastPsRadioTech = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    networkSearchState_->GetLastCfgTech(lastCfgTech);
    networkSearchState_->GetLastPsRadioTech(lastPsRadioTech);
    networkSearchState_->SetCfgTech(lastCfgTech);
    networkSearchState_->SetNetworkType(lastPsRadioTech, DomainType::DOMAIN_TYPE_PS);
    TELEPHONY_LOGI(
        "lastCfgTech:%{public}d lastPsRadioTech:%{public}d slotId:%{public}d", lastCfgTech, lastPsRadioTech, slotId_);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkRegister::NotifyStateChange()
{
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    networkSearchState_->NotifyStateChange();
    return TELEPHONY_ERR_SUCCESS;
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
    TELEPHONY_LOGI("NetworkRegister::ProcessChannelConfigInfo num size:%{public}d slotId:%{public}d", size, slotId_);
    if (size >= MAX_SIZE) {
        TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo num over max size");
        return;
    }
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
    for (int32_t  i = 0; i < size; ++i) {
        if (static_cast<RadioTech>(channelConfigInfos_[i].ratType) == RadioTech::RADIO_TECHNOLOGY_NR &&
            static_cast<ConnectServiceCell>(channelConfigInfos_[i].cellConnStatus) ==
            ConnectServiceCell::CONNECTION_SECONDARY_CELL) {
            isNrSecondaryCell = true;
            break;
        }
    }
    TELEPHONY_LOGI("isNrSecondaryCell:%{public}d slotId:%{public}d", isNrSecondaryCell, slotId_);
    NotifyNrFrequencyChanged();
    if (isNrSecondaryCell_ != isNrSecondaryCell) {
        isNrSecondaryCell_ = isNrSecondaryCell;
        UpdateNrState();
        UpdateCfgTech();
        auto networkSearchManager = networkSearchManager_.lock();
        if (networkSearchManager == nullptr) {
            TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo networkSearchManager is nullptr");
            return;
        }
        TELEPHONY_LOGI("physical channel change, slotId:%{public}d", slotId_);
        networkSearchManager->ProcessNotifyStateChangeEvent(slotId_);
    }
}

void NetworkRegister::NotifyNrFrequencyChanged()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::NotifyNrFrequencyChanged networkSearchManager is nullptr");
        return;
    }
    bool isFreqChanged = false;
    FrequencyType curFreqType = FrequencyType::FREQ_TYPE_UNKNOWN;

    sptr<NetworkSearchCallBackBase> cellularData = networkSearchManager->GetCellularDataCallBack();
    if (cellularData == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::NotifyNrFrequencyChanged cellularData callback is nullptr");
        return;
    }
    ssize_t size = channelConfigInfos_.size();
    if (size >= MAX_SIZE) {
        TELEPHONY_LOGE("NetworkRegister::NotifyNrFrequencyChanged channelConfigInfos_ over max size");
        return;
    }
    for (int32_t  i = 0; i < size; ++i) {
        std::vector<int32_t> &cids = channelConfigInfos_[i].contextIds;
        if (isFreqChanged) {
            TELEPHONY_LOGE("NetworkRegister::NotifyNrFrequencyChanged channelConfigInfos:%{public}d isFreqChanged", i);
            continue;
        }
        for (auto &cid : cids) {
            if (!cellularData->HasInternetCapability(slotId_, cid)) {
                TELEPHONY_LOGE("NetworkRegister::NotifyNrFrequencyChanged cid:%{public}d hasNoInternetCapability", cid);
                continue;
            }
            curFreqType = static_cast<FrequencyType>(channelConfigInfos_[i].freqRange);
            isFreqChanged = true;
            break;
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
}

void NetworkRegister::UpdateNrState()
{
    if (networkSearchState_ == nullptr || networkSearchState_->GetNetworkStatus() == nullptr) {
        TELEPHONY_LOGE("networkSearchState_ is nullptr, slotId:%{public}d", slotId_);
        return;
    }

    nrState_ = NrState::NR_STATE_NOT_SUPPORT;
    RadioTech rat = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();
    if (rat == RadioTech::RADIO_TECHNOLOGY_NR) {
        nrState_ = NrState::NR_NSA_STATE_SA_ATTACHED;
    } else {
        if (isNrSecondaryCell_) {
            nrState_ = NrState::NR_NSA_STATE_DUAL_CONNECTED;
        } else if (endcSupport_) {
            if (dcNrRestricted_) {
                nrState_ = NrState::NR_STATE_NOT_SUPPORT;
            } else {
                nrState_ = NrState::NR_NSA_STATE_NO_DETECT;
            }
        }
    }
    nrState_ = static_cast<NrState>(UpdateNsaState(static_cast<int32_t>(nrState_)));
    networkSearchState_->SetNrState(nrState_);
}

int32_t NetworkRegister::UpdateNsaState(int32_t nsaState)
{
    int32_t newNsaState = nsaState;
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr || networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("networkSearchState_ is nullptr, slotId:%{public}d", slotId_);
        return newNsaState;
    }
    std::vector<sptr<CellInformation>> cellInfo;
    networkSearchManager->GetCellInfoList(slotId_, cellInfo);
    int32_t cellId = 0;
    auto iter = cellInfo.begin();
    while (iter != cellInfo.end()) {
        if ((*iter)->GetNetworkType() == CellInformation::CellType::CELL_TYPE_LTE) {
            cellId = (*iter)->GetCellId();
            break;
        }
        iter++;
    }
    auto networkState = networkSearchState_->GetNetworkStatus();
    if (networkState == nullptr) {
        TELEPHONY_LOGE("networkState is nullptr, slotId:%{public}d", slotId_);
        return newNsaState;
    }
    RegServiceState regState = networkState->GetRegStatus();
    RadioTech psRegTech = networkState->GetPsRadioTech();
    if (regState != RegServiceState::REG_STATE_IN_SERVICE ||
        (psRegTech != RadioTech::RADIO_TECHNOLOGY_LTE && psRegTech != RadioTech::RADIO_TECHNOLOGY_LTE_CA)) {
        return newNsaState;
    }
    if (TELEPHONY_EXT_WRAPPER.updateNsaStateExt_ != nullptr) {
        newNsaState = TELEPHONY_EXT_WRAPPER.updateNsaStateExt_(
            slotId_, cellId, nrSupport_, dcNrRestricted_, newNsaState);
    }
    return newNsaState;
}

void NetworkRegister::UpdateCfgTech()
{
    if (networkSearchState_ == nullptr || networkSearchState_->GetNetworkStatus() == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::UpdateCfgTech networkSearchState_ is nullptr slotId:%{public}d", slotId_);
        return;
    }
    RadioTech tech = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();
    TELEPHONY_LOGD("tech:%{public}d slotId:%{public}d", tech, slotId_);
    RadioTech cfgTech = GetTechnologyByNrConfig(tech);
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

RegServiceState NetworkRegister::GetRegServiceState() const
{
    return regStatusResult_;
}

RadioTech NetworkRegister::ConvertTechFromRil(TelRilRadioTech code) const
{
    switch (code) {
        case TelRilRadioTech::RADIO_TECHNOLOGY_GSM:
            return RadioTech::RADIO_TECHNOLOGY_GSM;
        case TelRilRadioTech::RADIO_TECHNOLOGY_1XRTT:
            return RadioTech::RADIO_TECHNOLOGY_1XRTT;
        case TelRilRadioTech::RADIO_TECHNOLOGY_HSPA:
            return RadioTech::RADIO_TECHNOLOGY_HSPA;
        case TelRilRadioTech::RADIO_TECHNOLOGY_HSPAP:
            return RadioTech::RADIO_TECHNOLOGY_HSPAP;
        case TelRilRadioTech::RADIO_TECHNOLOGY_WCDMA:
            return RadioTech::RADIO_TECHNOLOGY_WCDMA;
        case TelRilRadioTech::RADIO_TECHNOLOGY_LTE:
            return RadioTech::RADIO_TECHNOLOGY_LTE;
        case TelRilRadioTech::RADIO_TECHNOLOGY_EVDO:
            return RadioTech::RADIO_TECHNOLOGY_EVDO;
        case TelRilRadioTech::RADIO_TECHNOLOGY_EHRPD:
            return RadioTech::RADIO_TECHNOLOGY_EHRPD;
        case TelRilRadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            return RadioTech::RADIO_TECHNOLOGY_TD_SCDMA;
        case TelRilRadioTech::RADIO_TECHNOLOGY_LTE_CA:
            return RadioTech::RADIO_TECHNOLOGY_LTE_CA;
        case TelRilRadioTech::RADIO_TECHNOLOGY_NR:
            return RadioTech::RADIO_TECHNOLOGY_NR;
        default:
            return RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    }
}

bool NetworkRegister::IsValidConfig(const std::string &config)
{
    if (config == TELEPHONY_NR_CONFIG_A || config == TELEPHONY_NR_CONFIG_B || config == TELEPHONY_NR_CONFIG_C ||
        config == TELEPHONY_NR_CONFIG_D || config == TELEPHONY_NR_CONFIG_AD) {
        return true;
    } else {
        return false;
    }
}

int32_t NetworkRegister::GetRrcConnectionState(int32_t &rrcState)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::GetRrcConnectionState networkSearchManager is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager->UpdateRrcConnectionState(slotId_, rrcState);
}

int32_t NetworkRegister::HandleRrcStateChanged(int32_t status)
{
    if (systemPropertiesConfig_ == TELEPHONY_NR_CONFIG_AD) {
        if (status == RRC_CONNECTED_STATUS) {
            currentNrConfig_ = TELEPHONY_NR_CONFIG_A;
        } else {
            currentNrConfig_ = TELEPHONY_NR_CONFIG_D;
        }
    }
    TELEPHONY_LOGI("currentNrConfig_:%{public}s, slotId:%{public}d", currentNrConfig_.c_str(), slotId_);
    UpdateNrState();
    UpdateCfgTech();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkRegister::GetSystemPropertiesConfig(std::string &config)
{
    char param[SYS_PARAMETER_SIZE] = { 0 };
    int32_t code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG, TELEPHONY_NR_CONFIG_D, param, SYS_PARAMETER_SIZE);
    if (code <= 0 || !IsValidConfig(param)) {
        TELEPHONY_LOGE("get system properties:%{public}s, slotId:%{public}d", param, slotId_);
        config = TELEPHONY_NR_CONFIG_D;
    } else {
        config = param;
    }
    return TELEPHONY_ERR_SUCCESS;
}

RadioTech NetworkRegister::GetTechnologyByNrConfig(RadioTech tech)
{
    if (tech != RadioTech::RADIO_TECHNOLOGY_LTE_CA && tech != RadioTech::RADIO_TECHNOLOGY_LTE) {
        return tech;
    }
    if (systemPropertiesConfig_ == TELEPHONY_NR_CONFIG_AD) {
        int32_t rrcState = 0;
        GetRrcConnectionState(rrcState);
        if (rrcState == RRC_CONNECTED_STATUS) {
            currentNrConfig_ = TELEPHONY_NR_CONFIG_A;
        } else {
            currentNrConfig_ = TELEPHONY_NR_CONFIG_D;
        }
    }
    TELEPHONY_LOGI("currentNrConfig_:%{public}s, slotId:%{public}d", currentNrConfig_.c_str(), slotId_);
    switch (nrState_) {
        case NrState::NR_NSA_STATE_NO_DETECT: {
            if (currentNrConfig_ == TELEPHONY_NR_CONFIG_D) {
                tech = RadioTech::RADIO_TECHNOLOGY_NR;
            }
            break;
        }
        case NrState::NR_NSA_STATE_CONNECTED_DETECT: {
            if (currentNrConfig_ == TELEPHONY_NR_CONFIG_C || currentNrConfig_ == TELEPHONY_NR_CONFIG_D) {
                tech = RadioTech::RADIO_TECHNOLOGY_NR;
            }
            break;
        }
        case NrState::NR_NSA_STATE_IDLE_DETECT: {
            if (currentNrConfig_ == TELEPHONY_NR_CONFIG_B || currentNrConfig_ == TELEPHONY_NR_CONFIG_C ||
                currentNrConfig_ == TELEPHONY_NR_CONFIG_D) {
                tech = RadioTech::RADIO_TECHNOLOGY_NR;
            }
            break;
        }
        case NrState::NR_NSA_STATE_DUAL_CONNECTED:
            tech = RadioTech::RADIO_TECHNOLOGY_NR;
            break;
        default:
            break;
    }
    return tech;
}
} // namespace Telephony
} // namespace OHOS

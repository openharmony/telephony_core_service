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

namespace OHOS {
namespace Telephony {
const char* TELEPHONY_NR_CONVERSION_CONFIG_INDEX = "persist.telephony.nr.config.index"; // "A/B/C/D"
/**
 * System configuration format
 * NOT_SUPPORT：4g,NO_DETECT:4g,CONNECTED_DETECT:4g,IDLE_DETECT:4g,DUAL_CONNECTED:5g,SA_ATTACHED:5g
*/
const char* TELEPHONY_NR_CONVERSION_CONFIG_A = "persist.telephony.nr.config.a";
const char* TELEPHONY_NR_CONVERSION_CONFIG_B = "persist.telephony.nr.config.b";
const char* TELEPHONY_NR_CONVERSION_CONFIG_C = "persist.telephony.nr.config.c";
const char* TELEPHONY_NR_CONVERSION_CONFIG_D = "persist.telephony.nr.config.d";
const int32_t SYS_PARAMETER_SIZE = 256;
const int32_t NR_STATE_NUM = 6;
const int32_t KEY_VALUE_NUM = 2;

NetworkRegister::NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState,
    std::weak_ptr<NetworkSearchManager> networkSearchManager)
    : networkSearchState_(networkSearchState), networkSearchManager_(networkSearchManager)
{}

void NetworkRegister::InitNrConversionConfig()
{
    char prase[SYS_PARAMETER_SIZE] = {0};
    int code = GetParameter(TELEPHONY_NR_CONVERSION_CONFIG_INDEX, "A", prase, SYS_PARAMETER_SIZE);
    if (code <= 0 || prase[0] > 'D' || prase[0] < 'A') {
        TELEPHONY_LOGE("Failed to get system properties %{public}s. err:%{public}d", prase, code);
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
        strNrConfig = "NOT_SUPPORT:4g,NO_DETECT:4g,CONNECTED_DETECT:4g,"
            "IDLE_DETECT:4g,DUAL_CONNECTED:5g,SA_ATTACHED:5g";
    }
    NrConfigParse(strNrConfig);
}

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
    networkSearchState_->SetEmergency(regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY);
    RadioTech tech = ConvertTechFromRil(static_cast<HRilRadioTech>(csRegStateResult->radioTechnology));
    networkSearchState_->SetNetworkType(tech, DomainType::DOMAIN_TYPE_CS);
    RoamingType roam = RoamingType::ROAMING_STATE_UNKNOWN;
    if (registrationStatus == RilRegister::REG_STATE_ROAMING) {
        roam = RoamingType::ROAMING_STATE_UNSPEC;
    }
    networkSearchState_->SetNetworkStateToRoaming(roam, DomainType::DOMAIN_TYPE_CS);
    TELEPHONY_LOGI("ProcessCsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d",
        registrationStatus, csRegStateResult->radioTechnology, roam);
    networkSearchManager->UpdateCellLocation(
        static_cast<int32_t>(tech), csRegStateResult->cellId, csRegStateResult->lacCode);
    networkSearchState_->CsRadioTechChange();
    if (networkSearchManager->CheckIsNeedNotify() || regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY) {
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
    networkSearchState_->SetEmergency(regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY);
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
    
    TELEPHONY_LOGI("ProcessPsRegister: regStatus= %{public}d radioTechnology=%{public}d roam=%{public}d",
        registrationStatus, psRegStatusResult->radioTechnology, roam);
    if (networkSearchManager->CheckIsNeedNotify() || regStatus == RegServiceState::REG_STATE_EMERGENCY_ONLY) {
        networkSearchState_->NotifyStateChange();
    }
}

void NetworkRegister::ProcessChannelConfigInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<ChannelConfigInfoList> channelConfigInfoList = event->GetSharedObject<ChannelConfigInfoList>();
    if (channelConfigInfoList == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo psRegStatusResult is nullptr\n");
        return;
    }
    int32_t size = channelConfigInfoList->itemNum;
    TELEPHONY_LOGI("NetworkRegister::ProcessChannelConfigInfo num size:%{public}d", size);
    if (channelConfigInfoList->channelConfigInfos.size() > 0 &&
        static_cast<int32_t>(channelConfigInfoList->channelConfigInfos.size()) == size) {
        std::vector<PhysicalChannelConfig> &configs = channelConfigInfoList->channelConfigInfos;
        channelConfigInfos_.clear();
        channelConfigInfos_.insert(channelConfigInfos_.begin(), configs.begin(), configs.end());
    } else {
        TELEPHONY_LOGE("NetworkRegister::ProcessChannelConfigInfo data error\n");
        return;
    }

    bool isNrSecondaryCell = false;
    for (int i = 0; i < size; ++i) {
        if (!isNrSecondaryCell &&
            (static_cast<RadioTech>(channelConfigInfos_[0].ratType) == RadioTech::RADIO_TECHNOLOGY_NR &&
            static_cast<ConnectServiceCell>(channelConfigInfos_[0].cellConnStatus) ==
            ConnectServiceCell::CONNECTION_SECONDARY_CELL)) {
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
    int32_t size = channelConfigInfos_.size();
    for (int i = 0; i < size; ++i) {
        std::vector<int32_t> &cids = channelConfigInfos_[i].contextIds;
        if (!isFreqChanged) {
            for (auto &cid : cids) {
                if (networkSearchManager->GetCellularDataCallBack()->HasInternetCapability(0, cid)) {
                    curFreqType = static_cast<FrequencyType>(channelConfigInfos_[i].freqRange);
                    isFreqChanged = true;
                    break;
                }
            }
        }
    }

    if (freqType_ != curFreqType) {
        freqType_ = curFreqType;
        networkSearchManager->NotifyNrFrequencyChanged();
        networkSearchManager->SetFrequencyType(freqType_);
    }
}

void NetworkRegister::DcPhysicalLinkActiveUpdate(bool isActive)
{
    TELEPHONY_LOGI("NetworkRegister::DcPhysicalLinkActiveUpdate isActive:%{public}s", isActive ? "true" : "false");
    isPhysicalLinkActive_ = isActive;
    UpdateNrState();
    UpdateCfgTech();
}

void NetworkRegister::UpdateNrState()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr || networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkRegister::UpdateNrState error");
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

    if (endcSupport_ &&
        (rat == RadioTech::RADIO_TECHNOLOGY_LTE || rat == RadioTech::RADIO_TECHNOLOGY_LTE_CA)) {
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
        if (isNrSecondaryCell_  || (!dcNrRestricted_ && nrSupport_ && isPhysicalLinkActive_)) {
            if (rat == RadioTech::RADIO_TECHNOLOGY_LTE) {
                nrState_ = NrState::NR_NSA_STATE_CONNECTED_DETECT;
            }
            if (rat == RadioTech::RADIO_TECHNOLOGY_LTE_CA) {
                nrState_ = NrState::NR_NSA_STATE_DUAL_CONNECTED;
            }
        }
    }

    networkSearchManager->SetNrOptionMode(nrMode);
    networkSearchState_->SetNrState(nrState_);
}

void NetworkRegister::UpdateCfgTech()
{
    if (nrConfigMap_.find(nrState_) == nrConfigMap_.end()) {
        TELEPHONY_LOGE("NetworkRegister::UpdateCfgTech not find nr state");
        return;
    }
    RadioTech cfgTech = nrConfigMap_[nrState_];
    if (cfgTech != RadioTech::RADIO_TECHNOLOGY_NR) {
        cfgTech = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();
    }
    networkSearchState_->SetCfgTech(cfgTech);
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

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = nsm->FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        int32_t psAttachStatus = callbackInfo->param_;
        TELEPHONY_LOGI("NetworkRegister::ProcessPsAttachStatus psAttachStatus is:%{public}d", psAttachStatus);
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::SET_PS_ATTACH_STATUS_RESULT, data);
            TELEPHONY_LOGI("NetworkRegister::ProcessPsAttachStatus callback success");
        }
        nsm->RemoveCallbackFromMap(index);
    }
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
     * "STATE_NOT_SUPPORT:4g,STATE_NO_DETECT:4g,STATE_CONNECTED_DETECT:4g,"
            "STATE_IDLE_DETECT:4g,STATE_DUAL_CONNECTED:5g,STATE_SA_ATTACHED:5g";
    */
    std::string strSep = ",";
    std::vector<std::string> strsRet;
    SplitStr(cfgStr, strSep, strsRet);
    if (static_cast<int>(strsRet.size()) != NR_STATE_NUM) {
        TELEPHONY_LOGE("NetworkRegister::NrConfigParse string error");
        return;
    }

    std::string strNrFlag = "";
    std::vector<std::string> nrStateKv;
    for (auto & state : strsRet) {
        strSep = ":";
        SplitStr(state, strSep, nrStateKv);
        if (static_cast<int>(nrStateKv.size()) != KEY_VALUE_NUM) {
            TELEPHONY_LOGE("NetworkRegister::NrConfigParse key value string error");
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

NrState NetworkRegister::ConvertStringToNrState(std::string& strState) const
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

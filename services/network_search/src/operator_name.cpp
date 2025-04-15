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

#include "operator_name.h"

#include <common_event.h>
#include <common_event_manager.h>

#include "common_event_support.h"
#include "core_manager_inner.h"
#include "tel_ril_network_parcel.h"
#include "network_search_manager.h"
#include "operator_config_types.h"
#include "operator_name_utils.h"
#include "resource_utils.h"
#include "telephony_common_utils.h"
#include "telephony_log_wrapper.h"
#include "telephony_ext_wrapper.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
namespace {
const int32_t FORMAT_IDX_SPN_CS = 0;
const int32_t PNN_CUST_STRING_SIZE = 2;
const int32_t OPL_CUST_STRING_SIZE = 4;
constexpr const char *CFG_DISPLAY_RULE_USE_ROAMING_FROM_NETWORK_STATE_BOOL =
    "persist.radio.cfg.display_rule_use_roaming_from_network_state";
} // namespace

OperatorName::OperatorName(const EventFwk::CommonEventSubscribeInfo &sp,
    std::shared_ptr<NetworkSearchState> networkSearchState, std::shared_ptr<ISimManager> simManager,
    std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : CommonEventSubscriber(sp), networkSearchState_(networkSearchState), simManager_(simManager),
      networkSearchManager_(networkSearchManager), slotId_(slotId)
{
    std::vector<std::string> vecSpnFormats;
    ResourceUtils::Get().GetStringArrayValueByName(ResourceUtils::SPN_FORMATS, vecSpnFormats);
    if (vecSpnFormats.size() > FORMAT_IDX_SPN_CS) {
        csSpnFormat_ = vecSpnFormats[FORMAT_IDX_SPN_CS];
    }
    UpdateOperatorConfig();
}

void OperatorName::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want &want = data.GetWant();
    std::string action = want.GetAction();
    if (action == CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED) {
        int32_t slotId = want.GetIntParam("slotId", 0);
        if (slotId_ != slotId) {
            return;
        }
        UpdateOperatorConfig();
        sptr<NetworkState> networkState = GetNetworkStatus();
        if (networkState != nullptr && networkState->GetRegStatus() == RegServiceState::REG_STATE_IN_SERVICE) {
            NotifySpnChanged();
            networkSearchState_->NotifyStateChange();
        }
    } else if (action == CommonEventSupport::COMMON_EVENT_LOCALE_CHANGED) {
        TELEPHONY_LOGI("locale changed Slot%{public}d", slotId_);
        TrySetLongOperatorNameWithTranslation();
        auto networkSearchManager = networkSearchManager_.lock();
        if (networkSearchManager == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is nullptr slotId:%{public}d", slotId_);
            return;
        }
        if (networkSearchManager->CheckIsNeedNotify(slotId_)) {
            networkSearchManager->ProcessNotifyStateChangeEvent(slotId_);
        }
    } else {
        TELEPHONY_LOGI("OperatorName::OnReceiveEvent Slot%{public}d: action=%{public}s code=%{public}d", slotId_,
            action.c_str(), data.GetCode());
    }
}

void OperatorName::HandleOperatorInfo(const std::shared_ptr<OperatorInfoResult> operatorInfoResult)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("OperatorName::HandleOperatorInfo networkSearchManager is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (operatorInfoResult == nullptr) {
        TELEPHONY_LOGE("operatorInfoResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    PhoneType type = networkSearchManager->GetPhoneType(slotId_);
    if (type == PhoneType::PHONE_TYPE_IS_GSM) {
        GsmOperatorInfo(operatorInfoResult);
    } else if (type == PhoneType::PHONE_TYPE_IS_CDMA) {
        CdmaOperatorInfo(operatorInfoResult);
    } else {
        TELEPHONY_LOGE("OperatorName::HandleOperatorInfo phone type:%{public}d invalid", type);
    }
    NotifySpnChanged();
    networkSearchManager->TriggerTimezoneRefresh(slotId_);
}

void OperatorName::GsmOperatorInfo(const std::shared_ptr<OperatorInfoResult> operatorInfoResult)
{
    std::string longName = "";
    std::string shortName = "";
    std::string numeric = "";
    if (operatorInfoResult != nullptr) {
        longName = operatorInfoResult->longName;
        longName_ = operatorInfoResult->longName;
        shortName = operatorInfoResult->shortName;
        numeric = operatorInfoResult->numeric;
        UpdateOperatorLongName(longName, numeric);
    }
    TELEPHONY_LOGI(
        "OperatorName::GsmOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : %{public}s "
        "slotId:%{public}d",
        longName.c_str(), shortName.c_str(), numeric.c_str(), slotId_);
    if (networkSearchState_ != nullptr) {
        networkSearchState_->SetOperatorInfo(longName, shortName, numeric, DomainType::DOMAIN_TYPE_CS);
        networkSearchState_->SetOperatorInfo(longName, shortName, numeric, DomainType::DOMAIN_TYPE_PS);
    }
}

void OperatorName::CdmaOperatorInfo(const std::shared_ptr<OperatorInfoResult> operatorInfoResult)
{
    std::string longName = "";
    std::string shortName = "";
    std::string numeric = "";
    if (operatorInfoResult != nullptr) {
        longName = operatorInfoResult->longName;
        longName_ = operatorInfoResult->longName;
        shortName = operatorInfoResult->shortName;
        numeric = operatorInfoResult->numeric;
        UpdateOperatorLongName(longName, numeric);
    }
    TELEPHONY_LOGI(
        "OperatorName::CdmaOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : %{public}s "
        "slotId:%{public}d",
        longName.c_str(), shortName.c_str(), numeric.c_str(), slotId_);
    if (networkSearchState_ != nullptr) {
        networkSearchState_->SetOperatorInfo(longName, shortName, numeric, DomainType::DOMAIN_TYPE_CS);
        networkSearchState_->SetOperatorInfo(longName, shortName, numeric, DomainType::DOMAIN_TYPE_PS);
    }
}

sptr<NetworkState> OperatorName::GetNetworkStatus()
{
    sptr<NetworkState> networkStatus = nullptr;
    if (networkSearchState_ != nullptr) {
        std::unique_ptr<NetworkState> networkState = networkSearchState_->GetNetworkStatus();
        if (networkState != nullptr) {
            networkStatus = networkState.release();
            return networkStatus;
        }
    }
    TELEPHONY_LOGE("OperatorName::GetNetworkStatus networkState is nullptr slotId:%{public}d", slotId_);
    return networkStatus;
}

/**
 * 3GPP TS 51.011 V5.0.0(2001-12) 10.3.11
 */
void OperatorName::NotifySpnChanged(bool isForce)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("OperatorName::NotifySpnChanged networkSearchManager is nullptr slotId:%{public}d", slotId_);
        return;
    }
    TELEPHONY_LOGD("OperatorName::NotifySpnChanged slotId:%{public}d", slotId_);
    std::string netPlmn = "";
    std::string simPlmn = "";
    std::string domesticSpn = "";
    RegServiceState regStatus = RegServiceState::REG_STATE_UNKNOWN;
    sptr<NetworkState> networkState = GetNetworkStatus();
    if (networkState != nullptr) {
        regStatus = networkState->GetRegStatus();
        netPlmn = networkState->GetPlmnNumeric();
    }
    if (simManager_ != nullptr) {
        std::u16string operatorNumeric = u"";
        simManager_->GetSimOperatorNumeric(slotId_, operatorNumeric);
        simPlmn = Str16ToStr8(operatorNumeric);
    }
    if (isDomesticRoaming(simPlmn, netPlmn)) {
        domesticSpn = GetCustomName(simPlmn);
    }

    if (networkSearchManager->GetPhoneType(slotId_) == PhoneType::PHONE_TYPE_IS_GSM) {
        NotifyGsmSpnChanged(regStatus, networkState, domesticSpn, isForce);
    } else if (networkSearchManager->GetPhoneType(slotId_) == PhoneType::PHONE_TYPE_IS_CDMA) {
        NotifyCdmaSpnChanged(regStatus, networkState, domesticSpn, isForce);
    }
}

void OperatorName::UpdatePlmn(RegServiceState regStatus, sptr<NetworkState> &networkState, OperatorNameParams &params)
{
    if (networkState != nullptr) {
        switch (regStatus) {
            case RegServiceState::REG_STATE_IN_SERVICE:
                params.plmn = GetPlmn(networkState, true);
                params.showPlmn = !params.plmn.empty() &&
                    ((static_cast<uint32_t>(params.spnRule) & SpnShowType::SPN_CONDITION_DISPLAY_PLMN) ==
                    SpnShowType::SPN_CONDITION_DISPLAY_PLMN);
                break;
            case RegServiceState::REG_STATE_NO_SERVICE:
            case RegServiceState::REG_STATE_EMERGENCY_ONLY:
            case RegServiceState::REG_STATE_SEARCH:
                if (networkState->IsEmergency()) {
                    ResourceUtils::Get().GetStringValueByName(ResourceUtils::EMERGENCY_CALLS_ONLY, params.plmn);
                } else {
                    ResourceUtils::Get().GetStringValueByName(ResourceUtils::OUT_OF_SERIVCE, params.plmn);
                }
                params.showPlmn = true;
                break;
            case RegServiceState::REG_STATE_UNKNOWN:
            case RegServiceState::REG_STATE_POWER_OFF:
            default:
                ResourceUtils::Get().GetStringValueByName(ResourceUtils::OUT_OF_SERIVCE, params.plmn);
                params.showPlmn = true;
                break;
        }
    }
}

void OperatorName::UpdateSpn(RegServiceState regStatus, sptr<NetworkState> &networkState, OperatorNameParams &params)
{
    if (regStatus == RegServiceState::REG_STATE_IN_SERVICE) {
        if (enableCust_ && !spnCust_.empty()) {
            params.spn = spnCust_;
        }
        if (params.spn.empty()) {
            std::u16string result = Str8ToStr16("");
            if (simManager_ != nullptr) {
                simManager_->GetSimSpn(slotId_, result);
            }
            params.spn = Str16ToStr8(result);
        }
        if (!csSpnFormat_.empty()) {
            params.spn = NetworkUtils::FormatString(csSpnFormat_, params.spn.c_str());
        }
        params.showSpn = !params.spn.empty() &&
            ((static_cast<uint32_t>(params.spnRule) & SpnShowType::SPN_CONDITION_DISPLAY_SPN) ==
            SpnShowType::SPN_CONDITION_DISPLAY_SPN);
    } else {
        params.spn = "";
        params.showSpn = false;
    }
}

void OperatorName::NotifyGsmSpnChanged(
    RegServiceState regStatus, sptr<NetworkState> &networkState, const std::string &domesticSpn, bool isForce)
{
    if (networkState == nullptr) {
        TELEPHONY_LOGE("OperatorName::NotifyGsmSpnChanged networkState is nullptr slotId:%{public}d", slotId_);
        return;
    }

    OperatorNameParams params = {false, "", false, "", 0};
    params.spnRule = static_cast<int32_t>(GetSpnRule(networkState));
    if (slotId_ == static_cast<int32_t>(SimSlotType::VSIM_SLOT_ID)) {
        UpdateVSimSpn(params);
    }
    UpdatePlmn(regStatus, networkState, params);
    UpdateSpn(regStatus, networkState, params);

    if (TELEPHONY_EXT_WRAPPER.updateOperatorNameParamsExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.updateOperatorNameParamsExt_(slotId_, networkState, params);
    }

    bool showPlmnOld = params.showPlmn;
    if (params.spn.empty() && !params.plmn.empty()) {
        params.showPlmn = true;
    }
    if (params.showPlmn && params.spn == params.plmn) {
        params.showSpn = false;
    }
    SetOperatorNameByParams(params);
    TELEPHONY_LOGI(
        "OperatorName::NotifyGsmSpnChanged showSpn:%{public}d curSpn_:%{public}s spn:%{public}s showPlmn:%{public}d "
        "curPlmn_:%{public}s plmn:%{public}s showPlmnOld:%{public}d enableCust_:%{public}d "
        "displayConditionCust_:%{public}d domesticSpn:%{public}s slotId:%{public}d",
        params.showSpn, curParams_.spn.c_str(), params.spn.c_str(), params.showPlmn, curParams_.plmn.c_str(),
        params.plmn.c_str(), showPlmnOld, enableCust_, displayConditionCust_, domesticSpn.c_str(), slotId_);
    if (isForce || curParams_.spnRule != params.spnRule || curRegState_ != regStatus ||
        curParams_.showSpn != params.showSpn || curParams_.showPlmn != params.showPlmn ||
        curParams_.spn.compare(params.spn) || curParams_.plmn.compare(params.plmn)) {
        TELEPHONY_LOGI("OperatorName::NotifyGsmSpnChanged start send broadcast slotId:%{public}d...", slotId_);
        bool isSatelliteOn = CoreManagerInner::GetInstance().IsSatelliteEnabled();
        if (isSatelliteOn && !domesticSpn.empty()) {
            params.plmn = domesticSpn;
            std::string emptyDomesticSpn = "";
            PublishEvent(params, regStatus, emptyDomesticSpn);
        } else {
            PublishEvent(params, regStatus, domesticSpn);
        }
    } else {
        TELEPHONY_LOGD(
            "OperatorName::NotifyGsmSpnChanged spn no changed, not need to update slotId:%{public}d", slotId_);
    }
}

void OperatorName::UpdateVSimSpn(OperatorNameParams &params)
{
    if (TELEPHONY_EXT_WRAPPER.getVSimSlotId_ && TELEPHONY_EXT_WRAPPER.changeSpnAndRuleExt_) {
        int vSimSlotId = static_cast<int>(SimSlotType::INVALID_SLOT_ID);
        TELEPHONY_EXT_WRAPPER.getVSimSlotId_(vSimSlotId);
        if (vSimSlotId == static_cast<int>(SimSlotType::VSIM_SLOT_ID)) {
            TELEPHONY_EXT_WRAPPER.changeSpnAndRuleExt_(params.spn, params.spnRule, params.showSpn);
        }
    }
}

void OperatorName::NotifyCdmaSpnChanged(
    RegServiceState regStatus, sptr<NetworkState> &networkState, const std::string &domesticSpn, bool isForce)
{
    if (networkState == nullptr) {
        TELEPHONY_LOGE("OperatorName::NotifyCdmaSpnChanged networkState is nullptr slotId:%{public}d", slotId_);
        return;
    }

    OperatorNameParams params = {false, "", false, "", 0};
    std::string numeric = networkState->GetPlmnNumeric();
    if (regStatus == RegServiceState::REG_STATE_IN_SERVICE) {
        params.plmn = GetCustomName(numeric);
        if (params.plmn.empty()) {
            params.plmn = networkState->GetLongOperatorName();
        }
        if (!csSpnFormat_.empty()) {
            params.plmn = NetworkUtils::FormatString(csSpnFormat_, params.plmn.c_str());
        }
    } else if (regStatus != RegServiceState::REG_STATE_POWER_OFF) {
        ResourceUtils::Get().GetStringValueByName(ResourceUtils::OUT_OF_SERIVCE, params.plmn);
    }
    params.showPlmn = !params.plmn.empty();
    SetOperatorNameByParams(params);
    TELEPHONY_LOGI(
        "OperatorName::NotifyCdmaSpnChanged showSpn:%{public}d curSpn_:%{public}s spn:%{public}s "
        "showPlmn:%{public}d curPlmn_:%{public}s plmn:%{public}s slotId:%{public}d",
        params.showSpn, curParams_.spn.c_str(), params.spn.c_str(), params.showPlmn, curParams_.plmn.c_str(),
        params.plmn.c_str(), slotId_);
    if (isForce || curParams_.spnRule != params.spnRule || curRegState_ != regStatus ||
        curParams_.showSpn != params.showSpn || curParams_.showPlmn != params.showPlmn ||
        curParams_.spn.compare(params.spn) || curParams_.plmn.compare(params.plmn)) {
        TELEPHONY_LOGI("OperatorName::NotifyCdmaSpnChanged start send broadcast slotId:%{public}d...", slotId_);
        PublishEvent(params, regStatus, domesticSpn);
    } else {
        TELEPHONY_LOGI(
            "OperatorName::NotifyCdmaSpnChanged spn no changed, not need to update slotId:%{public}d", slotId_);
    }
}

void OperatorName::SetOperatorNameByParams(OperatorNameParams &params)
{
    std::string showName;
    if (params.showPlmn) {
        showName = params.plmn;
    } else if (params.showSpn) {
        showName = params.spn;
    }
    if (!showName.empty()) {
        SetOperatorName(showName);
    }
}

void OperatorName::SetOperatorName(const std::string &operatorName)
{
    if (networkSearchState_ != nullptr) {
        networkSearchState_->SetLongOperatorName(operatorName, DomainType::DOMAIN_TYPE_CS);
        networkSearchState_->SetLongOperatorName(operatorName, DomainType::DOMAIN_TYPE_PS);
    }
}
void OperatorName::PublishEvent(OperatorNameParams params, const RegServiceState state, const std::string &domesticSpn)
{
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SPN_INFO_CHANGED);
    want.SetParam(CUR_SLOT_ID, slotId_);
    want.SetParam(CUR_PLMN_SHOW, params.showPlmn);
    want.SetParam(CUR_PLMN, params.plmn);
    want.SetParam(CUR_SPN_SHOW, params.showSpn);
    want.SetParam(CUR_SPN, params.spn);
    want.SetParam(DOMESTIC_SPN, domesticSpn);
    CommonEventData data;
    data.SetWant(want);

    CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    if (TELEPHONY_EXT_WRAPPER.publishSpnInfoChangedExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.publishSpnInfoChangedExt_(want);
    }
    TELEPHONY_LOGI("OperatorName::PublishEvent result : %{public}d slotId:%{public}d", publishResult, slotId_);
    if (publishResult) {
        curRegState_ = state;
        curParams_.spnRule = params.spnRule;
        curParams_.spn = params.spn;
        curParams_.showSpn = params.showSpn;
        curParams_.plmn = params.plmn;
        curParams_.showPlmn = params.showPlmn;
    }
}

std::string OperatorName::GetPlmn(const sptr<NetworkState> &networkState, bool longNameRequired)
{
    if (networkState == nullptr) {
        TELEPHONY_LOGE("OperatorName::GetPlmn networkState is nullptr slotId:%{public}d", slotId_);
        return "";
    }
    std::string plmn = "";
    std::string numeric = networkState->GetPlmnNumeric();
    bool roaming = networkState->IsRoaming();
    int32_t lac = GetCurrentLac();
    plmn = GetCustomName(numeric);
    if (plmn.empty()) {
        plmn = GetCustEons(numeric, lac, roaming, longNameRequired);
    }
    if (plmn.empty()) {
        plmn = GetEons(numeric, lac, longNameRequired);
    }
    if (plmn.empty()) {
        plmn = networkState->GetLongOperatorName();
    }
    std::string operatorLongName = longName_;
    if (TELEPHONY_EXT_WRAPPER.processOperatorName_ != nullptr) {
        netPriCust_ = TELEPHONY_EXT_WRAPPER.processOperatorName_(slotId_, operatorLongName, numeric);
        TELEPHONY_LOGI("OperatorName::GetPlmn netPriCust_:%{public}d", netPriCust_);
    }
    if (netPriCust_) {
        plmn = operatorLongName;
    }
    TELEPHONY_LOGD(
        "OperatorName::GetPlmn lac:%{public}d, numeric:%{public}s, longNameRequired:%{public}d, plmn:%{public}s", lac,
        numeric.c_str(), longNameRequired, plmn.c_str());
    return plmn;
}

std::string OperatorName::GetEons(const std::string &numeric, int32_t lac, bool longNameRequired)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("OperatorName::GetEons simManager_ is nullptr slotId:%{public}d", slotId_);
        return "";
    }
    return Str16ToStr8(simManager_->GetSimEons(slotId_, numeric, lac, longNameRequired));
}

bool OperatorName::GetRoamStateBySimFile(const std::string &netPlmn)
{
    if (netPlmn.empty() || simManager_ == nullptr) {
        return false;
    }
    std::u16string operatorNumeric = u"";
    int32_t errorCode = simManager_->GetSimOperatorNumeric(slotId_, operatorNumeric);
    if (errorCode != 0 || operatorNumeric.empty()) {
        return false;
    }
    std::string simPlmn = Str16ToStr8(operatorNumeric);
    if (simPlmn == netPlmn) {
        return false;
    }
    std::set<std::string> ehPlmns;
    simManager_->GetEhPlmns(slotId_, ehPlmns);
    auto it = ehPlmns.find(netPlmn);
    if (it != ehPlmns.end()) {
        return false;
    }
    std::set<std::string> spdiPlmns;
    simManager_->GetSpdiPlmns(slotId_, spdiPlmns);
    it = spdiPlmns.find(netPlmn);
    if (it != spdiPlmns.end()) {
        return false;
    }
    return true;
}

unsigned int OperatorName::GetSpnRule(sptr<NetworkState> &networkState)
{
    int32_t spnRule = 0;
    bool roaming = false;
    bool useRoamingFromNetworkState =
        system::GetBoolParameter(CFG_DISPLAY_RULE_USE_ROAMING_FROM_NETWORK_STATE_BOOL, false);
    if (useRoamingFromNetworkState) {
        roaming = networkState->IsRoaming();
    } else {
        std::string netPlmn = networkState->GetPlmnNumeric();
        roaming = GetRoamStateBySimFile(netPlmn);
    }
    if (enableCust_ && displayConditionCust_ != SPN_INVALID) {
        spnRule = static_cast<int32_t>(GetCustSpnRule(roaming));
    } else if (!roaming && IsChinaCard()) {
        spnRule = SPN_CONDITION_DISPLAY_PLMN;
    } else {
        std::string numeric = networkState->GetPlmnNumeric();
        if (simManager_ != nullptr) {
            spnRule = simManager_->ObtainSpnCondition(slotId_, roaming, numeric);
        }
    }
    return spnRule;
}

unsigned int OperatorName::GetCustSpnRule(bool roaming)
{
    unsigned int cond = 0;
    if (displayConditionCust_ <= SPN_INVALID) {
        return cond;
    }
    if (roaming) {
        cond = SPN_CONDITION_DISPLAY_PLMN;
        if ((static_cast<unsigned int>(displayConditionCust_) & static_cast<unsigned int>(SPN_COND)) == 0) {
            cond |= static_cast<unsigned int>(SPN_CONDITION_DISPLAY_SPN);
        }
    } else {
        cond = SPN_CONDITION_DISPLAY_SPN;
        if ((static_cast<unsigned int>(displayConditionCust_) & static_cast<unsigned int>(SPN_COND_PLMN)) ==
            SPN_COND_PLMN) {
            cond |= static_cast<unsigned int>(SPN_CONDITION_DISPLAY_PLMN);
        }
    }
    return cond;
}

std::string OperatorName::GetCustEons(const std::string &numeric, int32_t lac, bool roaming, bool longNameRequired)
{
    if (!enableCust_ || numeric.empty() || pnnCust_.empty() || (oplCust_.empty() && roaming)) {
        TELEPHONY_LOGI("OperatorName::GetCustEons is empty");
        return "";
    }
    int32_t pnnIndex = 1;
    for (std::shared_ptr<OperatorPlmnInfo> opl : oplCust_) {
        if (opl == nullptr) {
            continue;
        }
        pnnIndex = -1;
        TELEPHONY_LOGI(
            "OperatorName::GetCustEons numeric:%{public}s, opl->plmnNumeric:%{public}s, lac:%{public}d, "
            "opl->lacStart:%{public}d, opl->lacEnd:%{public}d, opl->pnnRecordId:%{public}d",
            numeric.c_str(), opl->plmnNumeric.c_str(), lac, opl->lacStart, opl->lacEnd, opl->pnnRecordId);
        if (numeric.compare(opl->plmnNumeric) == 0 &&
            ((opl->lacStart == 0 && opl->lacEnd == 0xfffe) || (opl->lacStart <= lac && opl->lacEnd >= lac))) {
            pnnIndex = opl->pnnRecordId;
            break;
        }
    }
    TELEPHONY_LOGI("OperatorName::GetCustEons pnnIndex:%{public}d", pnnIndex);
    std::string custEonsName = "";
    if (pnnIndex >= 1 && pnnIndex <= (int32_t)pnnCust_.size()) {
        TELEPHONY_LOGI(
            "OperatorName::GetCustEons longNameRequired:%{public}d, longName:%{public}s, shortName:%{public}s,",
            longNameRequired, pnnCust_.at(pnnIndex - 1)->longName.c_str(),
            pnnCust_.at(pnnIndex - 1)->shortName.c_str());
        if (longNameRequired) {
            custEonsName = pnnCust_.at(pnnIndex - 1)->longName;
        } else {
            custEonsName = pnnCust_.at(pnnIndex - 1)->shortName;
        }
    }
    return custEonsName;
}

std::string OperatorName::GetCustomName(const std::string &numeric)
{
    return OperatorNameUtils::GetInstance().GetCustomName(numeric);
}

bool OperatorName::isDomesticRoaming(const std::string &simPlmn, const std::string &netPlmn)
{
    if (isCMCard(simPlmn) && isCMDomestic(netPlmn)) {
        return true;
    }
    if (isCUCard(simPlmn) && isCUDomestic(netPlmn)) {
        return true;
    }
    if (isCTCard(simPlmn) && isCTDomestic(netPlmn)) {
        return true;
    }
    if (isCBCard(simPlmn) && isCBDomestic(netPlmn)) {
        return true;
    }
    TELEPHONY_LOGD("simPlmn not match netPlmn");
    return false;
}

bool OperatorName::isCMCard(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(cmMccMnc_.begin(), cmMccMnc_.end(), numeric);
    if (obj != cmMccMnc_.end()) {
        TELEPHONY_LOGD("is CM card");
        return true;
    }
    return false;
}

bool OperatorName::isCUCard(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(cuMccMnc_.begin(), cuMccMnc_.end(), numeric);
    if (obj != cuMccMnc_.end()) {
        TELEPHONY_LOGD("is CU card");
        return true;
    }
    return false;
}

bool OperatorName::isCTCard(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(ctMccMnc_.begin(), ctMccMnc_.end(), numeric);
    if (obj != ctMccMnc_.end()) {
        TELEPHONY_LOGD("is CT card");
        return true;
    }
    return false;
}

bool OperatorName::isCBCard(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(cbnMccMnc_.begin(), cbnMccMnc_.end(), numeric);
    if (obj != cbnMccMnc_.end()) {
        TELEPHONY_LOGD("is CB card");
        return true;
    }
    return false;
}

bool OperatorName::isCMDomestic(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(cmDomesticMccMnc_.begin(), cmDomesticMccMnc_.end(), numeric);
    if (obj != cmDomesticMccMnc_.end()) {
        TELEPHONY_LOGD("is CM domestic");
        return true;
    }
    return false;
}

bool OperatorName::isCUDomestic(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(cuDomesticMccMnc_.begin(), cuDomesticMccMnc_.end(), numeric);
    if (obj != cuDomesticMccMnc_.end()) {
        TELEPHONY_LOGD("is CU domestic");
        return true;
    }
    return false;
}

bool OperatorName::isCTDomestic(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(ctDomesticMccMnc_.begin(), ctDomesticMccMnc_.end(), numeric);
    if (obj != ctDomesticMccMnc_.end()) {
        TELEPHONY_LOGD("is CT domestic");
        return true;
    }
    return false;
}

bool OperatorName::isCBDomestic(const std::string &numeric)
{
    if (numeric.empty()) {
        return false;
    }
    auto obj = std::find(cbDomesticnMccMnc_.begin(), cbDomesticnMccMnc_.end(), numeric);
    if (obj != cbDomesticnMccMnc_.end()) {
        TELEPHONY_LOGD("is CB domestic");
        return true;
    }
    return false;
}

bool OperatorName::IsChinaCard()
{
    std::string simPlmn = "";
    if (simManager_ != nullptr) {
        std::u16string operatorNumeric = u"";
        simManager_->GetSimOperatorNumeric(slotId_, operatorNumeric);
        simPlmn = Str16ToStr8(operatorNumeric);
    }
    return isCMCard(simPlmn) || isCUCard(simPlmn) || isCTCard(simPlmn) || isCBCard(simPlmn);
}

int32_t OperatorName::GetCurrentLac()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("OperatorName::GetCurrentLac networkSearchManager is nullptr slotId:%{public}d", slotId_);
        return 0;
    }
    sptr<CellLocation> location = networkSearchManager->GetCellLocation(slotId_);
    if (location == nullptr) {
        TELEPHONY_LOGE("OperatorName::GetCurrentLac location is nullptr slotId:%{public}d", slotId_);
        return 0;
    }
    if (location->GetCellLocationType() != CellLocation::CellType::CELL_TYPE_GSM) {
        TELEPHONY_LOGE("OperatorName::GetCurrentLac location type isn't GSM slotId:%{public}d", slotId_);
        return 0;
    }
    sptr<GsmCellLocation> gsmLocation = sptr<GsmCellLocation>(static_cast<GsmCellLocation *>(location.GetRefPtr()));
    if (gsmLocation == nullptr) {
        TELEPHONY_LOGE("OperatorName::GetCurrentLac gsmLocation is nullptr slotId:%{public}d", slotId_);
        return 0;
    }
    return gsmLocation->GetLac();
}

void OperatorName::UpdateOperatorConfig()
{
    OperatorConfig operatorConfig;
    CoreManagerInner::GetInstance().GetOperatorConfigs(slotId_, operatorConfig);
    if (operatorConfig.boolValue.find(KEY_ENABLE_OPERATOR_NAME_CUST_BOOL) != operatorConfig.boolValue.end()) {
        enableCust_ = operatorConfig.boolValue[KEY_ENABLE_OPERATOR_NAME_CUST_BOOL];
    }
    if (operatorConfig.stringValue.find(KEY_OPERATOR_NAME_CUST_STRING) != operatorConfig.stringValue.end()) {
        spnCust_ = operatorConfig.stringValue[KEY_OPERATOR_NAME_CUST_STRING];
    }
    if (operatorConfig.intValue.find(KEY_SPN_DISPLAY_CONDITION_CUST_INT) != operatorConfig.intValue.end()) {
        displayConditionCust_ = operatorConfig.intValue[KEY_SPN_DISPLAY_CONDITION_CUST_INT];
    }
    if (operatorConfig.stringArrayValue.find(KEY_PNN_CUST_STRING_ARRAY) != operatorConfig.stringArrayValue.end()) {
        UpdatePnnCust(operatorConfig.stringArrayValue[KEY_PNN_CUST_STRING_ARRAY]);
    }
    if (operatorConfig.stringArrayValue.find(KEY_OPL_CUST_STRING_ARRAY) != operatorConfig.stringArrayValue.end()) {
        UpdateOplCust(operatorConfig.stringArrayValue[KEY_OPL_CUST_STRING_ARRAY]);
    }
}

void OperatorName::UpdatePnnCust(const std::vector<std::string> &pnnCust)
{
    pnnCust_.clear();
    if (pnnCust.empty()) {
        TELEPHONY_LOGE("OperatorName::UpdatePnnCust pnnCust is empty slotId:%{public}d", slotId_);
        return;
    }
    for (const auto &data : pnnCust) {
        TELEPHONY_LOGI("OperatorName::UpdatePnnCust: %{public}s", data.c_str());
        std::vector<std::string> pnnString = NetworkUtils::SplitString(data, ",");
        if (pnnString.size() != PNN_CUST_STRING_SIZE) {
            continue;
        }
        std::shared_ptr<PlmnNetworkName> pnn = std::make_shared<PlmnNetworkName>();
        pnn->shortName = pnnString.back();
        pnnString.pop_back();
        pnn->longName = pnnString.back();
        if (!pnn->longName.empty() || !pnn->shortName.empty()) {
            pnnCust_.push_back(pnn);
        }
    }
}

void OperatorName::UpdateOplCust(const std::vector<std::string> &oplCust)
{
    oplCust_.clear();
    if (oplCust.empty()) {
        TELEPHONY_LOGE("OperatorName::UpdateOplCust oplCust is empty slotId:%{public}d", slotId_);
        return;
    }
    for (const auto &data : oplCust) {
        TELEPHONY_LOGI("OperatorName::UpdateOplCust: %{public}s", data.c_str());
        std::vector<std::string> oplString = NetworkUtils::SplitString(data, ",");
        if (oplString.size() != OPL_CUST_STRING_SIZE || oplString.back().empty()) {
            continue;
        }
        std::shared_ptr<OperatorPlmnInfo> opl = std::make_shared<OperatorPlmnInfo>();
        uint8_t base = 16; // convert to hexadecimal
        bool isSuccess = ConvertStrToInt(oplString.back(), opl->pnnRecordId, base);
        oplString.pop_back();
        if (!isSuccess || oplString.back().empty()) {
            continue;
        }
        isSuccess = ConvertStrToInt(oplString.back(), opl->lacEnd, base);
        oplString.pop_back();
        if (!isSuccess || oplString.back().empty()) {
            continue;
        }
        isSuccess = ConvertStrToInt(oplString.back(), opl->lacStart, base);
        oplString.pop_back();
        opl->plmnNumeric = oplString.back();
        if (isSuccess || !opl->plmnNumeric.empty()) {
            oplCust_.push_back(opl);
        }
    }
}

void OperatorName::UpdateOperatorLongName(std::string &operatorLongName, const std::string &numeric)
{
    sptr<NetworkState> networkState = GetNetworkStatus();
    if (networkState == nullptr) {
        return;
    }

    RegServiceState regStatus = networkState->GetRegStatus();
    if (regStatus != RegServiceState::REG_STATE_IN_SERVICE) {
        return;
    }

    operatorLongName = longName_;
    if (TELEPHONY_EXT_WRAPPER.processOperatorName_ != nullptr) {
        netPriCust_ = TELEPHONY_EXT_WRAPPER.processOperatorName_(slotId_, operatorLongName, numeric);
        TELEPHONY_LOGI("OperatorName::UpdateOperatorLongName netPriCust_:%{public}d", netPriCust_);
    }

    std::string customizedOperatorLongName = GetCustomName(numeric);
    if (!customizedOperatorLongName.empty() && !netPriCust_) {
        operatorLongName = customizedOperatorLongName;
    }
}

void OperatorName::TrySetLongOperatorNameWithTranslation()
{
    sptr<NetworkState> networkState = GetNetworkStatus();
    if (networkState != nullptr && networkSearchState_ != nullptr) {
        std::string longOperatorName = networkState->GetLongOperatorName();
        std::string numeric = networkState->GetPlmnNumeric();
        UpdateOperatorLongName(longOperatorName, numeric);
        SetOperatorName(longOperatorName);
    }
    NotifySpnChanged();
}
} // namespace Telephony
} // namespace OHOS

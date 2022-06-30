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

#include "operator_name.h"

#include <common_event.h>
#include <common_event_manager.h>

#include "common_event_support.h"
#include "core_manager_inner.h"
#include "hril_network_parcel.h"
#include "network_search_manager.h"
#include "resource_utils.h"
#include "telephony_log_wrapper.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
const int32_t FORMAT_IDX_SPN_CS = 0;
const int32_t PNN_CUST_STRING_SIZE = 2;
const int32_t OPL_CUST_STRING_SIZE = 4;
/**
 * If true, customize the items related to operator name
 */
const std::string KEY_ENABLE_OPERATOR_NAME_CUST_BOOL = "enable_operator_name_cust_bool";
/**
 * Customize the operatoer name if #KEY_ENABLE_OPERATOR_NAME_CUST_BOOL is true.
 */
const std::string KEY_OPERATOR_NAME_CUST_STRING = "operator_name_cust_string";
/**
 * Customize the SPN Display Condition bits if #KEY_ENABLE_OPERATOR_NAME_CUST_BOOL is true. The default value '-1' means
 * this field is not set.
 * b1 = 0: display of registered PLMN name not required when registered PLMN is either HPLMN or a PLMN in the service
 * provider PLMN list (see EF_SPDI).
 * b1 = 1: display of registered PLMN name required when registered PLMN is either HPLMN or a PLMN in the service
 * provider PLMN list(see EF_SPDI).
 * b2 = 0: display of the service provider name is required when registered PLMN is neither HPLMN nor a PLMN in the
 * service provider PLMN list(see EF_SPDI).
 * b2 = 1: display of the service provider name is not required when registered PLMN is neither HPLMN nor a PLMN in the
 * service provider PLMN list(see EF_SPDI).
 *
 * See 3GPP TS 31.102 v15.2.0 Section 4.2.12 EF_SPN.
 */
const std::string KEY_SPN_DISPLAY_CONDITION_CUST_INT = "spn_display_condition_cust_int";
/**
 * Customize the PNN - a string array of comma-separated long and short names:
 * "long_name1,short_name1".
 *
 * See 3GPP TS 31.102 v15.2.0 Section 4.2.58 EF_PNN.
 */
const std::string KEY_PNN_CUST_STRING_ARRAY = "pnn_cust_string_array";
/**
 * Customize the OPL - a string array of OPL records, each with comma-delimited data fields as follows:
 * "plmn1,lac_start,lac_end,index".
 *
 * See 3GPP TS 31.102 v15.2.0 Section 4.2.59 EF_OPL.
 */
const std::string KEY_OPL_CUST_STRING_ARRAY = "opl_cust_string_array";

OperatorName::OperatorName(const EventFwk::CommonEventSubscribeInfo &sp,
    std::shared_ptr<NetworkSearchState> networkSearchState, std::shared_ptr<ISimManager> simManager,
    std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : CommonEventSubscriber(sp), networkSearchState_(networkSearchState), simManager_(simManager),
      networkSearchManager_(networkSearchManager), slotId_(slotId)
{
    std::vector<std::string> vecSpnFormats;
    ResourceUtils::Get().GetValueByName<std::vector<std::string>>(ResourceUtils::SPN_FORMATS, vecSpnFormats);
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
        }
    } else {
        TELEPHONY_LOGI("OperatorName::OnReceiveEvent Slot%{public}d: action=%{public}s code=%{public}d", slotId_,
            action.c_str(), data.GetCode());
    }
}

void OperatorName::HandleOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("OperatorName::HandleOperatorInfo networkSearchManager is nullptr slotId:%{public}d", slotId_);
    }
    PhoneType type = networkSearchManager->GetPhoneType(slotId_);
    if (type == PhoneType::PHONE_TYPE_IS_GSM) {
        GsmOperatorInfo(event);
    } else if (type == PhoneType::PHONE_TYPE_IS_CDMA) {
        CdmaOperatorInfo(event);
    } else {
        TELEPHONY_LOGE("OperatorName::HandleOperatorInfo phone type:%{public}d invalid", type);
    }
    networkSearchManager->decMsgNum(slotId_);
    if (networkSearchState_ != nullptr) {
        if (networkSearchManager->CheckIsNeedNotify(slotId_)) {
            networkSearchState_->NotifyStateChange();
        }
    }

    NotifySpnChanged();
    networkSearchManager->TriggerTimezoneRefresh(slotId_);
}

void OperatorName::GsmOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("OperatorName::GsmOperatorInfo event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::string longName = "";
    std::string shortName = "";
    std::string numeric = "";
    std::shared_ptr<OperatorInfoResult> operatorInfoResult = event->GetSharedObject<OperatorInfoResult>();
    if (operatorInfoResult != nullptr) {
        longName = operatorInfoResult->longName;
        shortName = operatorInfoResult->shortName;
        numeric = operatorInfoResult->numeric;
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

void OperatorName::CdmaOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("OperatorName::CdmaOperatorInfo event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::string longName = "";
    std::string shortName = "";
    std::string numeric = "";
    std::shared_ptr<OperatorInfoResult> operatorInfoResult = event->GetSharedObject<OperatorInfoResult>();
    if (operatorInfoResult != nullptr) {
        longName = operatorInfoResult->longName;
        shortName = operatorInfoResult->shortName;
        numeric = operatorInfoResult->numeric;
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
    if (networkSearchState_ != nullptr) {
        std::unique_ptr<NetworkState> networkState = networkSearchState_->GetNetworkStatus();
        if (networkState != nullptr) {
            networkState_ = networkState.release();
            return networkState_;
        }
    }
    TELEPHONY_LOGE("OperatorName::GetNetworkStatus networkState is nullptr slotId:%{public}d", slotId_);
    networkState_ = nullptr;
    return networkState_;
}

/**
 * 3GPP TS 51.011 V5.0.0(2001-12) 10.3.11
 */
void OperatorName::NotifySpnChanged()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("OperatorName::NotifySpnChanged networkSearchManager is nullptr slotId:%{public}d", slotId_);
    }
    TELEPHONY_LOGI("OperatorName::NotifySpnChanged slotId:%{public}d", slotId_);
    RegServiceState regStatus = RegServiceState::REG_STATE_UNKNOWN;
    sptr<NetworkState> networkState = GetNetworkStatus();
    if (networkState != nullptr) {
        regStatus = networkState->GetRegStatus();
    } else {
        TELEPHONY_LOGE("OperatorName::NotifySpnChanged networkState is nullptr slotId:%{public}d", slotId_);
    }
    if (networkSearchManager->GetPhoneType(slotId_) == PhoneType::PHONE_TYPE_IS_GSM) {
        NotifyGsmSpnChanged(regStatus, networkState);
    } else if (networkSearchManager->GetPhoneType(slotId_) == PhoneType::PHONE_TYPE_IS_CDMA) {
        NotifyCdmaSpnChanged(regStatus, networkState);
    }
}

void OperatorName::UpdatePlmn(
    RegServiceState regStatus, sptr<NetworkState> &networkState, int32_t spnRule, std::string &plmn, bool &showPlmn)
{
    if (networkState != nullptr) {
        switch (regStatus) {
            case RegServiceState::REG_STATE_IN_SERVICE:
                plmn = GetPlmn(networkState, true);
                showPlmn = !plmn.empty() && (((uint32_t)spnRule & SpnShowType::SPN_CONDITION_DISPLAY_PLMN) ==
                                                SpnShowType::SPN_CONDITION_DISPLAY_PLMN);
                break;
            case RegServiceState::REG_STATE_NO_SERVICE:
            case RegServiceState::REG_STATE_EMERGENCY_ONLY:
            case RegServiceState::REG_STATE_SEARCH:
                if (networkState->IsEmergency()) {
                    ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::EMERGENCY_CALLS_ONLY, plmn);
                } else {
                    ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::OUT_OF_SERIVCE, plmn);
                }
                showPlmn = true;
                break;
            case RegServiceState::REG_STATE_UNKNOWN:
            case RegServiceState::REG_STATE_POWER_OFF:
            default:
                ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::OUT_OF_SERIVCE, plmn);
                showPlmn = true;
                break;
        }
    }
}

void OperatorName::UpdateSpn(
    RegServiceState regStatus, sptr<NetworkState> &networkState, int32_t spnRule, std::string &spn, bool &showSpn)
{
    if (regStatus == RegServiceState::REG_STATE_IN_SERVICE) {
        if (enableCust_ && !spnCust_.empty()) {
            spn = spnCust_;
        }
        if (spn.empty()) {
            std::u16string result = Str8ToStr16("");
            if (simManager_ != nullptr) {
                result = simManager_->GetSimSpn(slotId_);
            }
            spn = Str16ToStr8(result);
        }
        if (!csSpnFormat_.empty()) {
            spn = NetworkUtils::FormatString(csSpnFormat_, spn.c_str());
        }
        showSpn = !spn.empty() && (((uint32_t)spnRule & SpnShowType::SPN_CONDITION_DISPLAY_SPN) ==
                                      SpnShowType::SPN_CONDITION_DISPLAY_SPN);
    } else {
        spn = "";
        showSpn = false;
    }
}

void OperatorName::NotifyGsmSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState)
{
    if (networkState == nullptr) {
        TELEPHONY_LOGE("OperatorName::NotifyGsmSpnChanged networkState is nullptr slotId:%{public}d", slotId_);
        return;
    }
    int32_t spnRule = 0;
    std::string plmn = "";
    std::string spn = "";
    bool showPlmn = false;
    bool showSpn = false;
    bool roaming = networkState->IsRoaming();
    if (enableCust_ && displayConditionCust_ != SPN_INVALID) {
        spnRule = GetCustSpnRule(roaming);
    } else {
        std::string numeric = networkState->GetPlmnNumeric();
        if (simManager_ != nullptr) {
            spnRule = simManager_->ObtainSpnCondition(slotId_, roaming, numeric);
        }
    }
    UpdatePlmn(regStatus, networkState, spnRule, plmn, showPlmn);
    UpdateSpn(regStatus, networkState, spnRule, spn, showSpn);
    TELEPHONY_LOGI(
        "OperatorName::NotifyGsmSpnChanged showSpn:%{public}d curSpn_:%{public}s spn:%{public}s showPlmn:%{public}d "
        "curPlmn_:%{public}s plmn:%{public}s slotId:%{public}d",
        showSpn, curSpn_.c_str(), spn.c_str(), showPlmn, curPlmn_.c_str(), plmn.c_str(), slotId_);
    if (curSpnRule_ != spnRule || curRegState_ != regStatus || curSpnShow_ != showSpn || curPlmnShow_ != showPlmn ||
        curSpn_.compare(spn) || curPlmn_.compare(plmn)) {
        TELEPHONY_LOGI("OperatorName::NotifyGsmSpnChanged start send broadcast slotId:%{public}d...", slotId_);
        PublishEvent(spnRule, regStatus, showPlmn, plmn, showSpn, spn);
    } else {
        TELEPHONY_LOGI(
            "OperatorName::NotifyGsmSpnChanged spn no changed, not need to update slotId:%{public}d", slotId_);
    }
}

void OperatorName::NotifyCdmaSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState)
{
    if (networkState == nullptr) {
        TELEPHONY_LOGE("OperatorName::NotifyCdmaSpnChanged networkState is nullptr slotId:%{public}d", slotId_);
        return;
    }
    int32_t spnRule = 0;
    std::string plmn = "";
    std::string spn = "";
    bool showPlmn = false;
    bool showSpn = false;
    bool roaming = networkState->IsRoaming();
    if (enableCust_ && displayConditionCust_ != SPN_INVALID) {
        spnRule = GetCustSpnRule(roaming);
    } else {
        std::string numeric = networkState->GetPlmnNumeric();
        if (simManager_ != nullptr) {
            spnRule = simManager_->ObtainSpnCondition(slotId_, roaming, numeric);
        }
    }
    if (regStatus == RegServiceState::REG_STATE_IN_SERVICE) {
        plmn = networkState->GetLongOperatorName();
        if (!csSpnFormat_.empty()) {
            plmn = NetworkUtils::FormatString(csSpnFormat_, plmn.c_str());
        }
    } else if (regStatus == RegServiceState::REG_STATE_NO_SERVICE) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::OUT_OF_SERIVCE, plmn);
    } else {
        plmn = "";
    }
    showPlmn = !plmn.empty() && (((uint32_t)spnRule & SpnShowType::SPN_CONDITION_DISPLAY_PLMN) ==
                                    SpnShowType::SPN_CONDITION_DISPLAY_PLMN);
    if (curSpnRule_ != spnRule || curRegState_ != regStatus || curSpnShow_ != showSpn || curPlmnShow_ != showPlmn ||
        curSpn_.compare(spn) || curPlmn_.compare(plmn)) {
        TELEPHONY_LOGI("OperatorName::NotifyCdmaSpnChanged start send broadcast slotId:%{public}d...", slotId_);
        PublishEvent(spnRule, regStatus, showPlmn, plmn, showSpn, spn);
    } else {
        TELEPHONY_LOGI(
            "OperatorName::NotifyCdmaSpnChanged spn no changed, not need to update slotId:%{public}d", slotId_);
    }
}

void OperatorName::PublishEvent(const int32_t rule, const RegServiceState state, const bool showPlmn,
    const std::string &plmn, const bool showSpn, const std::string &spn)
{
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SPN_INFO_CHANGED);
    want.SetParam(CUR_SLOT_ID, slotId_);
    want.SetParam(CUR_PLMN_SHOW, showPlmn);
    want.SetParam(CUR_PLMN, plmn);
    want.SetParam(CUR_SPN_SHOW, showSpn);
    want.SetParam(CUR_SPN, spn);

    CommonEventData data;
    data.SetWant(want);
    data.SetCode(MSG_NS_SPN_UPDATED);
    data.SetData(spn);

    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("OperatorName::PublishEvent result : %{public}d slotId:%{public}d", publishResult, slotId_);
    if (publishResult) {
        curRegState_ = state;
        curSpnRule_ = rule;
        curSpn_ = spn;
        curSpnShow_ = showSpn;
        curPlmn_ = plmn;
        curPlmnShow_ = showPlmn;
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
    TELEPHONY_LOGI(
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

unsigned int OperatorName::GetCustSpnRule(bool roaming)
{
    unsigned int cond = 0;
    if (displayConditionCust_ <= SPN_INVALID) {
        return cond;
    }
    if (roaming) {
        cond = SPN_CONDITION_DISPLAY_PLMN;
        if (((unsigned int)(displayConditionCust_) & (unsigned int)(SPN_COND)) == 0) {
            cond |= (unsigned int)SPN_CONDITION_DISPLAY_SPN;
        }
    } else {
        cond = SPN_CONDITION_DISPLAY_SPN;
        if (((unsigned int)(displayConditionCust_) & (unsigned int)(SPN_COND_PLMN)) == SPN_COND_PLMN) {
            cond |= (unsigned int)SPN_CONDITION_DISPLAY_PLMN;
        }
    }
    return cond;
}

std::string OperatorName::GetCustEons(const std::string &numeric, int32_t lac, bool roaming, bool longNameRequired)
{
    if (!enableCust_ || numeric.empty() || pnnCust_.empty()) {
        TELEPHONY_LOGI("OperatorName::GetCustEons Cust not enable, plmn or pnnFiles is empty");
        return "";
    }
    int32_t pnnIndex = -1;
    if (oplCust_.empty()) {
        TELEPHONY_LOGI("OperatorName::GetCustEons oplCust_ is empty");
        if (roaming) {
            return "";
        } else {
            pnnIndex = 1;
        }
    } else {
        for (std::shared_ptr<OperatorPlmnInfo> opl : oplCust_) {
            TELEPHONY_LOGI(
                "OperatorName::GetCustEons numeric:%{public}s, opl->plmnNumeric:%{public}s, lac:%{public}d, "
                "opl->lacStart:%{public}d, opl->lacEnd:%{public}d, "
                "opl->pnnRecordId:%{public}d",
                numeric.c_str(), opl->plmnNumeric.c_str(), lac, opl->lacStart, opl->lacEnd, opl->pnnRecordId);
            if (numeric.compare(opl->plmnNumeric) == 0 &&
                ((opl->lacStart == 0 && opl->lacEnd == 0xfffe) || (opl->lacStart <= lac && opl->lacEnd >= lac))) {
                if (opl->pnnRecordId == 0) {
                    return "";
                }
                pnnIndex = opl->pnnRecordId;
                break;
            }
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
    TELEPHONY_LOGI("OperatorName::GetCustomName numeric:%{public}s", numeric.c_str());
    std::string name = "";
    if (numeric.empty()) {
        return name;
    }
    auto obj = std::find(cmMccMnc_.begin(), cmMccMnc_.end(), numeric);
    if (obj != cmMccMnc_.end()) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::CMCC, name);
        TELEPHONY_LOGI("OperatorName::GetCustomName CMCC:%{public}s", name.c_str());
        return name;
    }
    obj = std::find(cuMccMnc_.begin(), cuMccMnc_.end(), numeric);
    if (obj != cuMccMnc_.end()) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::CUCC, name);
        TELEPHONY_LOGI("OperatorName::GetCustomName CUCC:%{public}s", name.c_str());
        return name;
    }
    obj = std::find(ctMccMnc_.begin(), ctMccMnc_.end(), numeric);
    if (obj != ctMccMnc_.end()) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::CTCC, name);
        TELEPHONY_LOGI("OperatorName::GetCustomName CTCC:%{public}s", name.c_str());
        return name;
    }
    return name;
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
        std::vector<std::string> pnnString = NetworkUtils::Split(data, ",");
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
        std::vector<std::string> oplString = NetworkUtils::Split(data, ",");
        if (oplString.size() != OPL_CUST_STRING_SIZE || oplString.back().empty()) {
            continue;
        }
        std::shared_ptr<OperatorPlmnInfo> opl = std::make_shared<OperatorPlmnInfo>();
        int32_t base = 16; // convert to hexadecimal
        opl->pnnRecordId = stoi(oplString.back(), 0, base);
        oplString.pop_back();
        if (oplString.back().empty()) {
            continue;
        }
        opl->lacEnd = stoi(oplString.back(), 0, base);
        oplString.pop_back();
        if (oplString.back().empty()) {
            continue;
        }
        opl->lacStart = stoi(oplString.back(), 0, base);
        oplString.pop_back();
        opl->plmnNumeric = oplString.back();
        if (!opl->plmnNumeric.empty()) {
            oplCust_.push_back(opl);
        }
    }
}
} // namespace Telephony
} // namespace OHOS

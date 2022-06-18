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
#include "hril_network_parcel.h"
#include "network_search_manager.h"
#include "resource_utils.h"
#include "sim_constant.h"
#include "telephony_log_wrapper.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
const int32_t FORMAT_IDX_SPN_CS = 0;
OperatorName::OperatorName(std::shared_ptr<NetworkSearchState> networkSearchState,
    std::shared_ptr<ISimManager> simManager, std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchState_(networkSearchState), simManager_(simManager), networkSearchManager_(networkSearchManager),
      slotId_(slotId)
{
    std::vector<std::string> vecSpnFormats;
    ResourceUtils::Get().GetValueByName<std::vector<std::string>>(ResourceUtils::SPN_FORMATS, vecSpnFormats);
    if (vecSpnFormats.size() > FORMAT_IDX_SPN_CS) {
        csSpnFormat_ = vecSpnFormats[FORMAT_IDX_SPN_CS];
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
        TELEPHONY_LOGE("OperatorName::HandleOperatorInfo networkSearchManager is nullptr slotId:%{public}d", slotId_);
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
    std::u16string result = Str8ToStr16("");
    if (simManager_ != nullptr) {
        result = simManager_->GetSimSpn(slotId_);
    }
    spn = Str16ToStr8(result);
    if (!csSpnFormat_.empty()) {
        spn = NetworkUtils::FormatString(csSpnFormat_, spn.c_str());
    }
    showSpn = !spn.empty() &&
              (((uint32_t)spnRule & SpnShowType::SPN_CONDITION_DISPLAY_SPN) == SpnShowType::SPN_CONDITION_DISPLAY_SPN);
    if (regStatus != RegServiceState::REG_STATE_IN_SERVICE) {
        spn = "";
        showSpn = false;
    }
}

void OperatorName::NotifyGsmSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState)
{
    int32_t spnRule = 0;
    std::string plmn = "";
    std::string spn = "";
    bool showPlmn = false;
    bool showSpn = false;
    if (networkState != nullptr) {
        bool roaming = networkState->IsRoaming();
        std::string numeric = networkState->GetPlmnNumeric();
        if (simManager_ != nullptr) {
            spnRule = simManager_->ObtainSpnCondition(slotId_, roaming, numeric);
        }
    }
    UpdatePlmn(regStatus, networkState, spnRule, plmn, showPlmn);
    UpdateSpn(regStatus, networkState, spnRule, spn, showSpn);
    TELEPHONY_LOGI(
        "OperatorName::NotifySpnChanged showSpn:%{public}d curSpn_:%{public}s spn:%{public}s showPlmn:%{public}d "
        "curPlmn_:%{public}s plmn:%{public}s slotId:%{public}d",
        showSpn, curSpn_.c_str(), spn.c_str(), showPlmn, curPlmn_.c_str(), plmn.c_str(), slotId_);
    if (curSpnRule_ != spnRule || curRegState_ != regStatus || curSpnShow_ != showSpn || curPlmnShow_ != showPlmn ||
        curSpn_.compare(spn) || curPlmn_.compare(plmn)) {
        PublishEvent(spnRule, regStatus, showPlmn, plmn, showSpn, spn);
    } else {
        TELEPHONY_LOGI("OperatorName::NotifySpnChanged spn no changed, not need to update slotId:%{public}d", slotId_);
    }
}

void OperatorName::NotifyCdmaSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState)
{
    int32_t spnRule = 0;
    std::string plmn = "";
    std::string spn = "";
    bool showPlmn = false;
    bool showSpn = false;
    if (networkState != nullptr) {
        bool roaming = networkState->IsRoaming();
        std::string numeric = networkState->GetPlmnNumeric();
        if (simManager_ != nullptr) {
            spnRule = simManager_->ObtainSpnCondition(slotId_, roaming, numeric);
        }
    }
    if (networkState != nullptr) {
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
    }
    showPlmn = !plmn.empty() && (((uint32_t)spnRule & SpnShowType::SPN_CONDITION_DISPLAY_PLMN) ==
                                    SpnShowType::SPN_CONDITION_DISPLAY_PLMN);
    if (curSpnRule_ != spnRule || curRegState_ != regStatus || curSpnShow_ != showSpn || curPlmnShow_ != showPlmn ||
        curSpn_.compare(spn) || curPlmn_.compare(plmn)) {
        TELEPHONY_LOGI("OperatorName::NotifySpnChanged start send broadcast slotId:%{public}d...", slotId_);
        PublishEvent(spnRule, regStatus, showPlmn, plmn, showSpn, spn);
    } else {
        TELEPHONY_LOGI("OperatorName::NotifySpnChanged spn no changed, not need to update slotId:%{public}d", slotId_);
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
    TELEPHONY_LOGI(
        "OperatorName::PublishEvent PublishSimEvent result : %{public}d slotId:%{public}d", publishResult, slotId_);
    curRegState_ = state;
    curSpnRule_ = rule;
    curSpn_ = spn;
    curSpnShow_ = showSpn;
    curPlmn_ = plmn;
    curPlmnShow_ = showPlmn;
}

std::string OperatorName::GetPlmn(sptr<NetworkState> &networkState, bool longNameRequired)
{
    std::string plmn = "";
    if (networkState != nullptr) {
        std::string numeric = networkState->GetPlmnNumeric();
        int32_t lac = GetCurrentLac();
        plmn = GetCustomName(numeric);
        if (plmn.empty()) {
            plmn = GetOverrideEons(numeric, lac, longNameRequired);
        }
        if (plmn.empty()) {
            plmn = GetEons(numeric, lac, longNameRequired);
        }
        if (plmn.empty()) {
            plmn = networkState->GetLongOperatorName();
        }
        TELEPHONY_LOGI("GetPlmn lac:%{public}d , numeric:%{public}s, longNameRequired:%{public}d, plmn:%{public}s", lac,
            numeric.c_str(), longNameRequired, plmn.c_str());
    }
    return plmn;
}

std::string OperatorName::GetEons(const std::string &numeric, int32_t lac, bool longNameRequired)
{
    if (simManager_ == nullptr) {
        return "";
    }
    return Str16ToStr8(simManager_->GetSimEons(slotId_, numeric, lac, longNameRequired));
}

std::string OperatorName::GetOverrideEons(const std::string &numeric, int32_t lac, bool longNameRequired)
{
    std::string overrideEonsName = "";
    return overrideEonsName;
}

std::string OperatorName::GetCustomName(const std::string &numeric)
{
    TELEPHONY_LOGI("GetCustomName numeric:%{public}s", numeric.c_str());
    std::string name = "";
    if (numeric.empty()) {
        return name;
    }
    auto obj = std::find(cmMccMnc_.begin(), cmMccMnc_.end(), numeric);
    if (obj != cmMccMnc_.end()) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::CMCC, name);
        TELEPHONY_LOGI("GetCustomName CMCC:%{public}s", name.c_str());
        return name;
    }
    obj = std::find(cuMccMnc_.begin(), cuMccMnc_.end(), numeric);
    if (obj != cuMccMnc_.end()) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::CUCC, name);
        TELEPHONY_LOGI("GetCustomName CUCC:%{public}s", name.c_str());
        return name;
    }
    obj = std::find(ctMccMnc_.begin(), ctMccMnc_.end(), numeric);
    if (obj != ctMccMnc_.end()) {
        ResourceUtils::Get().GetValueByName<std::string>(ResourceUtils::CTCC, name);
        TELEPHONY_LOGI("GetCustomName CTCC:%{public}s", name.c_str());
        return name;
    }
    TELEPHONY_LOGI("GetCustomName empty:%{public}s", name.c_str());
    return name;
}

int32_t OperatorName::GetCurrentLac()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("GetCurrentLac networkSearchManager is nullptr slotId:%{public}d", slotId_);
        return 0;
    }
    sptr<CellLocation> location = networkSearchManager->GetCellLocation(slotId_);
    if (location == nullptr) {
        TELEPHONY_LOGE("GetCurrentLac location is nullptr slotId:%{public}d", slotId_);
        return 0;
    }
    if (location->GetCellLocationType() != CellLocation::CellType::CELL_TYPE_GSM) {
        TELEPHONY_LOGE("GetCurrentLac location type isn't GSM slotId:%{public}d", slotId_);
        return 0;
    }
    sptr<GsmCellLocation> gsmLocation = sptr<GsmCellLocation>(static_cast<GsmCellLocation *>(location.GetRefPtr()));
    if (gsmLocation == nullptr) {
        TELEPHONY_LOGE("GetCurrentLac gsmLocation is nullptr slotId:%{public}d", slotId_);
        return 0;
    }
    return gsmLocation->GetLac();
}
} // namespace Telephony
} // namespace OHOS

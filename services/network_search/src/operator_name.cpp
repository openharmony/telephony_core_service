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

#include <common_event_manager.h>
#include <common_event.h>
#include "common_event_support.h"

#include "core_manager.h"
#include "hril_network_parcel.h"
#include "network_search_manager.h"
#include "telephony_log_wrapper.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
const std::string EMERGENCY_ONLY = "Emergency only";
const std::string NO_SERVICE = "No service";

OperatorName::OperatorName(std::shared_ptr<NetworkSearchState> networkSearchState,
    std::shared_ptr<ISimFileManager> simFileManager, std::weak_ptr<NetworkSearchManager> networkSearchManager)
    : networkSearchState_(networkSearchState), simFileManager_(simFileManager),
    networkSearchManager_(networkSearchManager)
{}

void OperatorName::HandleOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (phone_.PhoneTypeGsmOrNot()) {
        GsmOperatorInfo(event);
    }
    if (phone_.PhoneTypeCdmaOrNot()) {
        CdmaOperatorInfo(event);
    }

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager != nullptr) {
        networkSearchManager->decMsgNum();
        if (networkSearchState_ != nullptr) {
            if (networkSearchManager->CheckIsNeedNotify()) {
                networkSearchState_->NotifyStateChange();
            }
        }
    }

    NotifySpnChanged();
}

void OperatorName::GsmOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("OperatorName::GsmOperatorInfo event is nullptr");
        return;
    }
    std::shared_ptr<OperatorInfoResult> operatorInfoResult = event->GetSharedObject<OperatorInfoResult>();
    if (!operatorInfoResult) {
        TELEPHONY_LOGE("OperatorName::GsmOperatorInfo operatorInfoResult is nullptr");
        return;
    }
    TELEPHONY_LOGI(
        "OperatorName::GsmOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : "
        "%{public}s\n",
        operatorInfoResult->longName.c_str(), operatorInfoResult->shortName.c_str(),
        operatorInfoResult->numeric.c_str());
    if (networkSearchState_ != nullptr) {
        networkSearchState_->SetOperatorInfo(operatorInfoResult->longName, operatorInfoResult->shortName,
            operatorInfoResult->numeric, DomainType::DOMAIN_TYPE_CS);
    }
}

void OperatorName::CdmaOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("OperatorName::CdmaOperatorInfo event is nullptr");
        return;
    }
    std::shared_ptr<OperatorInfoResult> operatorInfoResult = event->GetSharedObject<OperatorInfoResult>();
    if (!operatorInfoResult) {
        TELEPHONY_LOGE("OperatorName::CdmaOperatorInfo operatorInfoResult is nullptr");
        return;
    }
    TELEPHONY_LOGI(
        "OperatorName::CdmaOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : "
        "%{public}s\n",
        operatorInfoResult->longName.c_str(), operatorInfoResult->shortName.c_str(),
        operatorInfoResult->numeric.c_str());
    if (networkSearchState_ != nullptr) {
        networkSearchState_->SetOperatorInfo(operatorInfoResult->longName, operatorInfoResult->shortName,
            operatorInfoResult->numeric, DomainType::DOMAIN_TYPE_PS);
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
    TELEPHONY_LOGE("OperatorName::GetNetworkStatus networkState is nullptr");
    networkState_ = nullptr;
    return networkState_;
}

/**
 * 3GPP TS 51.011 V5.0.0(2001-12) 10.3.11
 */
void OperatorName::NotifySpnChanged()
{
    TELEPHONY_LOGI("OperatorName::NotifySpnChanged");
    RegServiceState regStatus = RegServiceState::REG_STATE_UNKNOWN;
    sptr<NetworkState> networkState = GetNetworkStatus();
    if (networkState != nullptr) {
        regStatus = networkState->GetRegStatus();
    } else {
        TELEPHONY_LOGE("OperatorName::NotifySpnChanged networkState is nullptr");
    }
    if (phone_.PhoneTypeGsmOrNot()) {
        int32_t spnRule = 0;
        std::string plmn = "";
        bool showPlmn = false;
        if (networkState != nullptr) {
            bool roaming = networkState->IsRoaming();
            std::string numeric = networkState->GetPlmnNumeric();
            if (simFileManager_ != nullptr) {
                spnRule = simFileManager_->ObtainSpnCondition(roaming, numeric);
            }
        }
        if (regStatus == RegServiceState::REG_STATE_IN_SERVICE && networkState != nullptr) {
            plmn = networkState->GetLongOperatorName();
            showPlmn = !plmn.empty();
        } else {
            plmn = "";
            showPlmn = true;
        }

        bool showSpn = false;
        std::string spn = "";
        std::u16string result = Str8ToStr16("");
        if (simFileManager_ != nullptr) {
            result = simFileManager_->GetSimSpn(CoreManager::DEFAULT_SLOT_ID);
        }
        spn = Str16ToStr8(result);
        showSpn = !spn.empty();
        if (regStatus == RegServiceState::REG_STATE_UNKNOWN) {
            spn = "";
            showSpn = false;
        }
        if (curSpnRule_ != spnRule || curRegState_ != regStatus || curSpnShow_ != showSpn ||
            curPlmnShow_ != showPlmn || curSpn_.compare(spn) != 0 || curPlmn_.compare(plmn) != 0) {
            TELEPHONY_LOGI("OperatorName::NotifySpnChanged start send broadcast......\n");
            PublishEvent(spnRule, regStatus, showPlmn, plmn, showSpn, spn);
        } else {
            TELEPHONY_LOGE("OperatorName::NotifySpnChanged spn no changed, not need to update!");
        }
    }
}

void OperatorName::PublishEvent(const int32_t rule, const RegServiceState state, const bool showPlmn,
    const std::string &plmn, const bool showSpn, const std::string &spn)
{
    TELEPHONY_LOGI("OperatorName::PublishEvent\n");
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SPN_INFO_UPDATED);
    want.SetParam(CUR_SPN_SHOW_RULE, rule);
    want.SetParam(CUR_REG_STATE, static_cast<int32_t>(state));
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
    TELEPHONY_LOGI("OperatorName::PublishEvent PublishSimEvent result : %{public}d", publishResult);
    curRegState_ = state;
    curSpnRule_ = rule;
    curSpn_ = spn;
    curSpnShow_ = showSpn;
    curPlmn_ = plmn;
    curPlmnShow_ = showPlmn;
}
} // namespace Telephony
} // namespace OHOS

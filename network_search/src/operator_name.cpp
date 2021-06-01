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
#include "hril_network_parcel.h"

#include "hilog_network_search.h"
#include "network_search_manager.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
const std::string EMERGENCY_ONLY = "Emergency only";
const std::string NO_SERVICE = "No service";

OperatorName::OperatorName(std::shared_ptr<NetworkSearchState> networkSearchState)
    : networkSearchState_(networkSearchState), phone_()
{
    if (PhoneManager ::GetInstance().phone_[1] != nullptr) {
        if (PhoneManager ::GetInstance().phone_[1]->simFileManager_ != nullptr) {
            simFileManager_ = PhoneManager ::GetInstance().phone_[1]->simFileManager_;
        }
    }
}

void OperatorName::HandleOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (phone_.PhoneTypeGsmOrNot()) {
        GsmOperatorInfo(event);
    }
    if (phone_.PhoneTypeCdmaOrNot()) {
        CdmaOperatorInfo(event);
    }

    networkSearchState_->NotifyStateChange();
}

void OperatorName::GsmOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<OperatorInfoResult> operatorInfoResult = event->GetSharedObject<OperatorInfoResult>();
    if (!operatorInfoResult) {
        HILOG_INFO("OperatorName::GsmOperatorInfo operatorInfoResult is nullptr\n");
        return;
    }

    HILOG_INFO(
        "OperatorName::GsmOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : "
        "%{public}s\n",
        operatorInfoResult->longName.c_str(), operatorInfoResult->shortName.c_str(),
        operatorInfoResult->numeric.c_str());

    networkSearchState_->SetOperatorInfo(
        operatorInfoResult->longName, operatorInfoResult->shortName, operatorInfoResult->numeric, DOMAIN_TYPE_CS);
}

void OperatorName::CdmaOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<OperatorInfoResult> operatorInfoResult = event->GetSharedObject<OperatorInfoResult>();
    if (!operatorInfoResult) {
        HILOG_INFO("OperatorName::CdmaOperatorInfo operatorInfoResult is nullptr\n");
        return;
    }

    HILOG_INFO(
        "OperatorName::CdmaOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : "
        "%{public}s\n",
        operatorInfoResult->longName.c_str(), operatorInfoResult->shortName.c_str(),
        operatorInfoResult->numeric.c_str());

    networkSearchState_->SetOperatorInfo(
        operatorInfoResult->longName, operatorInfoResult->shortName, operatorInfoResult->numeric, DOMAIN_TYPE_PS);
}

void OperatorName::RenewSpnAndBroadcast()
{
    int regStatus = networkSearchState_->GetNetworkStatus()->GetRegStatus();
    if (phone_.PhoneTypeGsmOrNot()) {
        std::string plmn = "";

        bool showPlmn = false;
        if (regStatus == REG_STATE_IN_SERVICE) {
            plmn = networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
            showPlmn = !plmn.empty();
        } else if (regStatus == REG_STATE_EMERGENCY_ONLY || regStatus == REG_STATE_NO_SERVICE) {
            showPlmn = true;
            if (regStatus == REG_STATE_EMERGENCY_ONLY) {
                plmn = EMERGENCY_ONLY;
            } else {
                plmn = NO_SERVICE;
            }
        } else {
            showPlmn = true;
            plmn = NO_SERVICE;
        }

        if (plmn != curPlmn_) {
            HILOG_INFO("OperatorName::RenewSpnAndBroadcast start send broadcast......\n");
            Want want;
            want.SetAction(SPN_INFO_UPDATED_ACTION);
            want.SetParam(CUR_PLMN_SHOW, showPlmn);
            want.SetParam(CUR_PLMN, plmn);
            PublishBroadcastEvent(want, MSG_NS_SPN_UPDATED, plmn);

            curPlmn_ = plmn;
            curPlmnShow_ = showPlmn;
        }
    }
}

void OperatorName::PublishBroadcastEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData)
{
    CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    if (!publishResult) {
        HILOG_INFO("OperatorName::PublishBroadcastEvent result : %{public}d", publishResult);
    }
}
} // namespace OHOS

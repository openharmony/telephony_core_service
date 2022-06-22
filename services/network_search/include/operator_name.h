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

#ifndef NETWORK_SEARCH_INCLUDE_OPERATOR_NAME_H
#define NETWORK_SEARCH_INCLUDE_OPERATOR_NAME_H

#include <memory>

#include "common_event_subscriber.h"
#include "event_handler.h"
#include "i_sim_manager.h"
#include "network_search_state.h"
#include "telephony_types.h"
#include "want.h"

namespace OHOS {
namespace Telephony {
class OperatorName : public EventFwk::CommonEventSubscriber {
public:
    OperatorName(const EventFwk::CommonEventSubscribeInfo &sp, std::shared_ptr<NetworkSearchState> networkSearchState,
        std::shared_ptr<ISimManager> simManager, std::weak_ptr<NetworkSearchManager> networkSearchManager,
        int32_t slotId);
    virtual ~OperatorName() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
    void HandleOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void NotifySpnChanged();

private:
    void GsmOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event) const;
    void CdmaOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event) const;
    void PublishEvent(const int32_t rule, const RegServiceState state, const bool showPlmn, const std::string &plmn,
        const bool showSpn, const std::string &spn);
    sptr<NetworkState> GetNetworkStatus();
    void NotifyGsmSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState);
    void NotifyCdmaSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState);

    void UpdatePlmn(RegServiceState regStatus, sptr<NetworkState> &networkState, int32_t spnRule, std::string &plmn,
        bool &showPlmn);
    void UpdateSpn(
        RegServiceState regStatus, sptr<NetworkState> &networkState, int32_t spnRule, std::string &spn, bool &showSpn);
    int32_t GetCurrentLac();
    std::string GetCustomName(const std::string &numeric);
    std::string GetEons(const std::string &numeric, int32_t lac, bool longNameRequired);
    std::string GetOverrideEons(const std::string &numeric, int32_t lac, bool roaming, bool longNameRequired);
    std::string GetPlmn(const sptr<NetworkState> &networkState, bool longNameRequired);
    void UpdatePnnOverride(const std::vector<std::string> &pnnOverride);
    void UpdateOplOverride(const std::vector<std::string> &oplOverride);
    void UpdateOperatorConfig();

private:
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
    std::shared_ptr<ISimManager> simManager_ = nullptr;
    std::string curPlmn_ = "";
    bool curPlmnShow_ = false;
    std::string curSpn_ = "";
    bool curSpnShow_ = false;
    RegServiceState curRegState_ = RegServiceState::REG_STATE_UNKNOWN;
    int32_t curSpnRule_ = -1;
    sptr<NetworkState> networkState_ = nullptr;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    int32_t slotId_ = 0;
    std::string csSpnFormat_;
    const std::vector<std::string> cmMccMnc_ { "46000", "46002", "46004", "46007", "46008" };
    const std::vector<std::string> cuMccMnc_ { "46001", "46009" };
    const std::vector<std::string> ctMccMnc_ { "46003", "46011" };
    bool enableOverride_ = false;
    std::string spnOverride_ = "";
    int32_t spnRuleOverride_ = 0;
    std::vector<std::shared_ptr<PlmnNetworkName>> pnnOverride_;
    std::vector<std::shared_ptr<OperatorPlmnInfo>> oplOverride_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_OPERATOR_NAME_H

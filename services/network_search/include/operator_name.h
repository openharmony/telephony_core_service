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
#include "sim_constant.h"
#include "telephony_types.h"
#include "want.h"
#include "operator_name_params.h"

namespace OHOS {
namespace Telephony {
class OperatorName : public EventFwk::CommonEventSubscriber {
public:
    OperatorName(const EventFwk::CommonEventSubscribeInfo &sp, std::shared_ptr<NetworkSearchState> networkSearchState,
        std::shared_ptr<ISimManager> simManager, std::weak_ptr<NetworkSearchManager> networkSearchManager,
        int32_t slotId);
    virtual ~OperatorName() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
    void HandleOperatorInfo(const std::shared_ptr<OperatorInfoResult> operatorInfoResult);
    void NotifySpnChanged(bool isForce = false);
    void TrySetLongOperatorNameWithTranslation();

private:
    void GsmOperatorInfo(const std::shared_ptr<OperatorInfoResult> operatorInfoResult);
    void CdmaOperatorInfo(const std::shared_ptr<OperatorInfoResult> operatorInfoResult);
    void PublishEvent(OperatorNameParams params, RegServiceState state, const std::string &domesticSpn);
    sptr<NetworkState> GetNetworkStatus();
    void NotifyGsmSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState,
        const std::string &domesticSpn, bool isForce = false);
    void NotifyCdmaSpnChanged(RegServiceState regStatus, sptr<NetworkState> &networkState,
        const std::string &domesticSpn, bool isForce = false);

    void UpdatePlmn(RegServiceState regStatus, sptr<NetworkState> &networkState, OperatorNameParams &params);
    void UpdateSpn(RegServiceState regStatus, sptr<NetworkState> &networkState, OperatorNameParams &params);
    int32_t GetCurrentLac();
    std::string GetCustomName(const std::string &numeric);
    unsigned int GetSpnRule(sptr<NetworkState> &networkState);
    unsigned int GetCustSpnRule(bool roaming);
    std::string GetEons(const std::string &numeric, int32_t lac, bool longNameRequired);
    std::string GetCustEons(const std::string &numeric, int32_t lac, bool roaming, bool longNameRequired);
    std::string GetPlmn(const sptr<NetworkState> &networkState, bool longNameRequired);
    void UpdatePnnCust(const std::vector<std::string> &pnnCust);
    void UpdateOplCust(const std::vector<std::string> &oplCust);
    void UpdateOperatorConfig();
    bool isDomesticRoaming(const std::string &simPlmn, const std::string &netPlmn);
    bool IsChinaCard();
    bool isCMCard(const std::string &numeric);
    bool isCUCard(const std::string &numeric);
    bool isCTCard(const std::string &numeric);
    bool isCBCard(const std::string &numeric);
    bool isCMDomestic(const std::string &numeric);
    bool isCUDomestic(const std::string &numeric);
    bool isCTDomestic(const std::string &numeric);
    bool isCBDomestic(const std::string &numeric);
    void UpdateOperatorLongName(std::string &operatorLongName, const std::string &numeric);
    void UpdateVSimSpn(OperatorNameParams &params);
    void SetOperatorName(const std::string &operatorName);

private:
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
    std::shared_ptr<ISimManager> simManager_ = nullptr;
    OperatorNameParams curParams_ = {false, "", false, "", 0};
    RegServiceState curRegState_ = RegServiceState::REG_STATE_UNKNOWN;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    int32_t slotId_ = 0;
    std::string csSpnFormat_;
    const std::vector<std::string> cmMccMnc_ { "46000", "46002", "46004", "46007", "46008", "46013" };
    const std::vector<std::string> cuMccMnc_ { "46001", "46006", "46009" };
    const std::vector<std::string> ctMccMnc_ { "46003", "46011" };
    const std::vector<std::string> cbnMccMnc_ { "46015" };
    const std::vector<std::string> cmDomesticMccMnc_ { "46031", "46050" };
    const std::vector<std::string> cuDomesticMccMnc_ { "46022", "46061", "46059" };
    const std::vector<std::string> ctDomesticMccMnc_ { "46021", "46060" };
    const std::vector<std::string> cbDomesticnMccMnc_ { "46032", "46051" };
    bool enableCust_ = false;
    bool netPriCust_ = false;
    std::string spnCust_ = "";
    int32_t displayConditionCust_ = SPN_INVALID;
    std::vector<std::shared_ptr<PlmnNetworkName>> pnnCust_;
    std::vector<std::shared_ptr<OperatorPlmnInfo>> oplCust_;
    std::string longName_ = "";
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_OPERATOR_NAME_H

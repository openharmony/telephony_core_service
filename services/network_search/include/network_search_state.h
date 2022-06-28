/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_STATE_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_STATE_H

#include <memory>
#include <mutex>
#include "network_state.h"
#include "network_type.h"
#include "ims_core_service_types.h"
#include "ims_reg_types.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NetworkSearchState {
public:
    NetworkSearchState(const std::weak_ptr<NetworkSearchManager> &networkSearchManager, int32_t slotId);
    virtual ~NetworkSearchState() = default;
    bool Init();
    void SetOperatorInfo(const std::string &longName, const std::string &shortName, const std::string &numeric,
        DomainType domainType);
    void SetEmergency(bool isEmergency);
    bool IsEmergency();
    void SetNetworkType(RadioTech tech, DomainType domainType);
    void SetNetworkState(RegServiceState state, DomainType domainType);
    void SetNetworkStateToRoaming(RoamingType roamingType, DomainType domainType);
    void SetInitial();
    void SetNrState(NrState state);
    void SetCfgTech(RadioTech tech);
    std::unique_ptr<NetworkState> GetNetworkStatus();
    int32_t GetImsStatus(ImsServiceType imsSrvType, ImsRegInfo &info);
    void SetImsStatus(bool imsRegStatus);
    void SetImsServiceStatus(const ImsServiceStatus &imsServiceStatus);
    void NotifyStateChange();
    void CsRadioTechChange();

private:
    void NotifyPsRegStatusChange();
    void NotifyPsRoamingStatusChange();
    void NotifyPsRadioTechChange();
    void NotifyEmergencyChange();
    void NotifyNrStateChange();
    void NotifyImsStateChange(const ImsServiceType imsSrvType, const ImsRegInfo info);
    std::mutex mutex_;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::unique_ptr<NetworkState> networkState_ = nullptr;
    std::unique_ptr<NetworkState> networkStateOld_ = nullptr;
    std::mutex imsMutex_;
    bool imsRegStatus_ = false;
    int32_t slotId_ = 0;
    std::unique_ptr<ImsServiceStatus> imsServiceStatus_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_STATE_H

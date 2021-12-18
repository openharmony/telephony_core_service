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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_STATE_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_STATE_H

#include <memory>
#include <mutex>
#include "network_state.h"
#include "network_type.h"

namespace OHOS {
namespace Telephony {
class PhoneAbstract {
public:
    bool PhoneTypeGsmOrNot() const
    {
        return true;
    }

    bool PhoneTypeCdmaOrNot() const
    {
        return true;
    }
};

class NetworkSearchManager;
class NetworkSearchState {
public:
    NetworkSearchState(const std::weak_ptr<NetworkSearchManager> &networkSearchManager);
    virtual ~NetworkSearchState() = default;
    void Init();
    void SetOperatorInfo(const std::string &longName, const std::string &shortName, const std::string &numeric,
        DomainType domainType);
    void SetEmergency(bool isEmergency);
    void SetNetworkType(RadioTech tech, DomainType domainType);
    void SetNetworkState(RegServiceState state, DomainType domainType);
    void SetNetworkStateToRoaming(RoamingType roamingType, DomainType domainType);
    void SetInitial();
    bool GsmOrNot(RadioTech radioTechnology) const;
    bool CdmaOrNot(RadioTech radioTechnology) const;
    std::unique_ptr<NetworkState> GetNetworkStatus();
    bool GetImsStatus();
    void SetImsStatus(bool imsRegStatus);
    void NotifyStateChange();
    void CsRadioTechChange();

private:
    std::mutex mutex_;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::shared_ptr<NetworkState> networkState_ = nullptr;
    std::shared_ptr<NetworkState> networkStateOld_ = nullptr;
    std::mutex imsMutex_;
    bool imsRegStatus_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_STATE_H

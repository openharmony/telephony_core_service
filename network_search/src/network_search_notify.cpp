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
#include "network_search_notify.h"
#include <unistd.h>
#include "hilog_network_search.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
NetworkSearchNotify::NetworkSearchNotify() {};
NetworkSearchNotify::~NetworkSearchNotify() {};
void NetworkSearchNotify::ConnectService()
{
    HILOG_INFO("NetworkSearchNotify GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        HILOG_INFO("NetworkSearchNotify Get ISystemAbilityManager failed ... ");
        return;
    }
    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID);
    if (remote) {
        sptr<TelephonyState::ITelephonyStateNotify> telephonyService =
            iface_cast<TelephonyState::ITelephonyStateNotify>(remote);
        telephonyStateNotify_ = telephonyService;
        HILOG_INFO("NetworkSearchNotify Get TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID succ ...");
    } else {
        HILOG_INFO("NetworkSearchNotify Get TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID fail ...");
    }
}

bool NetworkSearchNotify::ResetConnectService()
{
    HILOG_INFO("NetworkSearchNotify ResetConnectService ...");
    for (int i = 1; i <= RESET_CONNECTS; ++i) {
        ConnectService();
        if (telephonyStateNotify_ != nullptr) {
            HILOG_INFO("NetworkSearchNotify ResetConnectService suc...");
            return true;
        }
        usleep(RESET_CONNECT_SLEEP_TIME * i);
    }
    HILOG_INFO("NetworkSearchNotify ResetConnectService fail...");
    return false;
}

void NetworkSearchNotify::NotifyNetworkStateUpdated(const sptr<NetworkState> &networkState)
{
    HILOG_INFO("NotifyNetworkStateUpdated~~~\n");

    if (telephonyStateNotify_ != nullptr) {
        int32_t result = telephonyStateNotify_->UpdateNetworkState(0, 0, networkState);
        HILOG_INFO("NotifyNetworkStateUpdated ret %{public}d", result);
        if (result != 0) {
            ResetConnectService();
            if (telephonyStateNotify_ != nullptr) {
                telephonyStateNotify_->UpdateNetworkState(0, 0, networkState);
                return;
            }
        }
    } else {
        ResetConnectService();
        if (telephonyStateNotify_ != nullptr) {
            telephonyStateNotify_->UpdateNetworkState(0, 0, networkState);
            return;
        }
        HILOG_INFO("NotifyNetworkStateUpdated TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID not found\n");
    }
}

void NetworkSearchNotify::NotifySignalInfoUpdated(const std::vector<sptr<SignalInformation>> &signalInfos)
{
    HILOG_INFO("NotifySignalInfoUpdated~~~ signalInfos.size=%{public}zu\n", signalInfos.size());

    if (telephonyStateNotify_ != nullptr) {
        int32_t result = telephonyStateNotify_->UpdateSignalInfo(0, 0, signalInfos);
        HILOG_INFO("NotifySignalInfoUpdated ret %{public}d", result);
        if (result != 0) {
            ResetConnectService();
            if (telephonyStateNotify_ != nullptr) {
                telephonyStateNotify_->UpdateSignalInfo(0, 0, signalInfos);
                return;
            }
        }
    } else {
        ResetConnectService();
        if (telephonyStateNotify_ != nullptr) {
            telephonyStateNotify_->UpdateSignalInfo(0, 0, signalInfos);
            return;
        }
        HILOG_INFO("NotifySignalInfoUpdated TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID not found\n");
    }
}
} // namespace OHOS

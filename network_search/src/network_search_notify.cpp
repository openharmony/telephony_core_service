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
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSearchNotify::NetworkSearchNotify() {};
NetworkSearchNotify::~NetworkSearchNotify() {};
void NetworkSearchNotify::ConnectService()
{
    TELEPHONY_LOGI("NetworkSearchNotify GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGI("NetworkSearchNotify Get ISystemAbilityManager failed ... ");
        return;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID);
    if (remote) {
        sptr<ITelephonyStateNotify> telephonyService = iface_cast<ITelephonyStateNotify>(remote);
        telephonyStateNotify_ = telephonyService;
        TELEPHONY_LOGI("NetworkSearchNotify Get TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID success ...");
    } else {
        TELEPHONY_LOGI("NetworkSearchNotify Get TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID fail ...");
    }
}

bool NetworkSearchNotify::ResetConnectService()
{
    TELEPHONY_LOGI("NetworkSearchNotify ResetConnectService ...");
    for (int i = 1; i <= RESET_CONNECTS; ++i) {
        ConnectService();
        if (telephonyStateNotify_ != nullptr) {
            TELEPHONY_LOGI("NetworkSearchNotify ResetConnectService suc...");
            return true;
        }
        usleep(RESET_CONNECT_SLEEP_TIME * i);
    }
    TELEPHONY_LOGI("NetworkSearchNotify ResetConnectService fail...");
    return false;
}

void NetworkSearchNotify::NotifyNetworkStateUpdated(const sptr<NetworkState> &networkState)
{
    TELEPHONY_LOGI("NotifyNetworkStateUpdated~~~\n");
    int simId = 0;
    if (telephonyStateNotify_ != nullptr) {
        int32_t result = telephonyStateNotify_->UpdateNetworkState(simId, networkState);
        TELEPHONY_LOGI("NotifyNetworkStateUpdated ret %{public}d", result);
        if (result != 0) {
            ResetConnectService();
            if (telephonyStateNotify_ != nullptr) {
                telephonyStateNotify_->UpdateNetworkState(simId, networkState);
                return;
            }
        }
    } else {
        ResetConnectService();
        if (telephonyStateNotify_ != nullptr) {
            telephonyStateNotify_->UpdateNetworkState(simId, networkState);
            return;
        }
        TELEPHONY_LOGI("NotifyNetworkStateUpdated TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID not found\n");
    }
}

void NetworkSearchNotify::NotifySignalInfoUpdated(const std::vector<sptr<SignalInformation>> &signalInfos)
{
    TELEPHONY_LOGI("NotifySignalInfoUpdated~~~ signalInfos size=%{public}zu\n", signalInfos.size());
    int simId = 0;
    if (telephonyStateNotify_ != nullptr) {
        int32_t result = telephonyStateNotify_->UpdateSignalInfo(simId, signalInfos);
        TELEPHONY_LOGI("NotifySignalInfoUpdated ret %{public}d", result);
        if (result != 0) {
            ResetConnectService();
            if (telephonyStateNotify_ != nullptr) {
                telephonyStateNotify_->UpdateSignalInfo(simId, signalInfos);
                return;
            }
        }
    } else {
        ResetConnectService();
        if (telephonyStateNotify_ != nullptr) {
            telephonyStateNotify_->UpdateSignalInfo(simId, signalInfos);
            return;
        }
        TELEPHONY_LOGI("NotifySignalInfoUpdated TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID not found\n");
    }
}
} // namespace Telephony
} // namespace OHOS
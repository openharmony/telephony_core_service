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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_NOTIFY_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_NOTIFY_H

#include <singleton.h>
#include "network_state.h"
#include "signal_information.h"
#include "telephony_state_registry_client.h"
#include "cell_information.h"
namespace OHOS {
namespace Telephony {
class NetworkSearchNotify {
    DECLARE_DELAYED_SINGLETON(NetworkSearchNotify)
    static const int32_t RESET_CONNECTS = 5;
    static const int32_t RESET_CONNECT_SLEEP_TIME = 5;

public:
    void NotifyNetworkStateUpdated(const sptr<NetworkState> &networkState);
    void NotifySignalInfoUpdated(const std::vector<sptr<SignalInformation>> &signalInfos);
    void NotifyCellInfoUpdated(const std::vector<sptr<CellInformation>> &signalInfos);
};
} // namespace Telephony
} // namespace OHOS

#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_NOTIFY_H

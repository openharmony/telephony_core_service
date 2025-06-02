/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_MANAGER_H
#define NETWORK_SEARCH_MANAGER_H
#include "mock_i_network_search_manager.h"

namespace OHOS {
namespace Telephony {

class NetworkSearchManager : public testing::NiceMock<MockINetworkSearch>, public std::enable_shared_from_this<NetworkSearchManager> {
public:
    virtual ~NetworkSearchManager() = default;
    NetworkSearchManager(std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<ISimManager> simManager)
    {
        testing::Mock::AllowLeak(this);
    }
};

}
}

#endif
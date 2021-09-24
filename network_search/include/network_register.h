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
#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_REGISTER_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_REGISTER_H
#include <memory>
#include <string>
#include "event_handler.h"
#include "hril_types.h"
#include "network_search_state.h"

namespace OHOS {
namespace Telephony {
class NetworkRegister {
public:
    explicit NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState);
    virtual ~NetworkRegister() = default;
    void ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessRestrictedState(const AppExecFwk::InnerEvent::Pointer &event) const;
    enum RilRegister {
        REG_STATE_NOT_REG = 0,
        REG_STATE_HOME_ONLY = 1,
        REG_STATE_SEARCH = 2,
        REG_STATE_NO_SERVICE = 3,
        REG_STATE_INVALID = 4,
        REG_STATE_ROAMING = 5,
        REG_STATE_EMERGENCY_ONLY = 6
    };

private:
    RegServiceState ConvertRegFromRil(int code) const;
    RadioTech ConvertTechFromRil(int code) const;

private:
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_REGISTER_H

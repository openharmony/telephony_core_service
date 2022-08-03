/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "core_service_hisysevent.h"

#include "hisysevent.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
static constexpr const char *DOMAIN_CORE_SERVICE = "CORE_SERVICE";

// EVENT
static constexpr const char *SIGNAL_LEVEL_EVENT = "SIGNAL_LEVEL";
static constexpr const char *NETWORK_REGISTER_EVENT = "NETWORK_REGISTER";
static constexpr const char *SET_DEFAULT_CELLULAR_DATA_EVENT = "SET_DEFAULT_CELLULAR_DATA";
static constexpr const char *SIM_STATE_CHANGE_EVENT = "SIM_STATE_CHANGE";

// KEY
static constexpr const char *SLOT_ID_KEY = "SLOT_ID";
static constexpr const char *SIGANL_LEVEL_KEY = "LEVEL";
static constexpr const char *NETWORK_DOMAIN_KEY = "REGISTRATION_DOMAIN";
static constexpr const char *NETWORK_TECH_KEY = "RADIO_TECH";
static constexpr const char *NETWORK_STATE_KEY = "REGISTRATION_STATE";
static constexpr const char *STATE_KEY = "STATE";

template<typename... Types>
void CoreServiceHiSysEvent::HiWriteEvent(const std::string &eventName, Types... args)
{
    OHOS::HiviewDFX::HiSysEvent::EventType type;
    if (eventName == SIGNAL_LEVEL_EVENT || eventName == NETWORK_REGISTER_EVENT || eventName == SIM_STATE_CHANGE_EVENT ||
        eventName == SET_DEFAULT_CELLULAR_DATA_EVENT) {
        type = HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
        OHOS::HiviewDFX::HiSysEvent::Write(DOMAIN_CORE_SERVICE, eventName, type, args...);
    } else {
        TELEPHONY_LOGE("CoreServiceHiSysEvent::HiWriteEvent the event name is not in the processing scope!");
        return;
    }
}

void CoreServiceHiSysEvent::SignalLevelBehaviorEvent(const int32_t slotId, const int32_t level)
{
    HiWriteEvent(SIGNAL_LEVEL_EVENT, SLOT_ID_KEY, slotId, SIGANL_LEVEL_KEY, level);
}

void CoreServiceHiSysEvent::NetworkStateBehaviorEvent(
    const int32_t slotId, const int32_t domain, const int32_t tech, const int32_t state)
{
    HiWriteEvent(NETWORK_REGISTER_EVENT, SLOT_ID_KEY, slotId, NETWORK_DOMAIN_KEY, domain, NETWORK_TECH_KEY, tech,
        NETWORK_STATE_KEY, state);
}

void CoreServiceHiSysEvent::DefaultDataSlotIdBehaviorEvent(const int32_t slotId)
{
    HiWriteEvent(SET_DEFAULT_CELLULAR_DATA_EVENT, SLOT_ID_KEY, slotId);
}

void CoreServiceHiSysEvent::SimStateBehaviorEvent(const int32_t slotId, const int32_t state)
{
    HiWriteEvent(SIM_STATE_CHANGE_EVENT, SLOT_ID_KEY, slotId, STATE_KEY, state);
}
} // namespace Telephony
} // namespace OHOS

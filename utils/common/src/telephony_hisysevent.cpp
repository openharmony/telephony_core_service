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

#include "telephony_hisysevent.h"
#include "hisysevent.h"

namespace OHOS {
namespace Telephony {
// CoreService HiSysEvent
const std::string CORE_SERVICE_DOMAIN = "CORE_SERVICE";
const std::string SLOT_ID = "SLOT_ID";
const std::string SIGNAL_STRENGTH_EVENT = "SIGNAL_LEVEL";
const std::string SIGANL_LEVEL = "LEVEL";
const std::string NETWORK_REGISTER_EVENT = "NETWORK_REGISTER";
const std::string NETWORK_DOMAIN = "REGISTRATION_DOMAIN";
const std::string NETWORK_TECH = "RADIO_TECH";
const std::string NETWORK_STATE = "REGISTRATION_STATE";

template<typename... Types>
static void WriteStatisticEvent(const std::string &domain, const std::string &eventType, Types... args)
{
    HiviewDFX::HiSysEvent::Write(domain, eventType, HiviewDFX::HiSysEvent::EventType::STATISTIC, args...);
}

void WriteSignalLevelHiSysEvent(const int32_t slotId, const int32_t level)
{
    WriteStatisticEvent(CORE_SERVICE_DOMAIN, SIGNAL_STRENGTH_EVENT, SLOT_ID, slotId, SIGANL_LEVEL, level);
}

void WriteNetworkStateHiSysEvent(const int32_t slotId, const int32_t domain, const int32_t tech, const int32_t state)
{
    WriteStatisticEvent(CORE_SERVICE_DOMAIN, NETWORK_REGISTER_EVENT,
        SLOT_ID, slotId, NETWORK_DOMAIN, domain, NETWORK_TECH, tech, NETWORK_STATE, state);
}
}  // namespace Telephony
}  // namespace OHOS
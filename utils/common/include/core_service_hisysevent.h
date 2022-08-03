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

#ifndef CORE_SERVICE_HISYSEVENT_H
#define CORE_SERVICE_HISYSEVENT_H

#include <string>

namespace OHOS {
namespace Telephony {
class CoreServiceHiSysEvent {
public:
    static void SignalLevelBehaviorEvent(const int32_t slotId, const int32_t level);
    static void NetworkStateBehaviorEvent(
        const int32_t slotId, const int32_t domain, const int32_t tech, const int32_t state);
    static void DefaultDataSlotIdBehaviorEvent(const int32_t slotId);
    static void SimStateBehaviorEvent(const int32_t slotId, const int32_t state);

private:
    template<typename... Types>
    static void HiWriteEvent(const std::string &eventName, Types... args);
};
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_HISYSEVENT_H

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

#include "telephony_hisysevent.h"

namespace OHOS {
namespace Telephony {
static const int32_t SWITCH_ON = 1;
static const int32_t SWITCH_OFF = 0;

enum class SmsMmsMessageType {
    SMS_SHORT_MESSAGE,
    MMS_SHORT_MESSAGE,
    CELL_BROAD_CAST,
    WAP_PUSH,
};

class CoreServiceHiSysEvent : public TelephonyHiSysEvent {
public:
    static void WriteSignalLevelBehaviorEvent(const int32_t slotId, const int32_t level);
    static void WriteNetworkStateBehaviorEvent(
        const int32_t slotId, const int32_t domain, const int32_t tech, const int32_t state);
    static void WriteDefaultDataSlotIdBehaviorEvent(const int32_t slotId);
    static void WriteSimStateBehaviorEvent(const int32_t slotId, const int32_t state);
    static void WriteDialCallFaultEvent(const int32_t slotId, const int32_t errCode, const std::string &desc);
    static void WriteAnswerCallFaultEvent(const int32_t slotId, const int32_t errCode, const std::string &desc);
    static void WriteHangUpFaultEvent(const int32_t slotId, const int32_t errCode, const std::string &desc);
    static void WriteSmsSendFaultEvent(
        const int32_t slotId, const SmsMmsMessageType type, const SmsMmsErrorCode errorCode, const std::string &desc);
    static void WriteSmsReceiveFaultEvent(
        const int32_t slotId, const SmsMmsMessageType type, const SmsMmsErrorCode errorCode, const std::string &desc);
    static void WriteDataActivateFaultEvent(const int32_t slotId, const int32_t switchState,
        const CellularDataErrorCode errorType, const std::string &errorMsg);
};
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_HISYSEVENT_H

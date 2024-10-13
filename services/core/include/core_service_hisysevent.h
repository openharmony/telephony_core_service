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
    static void WriteSignalLevelBehaviorEvent(int32_t slotId, int32_t level);
    static void WriteNetworkStateBehaviorEvent(int32_t slotId, int32_t domain, int32_t tech, int32_t state);
    static void WriteRadioStateBehaviorEvent(int32_t slotId, int32_t state);
    static void WriteDefaultDataSlotIdBehaviorEvent(int32_t slotId);
    static void WriteSimStateBehaviorEvent(int32_t slotId, int32_t state);
    static void WriteDialCallFaultEvent(int32_t slotId, int32_t errCode, const std::string &desc);
    static void WriteAnswerCallFaultEvent(int32_t slotId, int32_t errCode, const std::string &desc);
    static void WriteHangUpFaultEvent(int32_t slotId, int32_t errCode, const std::string &desc);
    static void WriteSmsSendFaultEvent(
        int32_t slotId, SmsMmsMessageType type, SmsMmsErrorCode errorCode, const std::string &desc);
    static void WriteSmsReceiveFaultEvent(
        int32_t slotId, SmsMmsMessageType type, SmsMmsErrorCode errorCode, const std::string &desc);
    static void WriteDataActivateFaultEvent(
        int32_t slotId, int32_t switchState, CellularDataErrorCode errorType, const std::string &errorMsg);
    static void WriteAirplaneModeChangeEvent(const int32_t enable);
    static void WriteSetActiveSimFaultEvent(int32_t slotId, SimCardErrorCode errorCode, const std::string &desc);
};
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_HISYSEVENT_H

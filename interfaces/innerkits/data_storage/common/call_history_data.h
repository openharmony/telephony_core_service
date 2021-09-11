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

#ifndef DATA_STORAGE_CALL_HISTORY_H
#define DATA_STORAGE_CALL_HISTORY_H

namespace OHOS {
namespace Telephony {
const std::string CALL_ID = "call_id";
const std::string PHONE_NUMBER = "phone_number";
const std::string CALL_TYPE = "call_type";
const std::string SESSION_TYPE = "session_type";
const std::string START_TIME = "start_time";
const std::string END_TIME = "end_time";
const std::string CALL_DURATION_TIME = "call_duration_time";
const std::string CALL_STATE = "call_state";
const std::string COUNTRY_CODE = "country_code";

struct CallHistoryInfo {
    int callId;
    std::string phoneNumber;
    int callType;
    int sessionType;
    std::string startTime;
    std::string endTime;
    long durationTime;
    int callState;
    std::string countryCode;
};

enum class SessionType : int { UNKNOWN = 0, CS, IMS, OTT };

enum class CallType : int { UNKNOWN = 0, INCOMING, CALLING };

enum class CallState : int { UNKNOWN = 0, REJECT, MISSED, ONLINE, PAUSE, COMPLETE };

const std::string uri = "dataability://telephony.callhistory";
} // namespace Telephony
} // namespace OHOS
#endif // DATA_STORAGE_CALL_HISTORY_H
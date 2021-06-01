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

#ifndef CALL_TYPES_H
#define CALL_TYPES_H

#include <cstdio>
#include <string>
#include <vector>
namespace OHOS {
const int kMaxNumberLen = 30;

// call state
enum TelCallStates {
    CALL_STATUS_ACTIVE = 0,
    CALL_STATUS_HOLDING,
    CALL_STATUS_DIALING,
    CALL_STATUS_ALERTING,
    CALL_STATUS_INCOMING,
    CALL_STATUS_WAITING,
    CALL_STATUS_DISCONNECTED,
    CALL_STATUS_DISCONNECTING,
    CALL_STATUS_IDLE,
};

// call type
enum CallType {
    TYPE_CS = 0, // CS
    TYPE_IMS = 1, // IMS
    TYPE_OTT = 2, // OTT
    TYPE_ERR_CALL = 3, // OTHER
};

// phone type
enum PhoneNetType {
    PHONE_TYPE_GSM = 1, // gsm
    PHONE_TYPE_CDMA = 2, // cdma
};

// call mode
enum class VedioStateType {
    TYPE_VOICE = 0, // Voice
    TYPE_VIDEO, // Video
};
} // namespace OHOS
#endif
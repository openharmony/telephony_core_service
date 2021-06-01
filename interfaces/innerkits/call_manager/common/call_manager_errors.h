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

#ifndef CALL_MANAGER_ERRORS_H
#define CALL_MANAGER_ERRORS_H
#include "../../../core_service/interfaces/innerkits/common/telephony_errors.h"
namespace OHOS {
namespace TelephonyCallManager {
enum {
    CALL_MANAGER_PHONENUM_NULL = CALL_MANAGER_ERR_OFFSET,
    CALL_MANAGER_DIAL_FAILED,
    CALL_MANAGER_ACCPET_FAILED,
    CALL_MANAGER_REJECT_FAILED,
    CALL_MANAGER_HOLD_FAILED,
    CALL_MANAGER_UNHOLD_FAILED,
    CALL_MANAGER_HANGUP_FAILED,
    CALL_MANAGER_NOT_NEW_STATE,
    CALL_MANAGER_DIAL_SCENE_INCORRECT,
    CALL_MANAGER_CREATE_CALL_OBJECT_FAIL,
    CALL_MANAGER_SETAUDIO_FAILED,
    CALL_MANAGER_CALL_NULL,
    CALL_MANAGER_CALL_EXIST,
    CALL_MANAGER_CALL_DISCONNECTED,
    CALL_MANAGER_PHONE_BEYOND,
    CALL_MANAGER_HAS_NEW_CALL,
    CALL_MANAGER_VIDEO_MODE_ERR,
    CALL_MANAGER_PHONENUM_INVALID,
    CALL_MANAGER_CALLID_INVALID,
};
} // namespace TelephonyCallManager
} // namespace OHOS
#endif // CALLMANAGER_ERRORS_H

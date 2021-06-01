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

#ifndef I_CALL_MANAGER_SERVICE_H
#define I_CALL_MANAGER_SERVICE_H
#include <cstdio>
#include <string>
#include <vector>

#include "iremote_broker.h"
#include "pac_map.h"

#include "call_manager_type.h"
#include "call_types.h"

namespace OHOS {
namespace TelephonyCallManager {
extern "C" {
enum TelephonyCallManagerSurfaceCode {
    INTERFACE_DIAL_CALL = 0,
    INTERFACE_ANSWER_CALL,
    INTERFACE_REJECT_CALL,
    INTERFACE_HOLD_CALL,
    INTERFACE_UNHOLD_CALL,
    INTERFACE_DISCONNECT_CALL,
    INTERFACE_SWAP_CALL,
    INTERFACE_SEPARATE_CONFERENCE,
    INTERFACE_JOIN_CONFERENCE,
    INTERFACE_COMBINE_CONFERENCE,
    INTERFACE_GET_MAIN_CALL_ID,
    INTERFACE_GET_SUB_CALL_ID_LIST,
    INTERFACE_GET_CALL_ID_LIST_FOR_CONFERENCE,
    INTERFACE_GET_PREDEFINE_REJECT_MESSAGES,
    INTERFACE_GETTRANSFER_NUMBER,
    INTERFACE_SETTRANSFER_NUMBER,
    INTERFACE_INVITE_TO_CONFERENCE,
    INTERFACE_KICKOUT_FROM_CONFERENCE,
    INTERFACE_LEAVE_CONFERENCE,
    INTERFACE_UPGRADE_CALL,
    INTERFACE_DOWNGRADE_CALL,
    INTERFACE_SET_VOLTE,
    INTERFACE_SET_WIFICALLING,
    INTERFACE_SET_WIFICALLING_MODE,
    INTERFACE_SET_VOLTE_STRONG_MODE,
    INTERFACE_START_DTMF,
    INTERFACE_STOP_DTMF,
    INTERFACE_SEND_DTMF,
    INTERFACE_SEND_DTMF_BUNCH,
    INTERFACE_HAS_INCALL,
    INTERFACE_IS_NEW_CALL_ALLOWED,
    INTERFACE_MUTE_RINGING,
    INTERFACE_GET_CALL_STATE,
    INTERFACE_IS_RINGING,
    INTERFACE_IS_IN_EMERGENCY_CALL,
    INTERFACE_CANCEL_MISSED_CALLS_NOTIFICATION,
    INTERFACE_SET_AUDIO_ROUTE,
    INTERFACE_SET_MUTED,
    INTERFACE_IS_VIDEO_CALLING_ENABLED,
    INTERFACE_HAS_VOICE_CAPABILITY,
    INTERFACE_CTRL_CAMERA,
    INTERFACE_SET_PREVIEW_WINDOW,
    INTERFACE_SET_DISPLAY_WINDOW,
    INTERFACE_SET_CAMERA_ZOOM,
    INTERFACE_SET_PAUSE_IMAGE,
    INTERFACE_SET_DEV_DIRECTION,
};
} // end extern

class ICallManagerService : public IRemoteBroker {
public:
    virtual ~ICallManagerService() = default;
    virtual int32_t DialCall(std::u16string number, AppExecFwk::PacMap &extras, int32_t &callId) = 0;
    virtual int32_t AcceptCall(int32_t callId, int32_t videoState) = 0;
    virtual int32_t RejectCall(int32_t callId, bool isSendSms, std::u16string content) = 0;
    virtual int32_t HangUpCall(int32_t callId) = 0;
    virtual int32_t GetCallState() = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ipc.ITelephonyCallManagerService");
};
} // namespace TelephonyCallManager
} // namespace OHOS
#endif // I_CALL_MANAGER_SERVICE_H
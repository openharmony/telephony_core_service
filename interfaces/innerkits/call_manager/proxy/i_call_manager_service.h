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

#include "call_manager_inner_type.h"
#include "cellular_call_types.h"
#include "i_call_ability_callback.h"

namespace OHOS {
namespace Telephony {
extern "C" {
enum TelephonyCallManagerSurfaceCode {
    INTERFACE_REGISTER_CALLBACK = 0,
    INTERFACE_DIAL_CALL,
    INTERFACE_ANSWER_CALL,
    INTERFACE_REJECT_CALL,
    INTERFACE_HOLD_CALL,
    INTERFACE_UNHOLD_CALL,
    INTERFACE_DISCONNECT_CALL,
    INTERFACE_GET_CALL_STATE,
    INTERFACE_SWAP_CALL,
    INTERFACE_HAS_CALL,
    INTERFACE_IS_NEW_CALL_ALLOWED,
    INTERFACE_IS_RINGING,
    INTERFACE_IS_EMERGENCY_CALL,
    INTERFACE_IS_EMERGENCY_NUMBER,
    INTERFACE_IS_FORMAT_NUMBER,
    INTERFACE_IS_FORMAT_NUMBER_E164,
    INTERFACE_COMBINE_CONFERENCE,
    INTERFACE_SEPARATE_CONFERENCE,
    INTERFACE_START_DTMF,
    INTERFACE_STOP_DTMF,
    INTERFACE_SEND_DTMF,
    INTERFACE_SEND_DTMF_BUNCH,
    INTERFACE_GET_CALL_WAITING,
    INTERFACE_SET_CALL_WAITING,
    INTERFACE_GET_CALL_RESTRICTION,
    INTERFACE_SET_CALL_RESTRICTION,
    INTERFACE_GET_CALL_TRANSFER,
    INTERFACE_SET_CALL_TRANSFER,
    INTERFACE_GET_MAINID,
    INTERFACE_GET_SUBCALL_LIST_ID,
    INTERFACE_GET_CALL_LIST_ID_FOR_CONFERENCE,
    INTERFACE_SET_MUTE,
    INTERFACE_MUTE_RINGER,
    INTERFACE_SET_AUDIO_DEVICE,
    INTERFACE_PLAY_DTMF,
};
} // end extern

class ICallManagerService : public IRemoteBroker {
public:
    virtual ~ICallManagerService() = default;
    virtual int32_t RegisterCallBack(const sptr<ICallAbilityCallback> &callback) = 0;
    virtual int32_t DialCall(std::u16string number, AppExecFwk::PacMap &extras) = 0;
    virtual int32_t AnswerCall(int32_t callId, int32_t videoState) = 0;
    virtual int32_t RejectCall(int32_t callId, bool rejectWithMessage, std::u16string textMessage) = 0;
    virtual int32_t HangUpCall(int32_t callId) = 0;
    virtual int32_t GetCallState() = 0;
    virtual int32_t HoldCall(int32_t callId) = 0;
    virtual int32_t UnHoldCall(int32_t callId) = 0;
    virtual int32_t SwitchCall(int32_t callId) = 0;
    virtual bool HasCall() = 0;
    virtual bool IsNewCallAllowed() = 0;
    virtual bool IsRinging() = 0;
    virtual bool IsInEmergencyCall() = 0;
    virtual int32_t StartDtmf(int32_t callId, char str) = 0;
    virtual int32_t SendDtmf(int32_t callId, char str) = 0;
    virtual int32_t StopDtmf(int32_t callId) = 0;
    virtual int32_t SendBurstDtmf(int32_t callId, std::u16string str, int32_t on, int32_t off) = 0;
    virtual int32_t GetCallWaiting(int32_t slotId) = 0;
    virtual int32_t SetCallWaiting(int32_t slotId, bool activate) = 0;
    virtual int32_t CombineConference(int32_t mainCallId) = 0;
    virtual bool IsEmergencyPhoneNumber(std::u16string &number, int32_t slotId) = 0;
    virtual int32_t FormatPhoneNumber(
        std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber) = 0;
    virtual int32_t FormatPhoneNumberToE164(
        std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber) = 0;
    virtual int32_t GetMainCallId(int32_t callId) = 0;
    virtual std::vector<std::u16string> GetSubCallIdList(int32_t callId) = 0;
    virtual std::vector<std::u16string> GetCallIdListForConference(int32_t callId) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ICallManagerService");
};
} // namespace Telephony
} // namespace OHOS

#endif // I_CALL_MANAGER_SERVICE_H
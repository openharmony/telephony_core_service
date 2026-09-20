/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
 
#ifndef VOIP_CALL_STATE_INFO_H
#define VOIP_CALL_STATE_INFO_H
 
#include <cstdint>
#include <string>
 
namespace OHOS {
namespace Telephony {
/**
 * @brief Public VoIP call type, combining media form and participant form.
 */
enum class VoIPCallType {
    /** Audio one-to-one call */
    VOICE_ONE_TO_ONE = 0,
    /** Video one-to-one call */
    VIDEO_ONE_TO_ONE = 1,
    /** Audio conference call */
    VOICE_CONFERENCE = 2,
    /** Video conference call */
    VIDEO_CONFERENCE = 3,
};
 
/**
 * @brief Public VoIP call state.
 */
enum class VoIPCallState {
    /** Idle state */
    IDLE = 0,
    /** Incoming call state */
    INCOMING = 1,
    /** Outgoing call state (call initiated but not yet dialing) */
    OUTGOING = 2,
    /** Dialing state */
    DIALING = 3,
    /** Answered state */
    ANSWERED = 4,
    /** Active/connected state */
    ACTIVE = 5,
    /** Holding state */
    HOLDING = 6,
    /** Disconnecting state */
    DISCONNECTING = 7,
    /** Disconnected state */
    DISCONNECTED = 8,
};
 
/**
 * @brief Public VoIP call state information exposed to third-party applications.
 *
 * Contains the minimal information set required by third-party wearable devices
 * to monitor VoIP call state changes.
 */
struct VoIPCallStateInfo {
    /** VoIP application name (bundle name of the VoIP app) */
    std::string appName = "";
    /** Contact name of the remote party */
    std::string contactName = "";
    /** Call type (media form + participant form) */
    VoIPCallType callType = VoIPCallType::VOICE_ONE_TO_ONE;
    /** Current call state */
    VoIPCallState callState = VoIPCallState::IDLE;
    /** Whether the VoIP app supports answering the current call as a voice call */
    bool isVoiceAnswerSupported = true;
};
} // namespace Telephony
} // namespace OHOS
#endif // VOIP_CALL_STATE_INFO_H
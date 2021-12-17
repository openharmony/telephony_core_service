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

#ifndef CALL_MANAGER_SERVICE_PROXY_H
#define CALL_MANAGER_SERVICE_PROXY_H

#include <cfloat>
#include <cstdio>
#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "pac_map.h"

#include "call_manager_inner_type.h"
#include "cellular_call_types.h"
#include "i_call_manager_service.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class CallManagerServiceProxy : public IRemoteProxy<ICallManagerService> {
public:
    /**
     * CallManagerServiceProxy
     *
     * @param impl
     */
    explicit CallManagerServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~CallManagerServiceProxy() = default;

    /**
     * register callback
     *
     * @param callback[in], callback function pointer
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RegisterCallBack(const sptr<ICallAbilityCallback> &callback, std::u16string &bundleName) override;

    /**
     * unregister callback
     *
     * @param bundleName[in], bundle name
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnRegisterCallBack(std::u16string &bundleName) override;

    /**
     * Call dial interface
     *
     * @param number[in], dial param.
     * @param extras[in], extras date.
     * @return Returns callId when the value is greater than zero, others on failure.
     */
    int32_t DialCall(std::u16string number, AppExecFwk::PacMap &extras) override;

    /**
     * Answer call
     *
     * @param callId[in], call id
     * @param videoState[in], 0: audio, 1: video
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t AnswerCall(int32_t callId, int32_t videoState) override;

    /**
     * Reject call
     *
     * @param callId[in], call id
     * @param rejectWithMessage[in], Whether to enter the reason for rejection,true:yes false:no
     * @param textMessage[in], The reason you reject the call
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RejectCall(int32_t callId, bool rejectWithMessage, std::u16string textMessage) override;

    /**
     * Disconnect call
     *
     * @param callId[in], call id
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUpCall(int32_t callId) override;

    /**
     * app get call state
     *
     * @return Returns call state.
     */
    int32_t GetCallState() override;

    /**
     * Hold call
     *
     * @param callId[in], call id
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HoldCall(int32_t callId) override;

    /**
     * UnHold call
     *
     * @param callId[in], call id
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnHoldCall(int32_t callId) override;

    /**
     * Switch call
     *
     * @param callId[in], call id
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchCall(int32_t callId) override;

    /**
     * Is there Call
     *
     * @return Returns TELEPHONY_SUCCESS on has call, others on there is no call.
     */
    bool HasCall() override;

    /**
     * Can I initiate a call
     *
     * @return Returns TELEPHONY_SUCCESS on can, others on there is not can.
     */
    bool IsNewCallAllowed() override;

    /**
     * Set mute state
     *
     * @param isMute[in], mute state
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetMuted(bool isMute) override;

    /**
     * Mute Ringer
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t MuteRinger() override;

    /**
     * Set audio device
     *
     * @param deviceType[in], audio device type
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetAudioDevice(AudioDevice deviceType) override;

    /**
     * Get ringing state
     *
     * @return Returns ringing state.
     */
    bool IsRinging() override;

    /**
     * Is there an emergency call
     *
     * @return Returns ture on Emergency call, false on No emergency call.
     */
    bool IsInEmergencyCall() override;

    /**
     * Play dtmf tone
     *
     * @param callId[in], call id
     * @param str[in], Characters sent
     * @return Returns 0 on success, others on failure.
     */
    int32_t StartDtmf(int32_t callId, char str) override;

    /**
     * Send dtmf
     *
     * @param callId[in], call id
     * @param str[in], Characters sent
     * @return Returns 0 on success, others on failure.
     */
    int32_t SendDtmf(int32_t callId, char str) override;

    /**
     * Stop dtmf tone
     *
     * @param callId[in], call id
     * @return Returns 0 on success, others on failure.
     */
    int32_t StopDtmf(int32_t callId) override;

    /**
     * Send dtmf string
     *
     * @param callId[in], call id
     * @param str[in], String sent
     * @param on  DTMF pulse width, the unit is milliseconds, default is 0.
     * @param off DTMF pulse interval, the unit is milliseconds, default is 0.
     * @return Returns 0 on success, others on failure.
     */
    int32_t SendBurstDtmf(int32_t callId, std::u16string str, int32_t on, int32_t off) override;

    /**
     * Get Call Waiting
     *
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallWaiting(int32_t slotId) override;

    /**
     * Set Call Waiting
     *
     * @param slotId
     * @param activate
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallWaiting(int32_t slotId, bool activate) override;

    /**
     * Get Call lRestriction
     *
     * @param slotId
     * @param type
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallRestriction(int32_t slotId, CallRestrictionType type) override;

    /**
     * Set Call lRestriction
     *
     * @param slotId
     * @param info
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallRestriction(int32_t slotId, CallRestrictionInfo &info) override;

    /**
     * Get Call Transfer
     *
     * @param slotId
     * @param CallTransferInfo
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallTransferInfo(int32_t slotId, CallTransferType type) override;

    /**
     * Set Call Transfer
     *
     * @param slotId
     * @param CallTransferInfo
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallTransferInfo(int32_t slotId, CallTransferInfo &info) override;

    /**
     * CombineConference
     *
     * @param callId[in], call id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t CombineConference(int32_t mainCallId) override;

    /**
     * SeparateConference
     *
     * @param callId[in], call id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SeparateConference(int32_t callId) override;

    /**
     * SetCallPreferenceMode
     *
     * @param CallPreferenceMode, mode
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallPreferenceMode(int32_t slotId, int32_t mode) override;

    /**
     * open or close Camera
     *
     * @param cameraId
     * @param callingPackage
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ControlCamera(std::u16string cameraId, std::u16string callingPackage) override;

    /**
     * Set Camera Preview Window
     *
     * @param window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPreviewWindow(VideoWindow &window) override;

    /**
     * set remote display video window
     *
     * @param window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDisplayWindow(VideoWindow &window) override;

    /**
     * Set Camera Zoom
     *
     * @param zoomRatio
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCameraZoom(float zoomRatio) override;

    /**
     * Set Pause Picture
     *
     * @param path
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPausePicture(std::u16string path) override;

    /**
     * Set Device Direction
     *
     * @param rotation
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDeviceDirection(int32_t rotation) override;

    bool IsEmergencyPhoneNumber(std::u16string &number, int32_t slotId, int32_t &errorCode) override;
    int32_t FormatPhoneNumber(
        std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber) override;
    int32_t FormatPhoneNumberToE164(
        std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber) override;
    int32_t GetMainCallId(int32_t callId) override;
    std::vector<std::u16string> GetSubCallIdList(int32_t callId) override;
    std::vector<std::u16string> GetCallIdListForConference(int32_t callId) override;
    int32_t CancelMissedCallsNotification(int32_t id) override;

private:
    static inline BrokerDelegator<CallManagerServiceProxy> delegator_;
    static constexpr HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_DOMAIN, "CallManager"};
};
} // namespace Telephony
} // namespace OHOS

#endif // CALL_MANAGER_SERVICE_PROXY_H

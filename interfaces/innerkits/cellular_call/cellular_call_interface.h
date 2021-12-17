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

#ifndef CELLULAR_CALL_INTERFACE_H
#define CELLULAR_CALL_INTERFACE_H

#include "cellular_call_types.h"
#include "i_call_status_callback.h"

namespace OHOS {
namespace Telephony {
class CellularCallInterface : public IRemoteBroker {
public:
    // operation type
    enum class OperationType : uint32_t {
        DIAL = 1,
        HANG_UP = 2,
        REJECT = 3,
        ANSWER = 4,
        HOLD_CALL = 5,
        UN_HOLD_CALL = 6,
        SWITCH_CALL = 7,
        EMERGENCY_CALL = 8,
        COMBINE_CONFERENCE = 9,
        SEPARATE_CONFERENCE = 10,
        START_DTMF = 11,
        STOP_DTMF = 12,
        SEND_DTMF = 13,
        SEND_DTMF_STRING = 14,
        SET_CALL_TRANSFER = 15,
        GET_CALL_TRANSFER = 16,
        SET_CALL_WAITING = 17,
        GET_CALL_WAITING = 18,
        SET_CALL_RESTRICTION = 19,
        GET_CALL_RESTRICTION = 20,
        REGISTER_CALLBACK = 21,
        UNREGISTER_CALLBACK = 22,
        CALL_SUPPLEMENT = 23,
        SET_CALL_PREFERENCE_MODE = 24,
        GET_CALL_PREFERENCE_MODE = 25,
        SET_LTE_IMS_SWITCH_STATUS = 26,
        GET_LTE_IMS_SWITCH_STATUS = 27,
        CTRL_CAMERA = 28,
        SET_PREVIEW_WINDOW = 29,
        SET_DISPLAY_WINDOW = 30,
        SET_CAMERA_ZOOM = 31,
        SET_PAUSE_IMAGE = 32,
        SET_DEVICE_DIRECTION = 33,
    };

    /**
     * Call management dial interface
     *
     * @param CellularCallInfo, dial param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Dial(const CellularCallInfo &callInfo) = 0;

    /**
     * HangUp.
     *
     * @param CellularCallInfo, HangUp param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t HangUp(const CellularCallInfo &callInfo) = 0;

    /**
     * Answer.
     *
     * @param CellularCallInfo, Answer param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Answer(const CellularCallInfo &callInfo) = 0;

    /**
     * Reject.
     *
     * @param CellularCallInfo, Reject param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t Reject(const CellularCallInfo &callInfo) = 0;

    /**
     * HoldCall.
     *
     * @param CellularCallInfo, Hold param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t HoldCall(const CellularCallInfo &callInfo) = 0;

    /**
     * UnHoldCall.
     *
     * @param CellularCallInfo, UnHold param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UnHoldCall(const CellularCallInfo &callInfo) = 0;

    /**
     * SwitchCall.
     *
     * @param CellularCallInfo, SwitchCall param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t SwitchCall(const CellularCallInfo &callInfo) = 0;

    /**
     * IsEmergencyPhoneNumber.
     *
     * @param phone number.
     * @param slotId.
     * @param error Code.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t IsEmergencyPhoneNumber(const std::string &phoneNum, int32_t slotId, int32_t &errorCode) = 0;

    /**
     * Merge into multiple calls
     *
     * @param CellularCallInfo, SwitchCall param.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t CombineConference(const CellularCallInfo &callInfo) = 0;

    /**
     * Separate Conference.
     *
     * @param CellularCallInfo, SwitchCall param.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SeparateConference(const CellularCallInfo &callInfo) = 0;

    /**
     * CallSupplement.
     *
     * @param CallSupplementType
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t CallSupplement(CallSupplementType type) = 0;

    /**
     * StartDtmf.
     *
     * @param Dtmf Code.
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t StartDtmf(char cDtmfCode, const CellularCallInfo &callInfo) = 0;

    /**
     * StopDtmf.
     *
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t StopDtmf(const CellularCallInfo &callInfo) = 0;

    /**
     * SendDtmf.
     *
     * @param Dtmf Code.
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SendDtmf(char cDtmfCode, const CellularCallInfo &callInfo) = 0;

    /**
     * Send Dtmf String.
     *
     * @param Dtmf Code string.
     * @param phoneNum.
     * @param switchOn.
     * @param switchOff.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SendDtmfString(
        const std::string &dtmfCodeStr, const std::string &phoneNum, int32_t switchOn, int32_t switchOff) = 0;

    /**
     * Set Call Transfer
     *
     * @param CallTransferInfo
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallTransferInfo(const CallTransferInfo &ctInfo, int32_t slotId) = 0;

    /**
     * Get Call Transfer
     *
     * @param CallTransferType
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t GetCallTransferInfo(CallTransferType type, int32_t slotId) = 0;

    /**
     * Set Call Waiting
     *
     * @param activate
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallWaiting(bool activate, int32_t slotId) = 0;

    /**
     * Get Call Waiting
     *
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t GetCallWaiting(int32_t slotId) = 0;

    /**
     * Set Call Restriction
     *
     * @param CallRestrictionInfo
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallRestriction(const CallRestrictionInfo &cRInfo, int32_t slotId) = 0;

    /**
     * Get Call Restriction
     *
     * @param CallRestrictionType
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t GetCallRestriction(CallRestrictionType facType, int32_t slotId) = 0;

    /**
     * Register CallBack
     *
     * @param sptr<ICallStatusCallback>
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback) = 0;

    /**
     * UnRegister CallBack
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UnRegisterCallManagerCallBack() = 0;

    /**
     * Set Call Preference Mode
     *
     * @param slotId
     * @param mode
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallPreferenceMode(int32_t slotId, int32_t mode) = 0;

    /**
     * Get Call Preference Mode
     *
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t GetCallPreferenceMode(int32_t slotId) = 0;

    /**
     * Set Lte Ims Switch Status
     *
     * @param slotId
     * @param active
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetLteImsSwitchStatus(int32_t slotId, bool active) = 0;

    /**
     * Get Lte Ims Switch Status
     *
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t GetLteImsSwitchStatus(int32_t slotId) = 0;

    /**
     * CtrlCamera
     *
     * @param cameraId
     * @param callingPackage
     * @param callingUid
     * @param callingPid
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t CtrlCamera(const std::u16string &cameraId, const std::u16string &callingPackage,
        int32_t callingUid, int32_t callingPid) = 0;

    /**
     * SetPreviewWindow
     *
     * @param x
     * @param y
     * @param z
     * @param width
     * @param height
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetPreviewWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height) = 0;

    /**
     * SetDisplayWindow
     *
     * @param x
     * @param y
     * @param z
     * @param width
     * @param height
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetDisplayWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height) = 0;

    /**
     * SetCameraZoom
     *
     * @param zoomRatio
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCameraZoom(float zoomRatio) = 0;

    /**
     * SetPauseImage
     *
     * @param path
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetPauseImage(const std::u16string &path) = 0;

    /**
     * SetDeviceDirection
     *
     * @param rotation
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetDeviceDirection(int32_t rotation) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.CellularCallInterface");
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_INTERFACE_H

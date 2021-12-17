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

#ifndef CELLULAR_CALL_PROXY_H
#define CELLULAR_CALL_PROXY_H

#include "cellular_call_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Telephony {
class CellularCallProxy : public IRemoteProxy<CellularCallInterface> {
public:
    /**
     * CellularCallProxy
     *
     * @param impl
     */
    explicit CellularCallProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<CellularCallInterface>(impl) {}

    ~CellularCallProxy() = default;

    /**
     * Call management dial interface
     *
     * @param CellularCallInfo, dial param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Dial(const CellularCallInfo &callInfo) override;

    /**
     * HangUp.
     *
     * @param CellularCallInfo, HangUp param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HangUp(const CellularCallInfo &callInfo) override;

    /**
     * Reject.
     *
     * @param CellularCallInfo, Reject param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Reject(const CellularCallInfo &callInfo) override;

    /**
     * Answer.
     *
     * @param CellularCallInfo, Answer param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t Answer(const CellularCallInfo &callInfo) override;

    /**
     * HoldCall.
     *
     * @param CellularCallInfo, Hold param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HoldCall(const CellularCallInfo &callInfo) override;

    /**
     * UnHoldCall.
     *
     * @param CellularCallInfo, UnHold param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnHoldCall(const CellularCallInfo &callInfo) override;

    /**
     * SwitchCall.
     *
     * @param CellularCallInfo, SwitchCall param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchCall(const CellularCallInfo &callInfo) override;

    /**
     * IsEmergencyPhoneNumber.
     *
     * @param phone number.
     * @param slotId.
     * @param error Code.
     * @return Is Urgent Call.
     */
    int32_t IsEmergencyPhoneNumber(const std::string &phoneNum, int32_t slotId, int32_t &errorCode) override;

    /**
     * Merge into multiple calls
     *
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t CombineConference(const CellularCallInfo &callInfo) override;

    /**
     * SeparateConference.
     *
     * @param std::string splitString
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SeparateConference(const CellularCallInfo &callInfo) override;

    /**
     * CallSupplement.
     *
     * @param CallSupplementType type
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t CallSupplement(CallSupplementType type) override;

    /**
     * StartDtmf.
     *
     * @param Dtmf Code.
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t StartDtmf(char cDtmfCode, const CellularCallInfo &callInfo) override;

    /**
     * StopDtmf.
     *
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t StopDtmf(const CellularCallInfo &callInfo) override;

    /**
     * SendDtmf.
     *
     * @param Dtmf Code.
     * @param CellularCallInfo.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SendDtmf(char cDtmfCode, const CellularCallInfo &callInfo) override;

    /**
     * Send Dtmf String.
     * @param Dtmf Code string.
     * @param phoneNum.
     * @param switchOn.
     * @param switchOff.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SendDtmfString(
        const std::string &dtmfCodeStr, const std::string &phoneNum, int32_t switchOn, int32_t switchOff) override;

    /**
     * Set Call Transfer
     *
     * @param CallTransferInfo
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallTransferInfo(const CallTransferInfo &cfInfo, int32_t slotId) override;

    /**
     * Inquire Call Transfer
     *
     * @param CallTransferType
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallTransferInfo(CallTransferType type, int32_t slotId) override;

    /**
     * Set Call Waiting
     *
     * @param activate
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallWaiting(bool activate, int32_t slotId) override;

    /**
     * Inquire Call Waiting
     *
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallWaiting(int32_t slotId) override;

    /**
     * Set Call Restriction
     *
     * @param CallRestrictionInfo
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallRestriction(const CallRestrictionInfo &crInfo, int32_t slotId) override;

    /**
     * Inquire Call Restriction
     *
     * @param CallRestrictionType
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallRestriction(CallRestrictionType facType, int32_t slotId) override;

    /**
     * RegisterCallManagerCallBack
     *
     * @param sptr<ICallStatusCallback>
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback) override;

    /**
     * UnRegister CallManager CallBack
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnRegisterCallManagerCallBack() override;

    /**
     * Set Call Preference Mode
     *
     * @param slotId
     * @param mode
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallPreferenceMode(int32_t slotId, int32_t mode) override;

    /**
     * Get Call Preference Mode
     *
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetCallPreferenceMode(int32_t slotId) override;

    /**
     * Set Lte Ims Switch Status
     *
     * @param slotId
     * @param active
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetLteImsSwitchStatus(int32_t slotId, bool active) override;

    /**
     * Get Lte Ims Switch Status
     *
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t GetLteImsSwitchStatus(int32_t slotId) override;

    /**
     * CtrlCamera
     *
     * @param cameraId
     * @param callingPackage
     * @param callingUid
     * @param callingPid
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t CtrlCamera(const std::u16string &cameraId, const std::u16string &callingPackage, int32_t callingUid,
        int32_t callingPid) override;

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
    int32_t SetPreviewWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height) override;

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
    int32_t SetDisplayWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height) override;

    /**
     * SetCameraZoom
     *
     * @param zoomRatio
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCameraZoom(float zoomRatio) override;

    /**
     * SetPauseImage
     *
     * @param path
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetPauseImage(const std::u16string &path) override;

    /**
     * SetDeviceDirection
     *
     * @param rotation
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetDeviceDirection(int32_t rotation) override;

private:
    const int32_t MAX_SIZE = 10;
    static inline BrokerDelegator<CellularCallProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_PROXY_H

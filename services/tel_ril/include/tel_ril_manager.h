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

#ifndef TEL_RIL_MANAGER_H
#define TEL_RIL_MANAGER_H

#include <iservice_registry.h>
#include <iservmgr_hdi.h>

#include "tel_ril_call.h"
#include "tel_ril_data.h"
#include "tel_ril_modem.h"
#include "tel_ril_network.h"
#include "tel_ril_sim.h"
#include "tel_ril_sms.h"
#include "hril_vendor_network_defs.h"

namespace OHOS {
namespace Telephony {
class TelRilManager : public OHOS::IPCObjectStub,
                      public ITelRilManager,
                      public std::enable_shared_from_this<TelRilManager> {
public:
    TelRilManager();
    ~TelRilManager();

    /**
     * @brief Oem Remote Request
     * @param code Number of retries remaining, must be equal to -1 if unknown
     * @param data is HDF service callback message
     * @param reply is HDF service callback message
     * @param option is HDF service callback message
     * @return int type
     */
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::MessageOption &option) override;
    void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId) override;

    /**
     * @brief Deal with the init_event,get ril_adapter service .
     */
    bool OnInit() override;

    /**
     * Send the request of CellularRadioIndication
     *
     * @return:Returns the value of the send_result.
     */
    int32_t SetCellularRadioIndication(bool isFirst);

    /**
     * Send the request of CellularRadioResponse
     *
     */
    int32_t SetCellularRadioResponse(bool isFirst);

    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) override;
    void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what) override;

    void SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetRadioState(const AppExecFwk::InnerEvent::Pointer &response) override;

    void ShutDown(const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief Get current Calls
     */
    void GetCallList(const AppExecFwk::InnerEvent::Pointer &result) override;

    /**
     * @brief Dial a call
     *
     * @param string address
     * @param int clirMode
     */
    void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result) override;

    /**
     * @brief  Reject the Call
     */
    void Reject(const AppExecFwk::InnerEvent::Pointer &result) override;

    /**
     *  @brief Hang up the call
     *
     *  @param :int32_t gsmIndex
     */
    void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result) override;

    void Answer(const AppExecFwk::InnerEvent::Pointer &result) override;

    void HoldCall(const AppExecFwk::InnerEvent::Pointer &result) override;

    void UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result) override;

    void SwitchCall(const AppExecFwk::InnerEvent::Pointer &result) override;

    void CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) override;

    void SeparateConference(
        int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) override;

    void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetCallWaiting(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetCallTransferInfo(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetCallTransferInfo(const int32_t reason, const int32_t mode, std::string number, const int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetClip(const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetClir(const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetCallRestriction(std::string &fac, int32_t mode, std::string &password,
        const AppExecFwk::InnerEvent::Pointer &result) override;
    void SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result) override;
    void SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) override;
    void StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) override;
    void StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetImei(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetMeid(const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetPsAttachStatus(int32_t psAttachStatus, const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetPhysicalChannelConfig(const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetLocateUpdates(HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response) override;
    /**
     * @brief  Send Sms
     */
    void SendGsmSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief  Send CDMA Sms
     */
    void SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief  Storage Sms
     */
    void AddSimMessage(int32_t status, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief  Delete Sms
     */
    void DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response) override;

    void UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetCBConfig(int32_t mode, std::string idList, std::string dcsList,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetCdmaCBConfig(
        CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetRadioCapability(
        RadioCapabilityInfo &radioCapabilityInfo, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief Send Sms ExpectMore
     */
    void SendSmsMoreMode(
        std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) override;
    void AddCdmaSimMessage(int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;
    void DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response) override;
    void UpdateCdmaSimMessage(int32_t cdmaIndex, int32_t state, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    /* PDP start */
    int32_t SetInitApnInfo(CellularDataProfile dataProfile, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t DeactivatePdpContext(
        int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetLinkBandwidthReportingRule(
        LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response) override;

    /* PDP end */

    /**
     * @brief Get IMSI
     *
     * @param :string aid
     */
    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimIO(SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetImsi(const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result) override;
    void ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result) override;
    void UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result) override;
    void UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result) override;
    void UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &result) override;
    void UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &result) override;
    void SendTerminalResponseCmd(
        const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) override;
    void SendEnvelopeCmd(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) override;
    void StkControllerIsReady(const AppExecFwk::InnerEvent::Pointer &response) override;
    void StkCmdCallSetup(int32_t flagAccept, const AppExecFwk::InnerEvent::Pointer &response) override;
    void UnlockSimLock(int32_t lockType, std::string password,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetPreferredNetwork(
        int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetImsCallList(const AppExecFwk::InnerEvent::Pointer &response) override;
    void SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &response) override;
    void SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &response) override;
    void SetRadioProtocol(SimProtocolRequest data, const AppExecFwk::InnerEvent::Pointer &response) override;
    void SetUssdCusd(const std::string str, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetUssdCusd(const AppExecFwk::InnerEvent::Pointer &response) override;
    void SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetMute(const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &response) override;
    void OpenLogicalSimIO(
        const std::string &appID, const int32_t p2, const AppExecFwk::InnerEvent::Pointer &response) override;
    void CloseLogicalSimIO(const int32_t chanID, const AppExecFwk::InnerEvent::Pointer &response) override;
    void TransmitApduSimIO(ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response) override;

    bool InitCellularRadio(bool isFirst) override;
    int32_t cdmaSubscription_ = 0;
    static const int INVALID_WAKELOCK = -1;
    static const int FOR_WAKELOCK = 0;
    static const int FOR_ACK_WAKELOCK = 1;
    static const int32_t RIL_INIT_COUNT_MAX = 10;

protected:
    int32_t preferredNetworkType_ = 0;
    void InitTelInfo() override;

private:
    /**
     * @brief Task schedule. The function of this function is to unify the input interface.
     * @param __result response handler
     * @param __module Sub module identification, used to print logs.
     *   This header file cannot use the typeid() keyword, so the module name is passed in.
     * @param template: __obj - Object type (this)pointer.
     * @param template: __func - Class member function address.
     * @param template: __args - The parameter list of the class member function except the response parameter.
     *    The number can vary.
     * @return true/false - success/fail
     */
    template<typename ResponsePtr, typename ClassTypePtr, typename FuncType, typename... ParamTypes>
    inline bool TaskSchedule(ResponsePtr &__result, const char *__module, ClassTypePtr &&__obj, FuncType &&__func,
        ParamTypes &&...__args) const
    {
        if (__obj != nullptr && __func != nullptr) {
            // The reason for using native member function access here is to
            //   remove std::unique_ptr to prevent copying.
            // The reason for not directly using pointers to access member functions is:
            //   __obj is a smart pointer, not a native pointer.
            ((*__obj).*(__func))(std::forward<ParamTypes>(__args)..., __result);
            return true;
        } else {
            PrintErrorLog(__module, (const uint8_t *)(__obj.get()), "null pointer");
            return false;
        }
    }

    /**
     * @brief print error log.
     * @param moduleName Module flag.
     * @param objPtr Object pointer.
     * @param param Additional parameters.
     * @return no
     */
    void PrintErrorLog(const char *moduleName, const uint8_t *objPtr, const char *param) const;

private:
    int32_t slotId_ = 0;
    std::mutex mutex_;
    static constexpr const char *RIL_ADAPTER_SERVICE_NAME = "cellular_radio1";
    static const int32_t RIL_ADAPTER_ERROR = 29189;
    std::shared_ptr<ObserverHandler> observerHandler_;
    sptr<IRemoteObject> cellularRadio_;
    std::unique_ptr<TelRilNetwork> telRilNetwork_;
    std::unique_ptr<TelRilModem> telRilModem_;
    std::unique_ptr<TelRilData> telRilData_;
    std::unique_ptr<TelRilSim> telRilSim_;
    std::unique_ptr<TelRilCall> telRilCall_;
    std::unique_ptr<TelRilSms> telRilSms_;
    sptr<OHOS::IPCObjectStub> telRilCallback_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_MANAGER_H

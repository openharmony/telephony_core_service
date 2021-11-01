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
#include "tel_ril_modem.h"
#include "tel_ril_network.h"
#include "tel_ril_call.h"
#include "tel_ril_data.h"
#include "tel_ril_sms.h"
#include "tel_ril_sim.h"

#define HDF_LOG_TAG "RilManagerHdf"
#define SAMPLE_WRITE_READ 123

namespace OHOS {
namespace Telephony {
class RilManager : public OHOS::IPCObjectStub, public IRilManager, public std::enable_shared_from_this<RilManager> {
public:
    RilManager();
    ~RilManager();

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
    void OnInit() override;

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

    void RegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) override;
    void UnRegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what) override;

    void SetRadioStatus(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetRadioStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

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

    void Hold(const AppExecFwk::InnerEvent::Pointer &result) override;

    void Active(const AppExecFwk::InnerEvent::Pointer &result) override;

    void Swap(const AppExecFwk::InnerEvent::Pointer &result) override;

    void Join(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) override;

    void Split(int32_t nThCall, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) override;

    void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetCallWait(const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetCallWait(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetCallForward(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) override;

    void SetCallForward(const int32_t reason, const int32_t mode, std::string number, const int32_t classx,
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

    void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetSlotIMEI(const AppExecFwk::InnerEvent::Pointer &response) override;
    /**
     * @brief  Send Sms
     */
    void SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief  Storage Sms
     */
    void StorageSms(int32_t status, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief  Delete Sms
     */
    void DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response) override;

    void UpdateSms(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetSmsCenterAddress(
        int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response) override;

    void SetCellBroadcast(int32_t mode, std::string idList, std::string dcsList,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    /**
     * @brief Send Sms ExpectMore
     */
    void SendSmsMoreMode(
        std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) override;

    void ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response) override;
    void DeactivatePdpContext(
        int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief Get IMSI
     *
     * @param :string aid
     */
    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result) override;
    void RequestSimIO(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3, std::string data,
        std::string path, const AppExecFwk::InnerEvent::Pointer &response) override;
    void GetImsi(const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetIccID(const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result) override;
    void ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result) override;
    void EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result) override;
    void UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result) override;

    void GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &result) override;
    void SetNetworkLocationUpdate(const AppExecFwk::InnerEvent::Pointer &response) override;
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

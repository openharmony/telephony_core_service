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
#ifndef RIL_MANAGER_H
#define RIL_MANAGER_H

#include <fcntl.h>
#include <iservice_registry.h>
#include <iservmgr_hdi.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <map>
#include <unordered_map>
#include "cellular_data_profile.h"
#include "observer_handler.h"
#include "i_tel_ril_manager.h"
#include "tel_ril_common.h"
#include "hril_types.h"
#include "tel_ril_modem.h"
#include "tel_ril_network.h"
#include "tel_ril_call.h"
#include "tel_ril_data.h"
#include "tel_ril_sms.h"
#include "tel_ril_sim.h"

#define HDF_LOG_TAG "RilManagerHdf"
#define SAMPLE_WRITE_READ 123
namespace OHOS {
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
    int OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
        OHOS::MessageOption &option) override;
    void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId) override;

    /**
     * @brief Deal with the init_event,get ril_adapter sevice .
     */
    void OnInit() override;

    /**
     * Send the request of CellularRadioIndication
     *
     * @return:Returns the value of the send_result.
     */
    int32_t SetCellularRadioIndication();

    /**
     * Send the request of CellularRadioResponse
     *
     */
    int32_t SetCellularRadioResponse();

    void RegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) override;
    void UnRegisterPhoneNotify(int what) override;

    void SetModemRadioPower(bool on, const AppExecFwk::InnerEvent::Pointer &response) override;
    void SetRadioPower(ModemPowerState radioState) override;
    ModemPowerState GetRadioState() override;
    void ShutDown(const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief Get current Calls
     */
    void GetCallList(const AppExecFwk::InnerEvent::Pointer &result) override;

    /**
     * @brief Dial a call
     */
    void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result) override;

    /**
     * @brief Calling Dial by UusInformation
     *
     * @param string address
     * @param int clirMode
     * @param UusInformation *uusInformation
     */
    void Dial(std::string address, int clirMode, struct UusInformation *uusInformation,
        const AppExecFwk::InnerEvent::Pointer &result);

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

    void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) override;

    void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @brief  Send Sms
     */
    void SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

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
    void GetImsi(std::string aid, const AppExecFwk::InnerEvent::Pointer &result) override;
    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result) override;
    void ReadIccFile(int32_t command, int32_t fileId, std::string path, int32_t p1, int32_t p2, int32_t p3,
        std::string data, std::string pin2, std::string aid,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    std::shared_ptr<ObserverHandler> observerHandler_;
    sptr<IRemoteObject> cellularRadio_;
    int32_t cdmaSubscription_;
    static const int INVALID_WAKELOCK = -1;
    static const int FOR_WAKELOCK = 0;
    static const int FOR_ACK_WAKELOCK = 1;

protected:
    int32_t preferredNetworkType_;
    void InitTelInfo() override;

private:
    int32_t phoneId_ = 0;
    std::mutex mutex_;
    static constexpr const char *RIL_ADAPTER_SERVICE_NAME = "cellular_radio1";
    static const int32_t RIL_ADAPTER_ERROR = 29189;
    std::unique_ptr<TelRilNetwork> telRilNetwork_;
    std::unique_ptr<TelRilModem> telRilModem_;
    std::unique_ptr<TelRilData> telRilData_;
    std::unique_ptr<TelRilSim> telRilSim_;
    std::unique_ptr<TelRilCall> telRilCall_;
    std::unique_ptr<TelRilSms> telRilSms_;
};
} // namespace OHOS
#endif

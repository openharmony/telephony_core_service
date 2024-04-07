/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <singleton.h>
#include <v1_3/iril.h>

#include "hdf_service_status_listener.h"
#include "i_tel_ril_manager.h"
#include "tel_ril_call.h"
#include "tel_ril_data.h"
#include "tel_ril_handler.h"
#include "tel_ril_modem.h"
#include "tel_ril_network.h"
#include "tel_ril_sim.h"
#include "tel_ril_sms.h"

namespace OHOS {
namespace Telephony {
class TelRilManager : public ITelRilManager, public std::enable_shared_from_this<TelRilManager> {
public:
    TelRilManager();
    ~TelRilManager() override = default;

    bool OnInit() override;
    bool DeInit();

    int32_t RegisterCoreNotify(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what, int32_t *obj) override;
    int32_t UnRegisterCoreNotify(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int32_t what) override;

    int32_t SetRadioState(
        int32_t slotId, int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetRadioState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t ShutDown(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetCallList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t Dial(
        int32_t slotId, std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t Reject(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t Hangup(int32_t slotId, int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t Answer(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t HoldCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t UnHoldCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SwitchCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t CombineConference(int32_t slotId, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SeparateConference(
        int32_t slotId, int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t CallSupplement(int32_t slotId, int32_t type, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t GetCallWaiting(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SetCallWaiting(
        int32_t slotId, const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t GetCallTransferInfo(
        int32_t slotId, const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SetCallTransferInfo(
        int32_t slotId, const CallTransferParam &callTransfer, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t GetClip(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SetClip(int32_t slotId, const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t GetClir(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SetClir(int32_t slotId, const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t GetCallRestriction(int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SetCallRestriction(int32_t slotId, const CallRestrictionParam &callRestriction,
        const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SetBarringPassword(int32_t slotId, const char *oldPassword, const char *newPassword,
        const std::string &restrictionType, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetVoNRSwitch(int32_t slotId, int32_t state, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SendDtmf(
        int32_t slotId, const DtmfParam &dtmfParam, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t SendDtmf(
        int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t StartDtmf(
        int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t StopDtmf(int32_t slotId, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t GetSignalStrength(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetCsRegStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetPsRegStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetOperatorInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetCellInfoList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetCurrentCellInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetImei(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetImeiSv(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetMeid(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetVoiceRadioTechnology(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetPhysicalChannelConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetLocateUpdates(
        int32_t slotId, HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @param slotId is the card slot index number
     * @param newFilter is the notification filter with bits in HRilNotificationFilter
     * @param response is the feedback info after setting notification filter
     * @return int32_t Indicates if notification filter is set successfully
     */
    int32_t SetNotificationFilter(
        int32_t slotId, int32_t newFilter, const AppExecFwk::InnerEvent::Pointer &response) override;

    /**
     * @param slotId is the card slot index number
     * @param deviceStateType is the device state type in HRilDeviceStateType
     * @param deviceStateOn Indicates the specific device state is on
     * @param response is the feedback info after setting device state
     * @return int32_t Indicates if device state is set successfully
     */
    int32_t SetDeviceState(int32_t slotId, int32_t deviceStateType, bool deviceStateOn,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetBasebandVersion(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetNrOptionMode(int32_t slotId, int32_t mode, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetNrOptionMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetRrcConnectionState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetNrSsbId(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SendGsmSms(
        int32_t slotId, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SendCdmaSms(int32_t slotId, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t AddSimMessage(
        int32_t slotId, const SimMessageParam &simMessage, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t DelSimMessage(int32_t slotId, int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t UpdateSimMessage(
        int32_t slotId, const SimMessageParam &simMessage, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetSmscAddr(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetCdmaCBConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetSmscAddr(
        int32_t slotId, int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetCBConfig(
        int32_t slotId, const CBConfigParam &cbConfig, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetCdmaCBConfig(int32_t slotId, CdmaCBConfigInfoList &cdmaCBConfigInfoList,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetCBConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;

    int32_t SendSmsMoreMode(
        int32_t slotId, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SendSmsAck(
        int32_t slotId, bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t AddCdmaSimMessage(
        int32_t slotId, int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t DelCdmaSimMessage(
        int32_t slotId, int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t UpdateCdmaSimMessage(int32_t slotId, const CdmaSimMessageParam &cdmaSimMsg,
        const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetInitApnInfo(
        int32_t slotId, const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t ActivatePdpContext(
        int32_t slotId, const ActivateDataParam &activeData, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t DeactivatePdpContext(
        int32_t slotId, int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetPdpContextList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetLinkBandwidthInfo(
        int32_t slotId, const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetLinkBandwidthReportingRule(
        int32_t slotId, LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetDataPermitted(
        int32_t slotId, int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetLinkCapability(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t CleanAllConnections(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetSimStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t GetSimIO(int32_t slotId, SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetImsi(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t GetSimLockStatus(int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t SetSimLock(
        int32_t slotId, const SimLockParam &simLock, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t ChangeSimPassword(
        int32_t slotId, const SimPasswordParam &simPassword, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t UnlockPin(int32_t slotId, const std::string &pin, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t UnlockPuk(int32_t slotId, const std::string &puk, const std::string &pin,
        const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t UnlockPin2(int32_t slotId, const std::string &pin2, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t UnlockPuk2(int32_t slotId, const std::string &puk2, const std::string &pin2,
        const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t SetActiveSim(
        int32_t slotId, int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t SendTerminalResponseCmd(
        int32_t slotId, const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SendEnvelopeCmd(
        int32_t slotId, const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SendCallSetupRequestResult(
        int32_t slotId, bool accept, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SimStkIsReady(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t UnlockSimLock(int32_t slotId, int32_t lockType, std::string password,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetRadioProtocol(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetRadioProtocol(
        int32_t slotId, RadioProtocol radioProtocol, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t GetNetworkSearchInformation(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t GetNetworkSelectionMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t automaticFlag, std::string oper,
        const AppExecFwk::InnerEvent::Pointer &result) override;
    int32_t SetPreferredNetwork(
        int32_t slotId, int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetPreferredNetwork(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;

    int32_t SetCallPreferenceMode(
        int32_t slotId, const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetCallPreferenceMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetUssd(int32_t slotId, const std::string str, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetUssd(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetMute(int32_t slotId, const int32_t mute, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetMute(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetEmergencyCallList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SetEmergencyCallList(int32_t slotId, const std::vector<EmergencyCall> &eccVec,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t GetCallFailReason(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SimOpenLogicalChannel(int32_t slotId, const std::string &appID, const int32_t p2,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SimCloseLogicalChannel(
        int32_t slotId, const int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SimTransmitApduLogicalChannel(
        int32_t slotId, const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SimTransmitApduBasicChannel(
        int32_t slotId, const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SimAuthentication(int32_t slotId, const SimAuthenticationRequestInfo &reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t SendSimMatchedOperatorInfo(int32_t slotId, const NcfgOperatorInfo &reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t CloseUnFinishedUssd(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) override;
    int32_t InitTelExtraModule(int32_t slotId) override;

    /**
     * Register hdf status listener
     *
     * @return:True is Register HdfStatusListener success, false is fail
     */
    bool RegisterHdfStatusListener();

    /**
     * UnRegister hdf status listener
     *
     * @return:True is UnRegister HdfStatusListener success, false is fail
     */
    bool UnRegisterHdfStatusListener();

    std::shared_ptr<TelRilSms> GetTelRilSms(int32_t slotId);
    std::shared_ptr<TelRilSim> GetTelRilSim(int32_t slotId);
    std::shared_ptr<TelRilCall> GetTelRilCall(int32_t slotId);
    std::shared_ptr<TelRilData> GetTelRilData(int32_t slotId);
    std::shared_ptr<TelRilNetwork> GetTelRilNetwork(int32_t slotId);
    std::shared_ptr<TelRilModem> GetTelRilModem(int32_t slotId);
    void SendAckAndLock(void);
    void ReduceRunningLock();
    void ReleaseRunningLock();

public:
    static const int32_t INVALID_WAKELOCK = -1;
    static const int32_t FOR_WAKELOCK = 0;
    static const int32_t FOR_ACK_WAKELOCK = 1;

private:
    void CreatTelRilHandler(void);
    int32_t SendResponseAck(void);
    void InitTelModule(int32_t slotId);
    bool ConnectRilInterface();
    bool ResetRilInterface(void);
    void HandleRilInterfaceStatusCallback(const OHOS::HDI::ServiceManager::V1_0::ServiceStatus &status);
    bool ReConnectRilInterface();
    bool DisConnectRilInterface();
    void ResetRilInterfaceBySlotId(int32_t slotId);

    std::shared_ptr<ObserverHandler> GetObserverHandler(int32_t slotId);

    /**
     * @brief Task schedule. The function of this function is to unify the input interface.
     * @param _result response handler
     * @param _module Sub module identification, used to print logs.
     *   This header file cannot use the typeid() keyword, so the module name is passed in.
     * @param template: _obj - Object type (this)pointer.
     * @param template: _func - Class member function address.
     * @param template: _args - The parameter list of the class member function except the response parameter.
     *    The number can vary.
     * @return true/false - success/fail
     */
    template<typename ResponsePtr, typename ClassTypePtr, typename FuncType, typename... ParamTypes>
    inline int32_t TaskSchedule(ResponsePtr &_result, const std::string _module, ClassTypePtr _obj, FuncType &&_func,
        ParamTypes &&... _args) const
    {
        if (_func != nullptr && _obj != nullptr) {
            // The reason for using native member function access here is to
            //   remove std::unique_ptr to prevent copying.
            // The reason for not directly using pointers to access member functions is:
            //   _obj is a smart pointer, not a native pointer.
            return (_obj.get()->*(_func))(std::forward<ParamTypes>(_args)..., _result);
        } else {
            TELEPHONY_LOGE("%{public}s - func: %{public}s", _module.c_str(), "null pointer");
            return HRIL_ERR_NULL_POINT;
        }
    }

private:
    std::mutex mutex_;
    std::vector<std::shared_ptr<TelRilSim>> telRilSim_;
    std::vector<std::shared_ptr<TelRilSms>> telRilSms_;
    std::vector<std::shared_ptr<TelRilCall>> telRilCall_;
    std::vector<std::shared_ptr<TelRilData>> telRilData_;
    std::vector<std::shared_ptr<TelRilModem>> telRilModem_;
    std::vector<std::shared_ptr<TelRilNetwork>> telRilNetwork_;
    std::vector<std::shared_ptr<ObserverHandler>> observerHandler_;
    std::shared_ptr<TelRilHandler> handler_ = nullptr;
    sptr<OHOS::HDI::ServiceManager::V1_0::IServiceManager> servMgr_ = nullptr;
    sptr<HdfServiceStatusListener::IServStatListener> hdfListener_ = nullptr;
    sptr<HDI::Ril::V1_3::IRil> rilInterface_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_MANAGER_H

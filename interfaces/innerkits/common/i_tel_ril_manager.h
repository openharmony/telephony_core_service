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

#ifndef I_TEL_RIL_MANAGER_H
#define I_TEL_RIL_MANAGER_H

#include "cellular_data_profile.h"
#include "event_runner.h"
#include "hril_types.h"

namespace OHOS {
namespace Telephony {
enum ModemPowerState { CORE_SERVICE_POWER_OFF, CORE_SERVICE_POWER_ON, CORE_SERVICE_POWER_NOT_AVAILABLE };

class IRilManager {
public:
    // RilBaseCommands
    virtual void OnInit() = 0;
    virtual void InitTelInfo() = 0;

    virtual void RegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) = 0;
    virtual void UnRegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what) = 0;

    virtual void SetRadioStatus(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetRadioStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void ShutDown(const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Reject(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Answer(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallList(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Hold(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Active(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Swap(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Join(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Split(int32_t nThCall, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallWait(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetCallWait(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallForward(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetCallForward(const int32_t reason, const int32_t mode, std::string number, const int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetClip(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetClir(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetCallRestriction(
        std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void DeactivatePdpContext(
        int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void StorageSms(
        int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void UpdateSms(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetSmsCenterAddress(
        int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetCellBroadcast(int32_t mode, std::string idList, std::string dcsList,
        const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendSmsMoreMode(
        std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void RequestSimIO(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3,
        std::string data, std::string path, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetImsi(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetIccID(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void ChangeSimPassword(std::string fac, std::string oldPasswd, std::string newPasswd,
        int32_t pwdLength, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual void GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SetNetworkLocationUpdate(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSlotIMEI(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId) = 0;
    virtual bool InitCellularRadio(bool isFirst) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_TEL_RIL_MANAGER_H

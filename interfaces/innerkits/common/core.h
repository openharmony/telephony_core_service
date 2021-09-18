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

#ifndef IMPL_CORE_H
#define IMPL_CORE_H

#include <unistd.h>
#include <thread>
#include "i_network_search.h"
#include "i_sim_file_manager.h"
#include "i_sim_state_manager.h"
#include "i_sim_sms_manager.h"
#include "i_tel_ril_manager.h"
#include "i_sim_manager.h"
#include "observer_handler.h"

namespace OHOS {
namespace Telephony {
const int NUM_CIRCLES = 4;

class Core {
public:
    Core(int opt);

    ~Core() = default;

    void OnInit();
    bool IsInitCore();

    void InitTelInfo();

    void RegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj);
    void UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);

    void SetRadioStatus(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response);
    void GetRadioStatus(const AppExecFwk::InnerEvent::Pointer &response);
    void ShutDown(const AppExecFwk::InnerEvent::Pointer &response);

    void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result);
    void DialIms(const AppExecFwk::InnerEvent::Pointer &result);
    void Reject(const AppExecFwk::InnerEvent::Pointer &result);
    void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result);
    void Answer(const AppExecFwk::InnerEvent::Pointer &result);
    void GetCallList(const AppExecFwk::InnerEvent::Pointer &result);
    void Hold(const AppExecFwk::InnerEvent::Pointer &result);
    void Active(const AppExecFwk::InnerEvent::Pointer &result);
    void Swap(const AppExecFwk::InnerEvent::Pointer &result);
    void Join(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);
    void Split(int32_t nThCall, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);
    void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result);
    void GetClip(const AppExecFwk::InnerEvent::Pointer &result);
    void SetClip(int32_t action, const AppExecFwk::InnerEvent::Pointer &result);
    void GetClir(const AppExecFwk::InnerEvent::Pointer &result);
    void SetClir(int32_t action, const AppExecFwk::InnerEvent::Pointer &result);
    void SetCallWait(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result);
    void SetCallForward(int32_t reason, int32_t mode, std::string number, int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result);
    void GetCallForward(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result);
    void GetCallWait(const AppExecFwk::InnerEvent::Pointer &result);
    void GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result);
    void SetCallRestriction(
        std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result);
    void ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response);
    void StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result);
    void DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response);

    void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response);
    void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPsRadioTech(int32_t slotId);
    int32_t GetCsRadioTech(int32_t slotId);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId);
    std::u16string GetOperatorNumeric(int32_t slotId);
    std::u16string GetOperatorName(int32_t slotId);
    sptr<NetworkState> GetNetworkStatus(int32_t slotId);
    bool SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback);
    bool GetRadioState(const sptr<INetworkSearchCallback> &callback);
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId);
    bool GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    void RegisterIccStateChanged(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void RegisterImsiLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void RegisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t ObtainSpnCondition(bool roaming, std::string operatorNum);
    std::u16string GetSpn(int32_t slotId);
    void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response);

    void SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void StorageSms(
        int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    void GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response);

    void SetSmsCenterAddress(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response);

    void DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response);
    void SendSmsMoreMode(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);

    void SetCellBroadcast(
        int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response);

    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result);
    void ReadIccFile(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3, std::string data,
        std::string path, const AppExecFwk::InnerEvent::Pointer &response);
    void GetImsi(const AppExecFwk::InnerEvent::Pointer &result);
    void GetIccID(const AppExecFwk::InnerEvent::Pointer &result);
    void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result);
    void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result);
    void ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result);
    void EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result);
    void UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result);
    void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result);
    void GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response);
    void GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response);
    void SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response);
    void SetNetworkLocationUpdate(const AppExecFwk::InnerEvent::Pointer &result);
    void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId);
    bool InitCellularRadio(bool isFirst);
    std::shared_ptr<INetworkSearch> GetNetworkSearchManager() const;
    std::shared_ptr<IRilManager> GetRilManager() const;
    std::shared_ptr<ISimFileManager> GetSimFileManager() const;
    std::shared_ptr<ISimStateManager> GetSimStateManager() const;
    std::shared_ptr<ISimSmsManager> GetSimSmsManager() const;
    std::shared_ptr<ISimManager> GetSimManager() const;

private:
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
    std::shared_ptr<IRilManager> rilManager_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<ISimSmsManager> simSmsManager_ = nullptr;
    std::shared_ptr<ISimManager> simManager_ = nullptr;
    int slotId_;
    bool isInitCore_;
};
} // namespace Telephony
} // namespace OHOS
#endif

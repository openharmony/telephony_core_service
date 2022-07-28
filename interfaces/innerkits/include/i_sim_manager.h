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

#ifndef OHOS_I_SIM_MANAGER_H
#define OHOS_I_SIM_MANAGER_H

#include "dialling_numbers_info.h"
#include "i_network_search.h"
#include "operator_config_types.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
class ISimManager {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    // Init
    virtual bool OnInit(int32_t slotCount) = 0;
    virtual void SetNetworkSearchManager(int32_t slotCount, std::shared_ptr<INetworkSearch> networkSearchManager) = 0;
    // SimState
    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual int32_t GetSimState(int32_t slotId) = 0;
    virtual int32_t GetCardType(int32_t slotId) = 0;
    virtual bool UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response) = 0;
    virtual bool UnlockPuk(int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response) = 0;
    virtual bool AlterPin(int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response) = 0;
    virtual bool SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) = 0;
    virtual int32_t GetLockState(int32_t slotId, LockType lockType) = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    virtual bool UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response) = 0;
    virtual bool UnlockPuk2(
        int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response) = 0;
    virtual bool AlterPin2(
        int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response) = 0;
    virtual bool UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) = 0;
    // SimAccount
    virtual bool IsSimActive(int32_t slotId) = 0;
    virtual bool SetActiveSim(int32_t slotId, int32_t enable) = 0;
    virtual bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) = 0;
    virtual bool SetDefaultVoiceSlotId(int32_t slotId) = 0;
    virtual bool SetDefaultSmsSlotId(int32_t slotId) = 0;
    virtual bool SetDefaultCellularDataSlotId(int32_t slotId) = 0;
    virtual bool SetPrimarySlotId(int32_t slotId) = 0;
    virtual bool SetShowNumber(int32_t slotId, const std::u16string number) = 0;
    virtual bool SetShowName(int32_t slotId, const std::u16string name) = 0;
    virtual int32_t GetDefaultVoiceSlotId() = 0;
    virtual int32_t GetDefaultSmsSlotId() = 0;
    virtual int32_t GetDefaultCellularDataSlotId() = 0;
    virtual int32_t GetPrimarySlotId() = 0;
    virtual std::u16string GetShowNumber(int32_t slotId) = 0;
    virtual std::u16string GetShowName(int32_t slotId) = 0;
    virtual bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) = 0;
    virtual bool GetOperatorConfigs(int slotId, OperatorConfig &poc) = 0;
    virtual bool HasOperatorPrivileges(const int32_t slotId) = 0;
    virtual int32_t SimAuthentication(
        int32_t slotId, const std::string &aid, const std::string &authData, SimAuthenticationResponse &response) = 0;
    // STK
    virtual bool SendEnvelopeCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual bool SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) = 0;
    // SimFile
    virtual std::u16string GetSimOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetISOCountryCodeForSim(int32_t slotId) = 0;
    virtual std::u16string GetSimSpn(int32_t slotId) = 0;
    virtual std::u16string GetSimIccId(int32_t slotId) = 0;
    virtual std::u16string GetIMSI(int32_t slotId) = 0;
    virtual std::u16string GetLocaleFromDefaultSim(int32_t slotId) = 0;
    virtual std::u16string GetSimGid1(int32_t slotId) = 0;
    virtual std::u16string GetSimGid2(int32_t slotId) = 0;
    virtual std::u16string GetOpName(int32_t slotId) = 0;
    virtual std::u16string GetOpKey(int32_t slotId) = 0;
    virtual std::u16string GetOpKeyExt(int32_t slotId) = 0;
    virtual std::u16string GetSimTelephoneNumber(int32_t slotId) = 0;
    virtual std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) = 0;
    virtual std::u16string GetVoiceMailIdentifier(int32_t slotId) = 0;
    virtual std::u16string GetVoiceMailNumber(int32_t slotId) = 0;
    virtual int ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum) = 0;
    virtual bool SetVoiceMailInfo(
        int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) = 0;
    virtual std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) = 0;
    // SimSms
    virtual bool AddSmsToIcc(int32_t slotId, int status, std::string &pdu, std::string &smsc) = 0;
    virtual bool UpdateSmsIcc(int32_t slotId, int index, int status, std::string &pduData, std::string &smsc) = 0;
    virtual bool DelSmsIcc(int32_t slotId, int index) = 0;
    virtual std::vector<std::string> ObtainAllSmsOfIcc(int32_t slotId) = 0;
    // IccDiallingNumbers
    virtual std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type) = 0;
    virtual bool AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual bool DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    // Event register
    virtual void RegisterCoreNotify(int32_t slotId, const HANDLE &handler, int what) = 0;
    virtual void UnRegisterCoreNotify(int32_t slotId, const HANDLE &observerCallBack, int what) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_I_SIM_MANAGER_H
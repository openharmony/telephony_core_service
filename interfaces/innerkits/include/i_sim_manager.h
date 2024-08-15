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

#ifndef OHOS_I_SIM_MANAGER_H
#define OHOS_I_SIM_MANAGER_H

#include "dialling_numbers_info.h"
#include "event_handler.h"
#include "operator_config_types.h"
#include "sim_account_callback.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
class ISimManager {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    // Init
    virtual bool OnInit(int32_t slotCount) = 0;
    virtual int32_t InitTelExtraModule(int32_t slotId) = 0;
    // SimState
    virtual int32_t HasSimCard(int32_t slotId, bool &hasSimCard) = 0;
    virtual int32_t GetSimState(int32_t slotId, SimState &simState) = 0;
    virtual int32_t GetSimIccStatus(int32_t slotId, IccSimStatus &iccStatus) = 0;
    virtual int32_t GetCardType(int32_t slotId, CardType &cardType) = 0;
    virtual int32_t SetModemInit(int32_t slotId, bool state) = 0;
    virtual int32_t UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response) = 0;
    virtual int32_t UnlockPuk(
        int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response) = 0;
    virtual int32_t AlterPin(
        int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response) = 0;
    virtual int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) = 0;
    virtual int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState) = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    virtual int32_t UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response) = 0;
    virtual int32_t UnlockPuk2(
        int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response) = 0;
    virtual int32_t AlterPin2(
        int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response) = 0;
    virtual int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) = 0;
    // SimAccount
    virtual bool IsSimActive(int32_t slotId) = 0;
    virtual int32_t SetActiveSim(int32_t slotId, int32_t enable) = 0;
    virtual int32_t GetSimAccountInfo(int32_t slotId, bool denied, IccAccountInfo &info) = 0;
    virtual int32_t SetDefaultVoiceSlotId(int32_t slotId) = 0;
    virtual int32_t SetDefaultSmsSlotId(int32_t slotId) = 0;
    virtual int32_t SetDefaultCellularDataSlotId(int32_t slotId) = 0;
    virtual int32_t SetPrimarySlotId(int32_t slotId) = 0;
    virtual int32_t SetShowNumber(int32_t slotId, const std::u16string &number) = 0;
    virtual int32_t SetShowName(int32_t slotId, const std::u16string &name) = 0;
    virtual int32_t GetDefaultVoiceSlotId() = 0;
    virtual int32_t GetDefaultVoiceSimId(int32_t &simId) = 0;
    virtual int32_t GetDefaultSmsSlotId() = 0;
    virtual int32_t GetDefaultSmsSimId(int32_t &simId) = 0;
    virtual int32_t GetDefaultCellularDataSlotId() = 0;
    virtual int32_t GetDefaultCellularDataSimId(int32_t &simId) = 0;
    virtual int32_t RegisterSimAccountCallback(
        const int32_t tokenId, const sptr<SimAccountCallback> &callback) = 0;
    virtual int32_t UnregisterSimAccountCallback(const int32_t tokenId) = 0;
    virtual int32_t GetPrimarySlotId(int32_t &slotId) = 0;
    virtual int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber) = 0;
    virtual int32_t GetShowName(int32_t slotId, std::u16string &showName) = 0;
    virtual int32_t GetActiveSimAccountInfoList(bool denied, std::vector<IccAccountInfo> &iccAccountInfoList) = 0;
    virtual int32_t GetOperatorConfigs(int slotId, OperatorConfig &poc) = 0;
    virtual int32_t UpdateOperatorConfigs(int32_t slotId) = 0;
    virtual int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges) = 0;
    virtual int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response) = 0;
    virtual int32_t GetRadioProtocolTech(int32_t slotId) = 0;
    virtual void GetRadioProtocol(int32_t slotId) = 0;
    virtual int32_t GetDsdsMode(int32_t &dsdsMode) = 0;
    virtual int32_t SetDsdsMode(int32_t dsdsMode) = 0;
    virtual int32_t SendSimMatchedOperatorInfo(
        int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey) = 0;
    // STK
    virtual int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual int32_t SendCallSetupRequestResult(int32_t slotId, bool accept) = 0;
    // SimFile
    virtual int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric) = 0;
    virtual int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode) = 0;
    virtual int32_t GetSimSpn(int32_t slotId, std::u16string &spn) = 0;
    virtual int32_t GetSimIccId(int32_t slotId, std::u16string &iccId) = 0;
    virtual int32_t GetIMSI(int32_t slotId, std::u16string &imsi) = 0;
    virtual std::u16string GetLocaleFromDefaultSim(int32_t slotId) = 0;
    virtual int32_t GetSlotId(int32_t simId) = 0;
    virtual int32_t GetSimId(int32_t slotId) = 0;
    virtual int32_t GetSimGid1(int32_t slotId, std::u16string &gid1) = 0;
    virtual std::u16string GetSimGid2(int32_t slotId) = 0;
    virtual int32_t GetOpName(int32_t slotId, std::u16string &opname) = 0;
    virtual int32_t GetOpKey(int32_t slotId, std::u16string &opkey) = 0;
    virtual int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt) = 0;
    virtual int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber) = 0;
    virtual std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) = 0;
    virtual int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier) = 0;
    virtual int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber) = 0;
    virtual int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount) = 0;
    virtual int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount) = 0;
    virtual int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number) = 0;
    virtual std::u16string GetSimIst(int32_t slotId) = 0;
    virtual int ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum) = 0;
    virtual int32_t SetVoiceMailInfo(
        int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) = 0;
    virtual std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) = 0;
    virtual int32_t IsCTSimCard(int32_t slotId, bool &isCTSimCard) = 0;
    // SimSms
    virtual int32_t AddSmsToIcc(int32_t slotId, int status, std::string &pdu, std::string &smsc) = 0;
    virtual int32_t UpdateSmsIcc(int32_t slotId, int index, int status, std::string &pduData, std::string &smsc) = 0;
    virtual int32_t DelSmsIcc(int32_t slotId, int index) = 0;
    virtual std::vector<std::string> ObtainAllSmsOfIcc(int32_t slotId) = 0;
    // IccDiallingNumbers
    virtual int32_t QueryIccDiallingNumbers(
        int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result) = 0;
    virtual int32_t AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual int32_t DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual int32_t UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    // Event register
    virtual void RegisterCoreNotify(int32_t slotId, const HANDLE &handler, int what) = 0;
    virtual void UnRegisterCoreNotify(int32_t slotId, const HANDLE &observerCallBack, int what) = 0;
    // Ims Switch
    virtual int32_t SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue) = 0;
    virtual int32_t QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue) = 0;

    virtual bool IsSetActiveSimInProgress(int32_t slotId) = 0;
    virtual bool IsSetPrimarySlotIdInProgress() = 0;
    virtual int32_t GetSimIO(int32_t slotId, int32_t command,
        int32_t fileId, const std::string &data, const std::string &path, SimAuthenticationResponse &response) = 0;
    virtual int32_t SavePrimarySlotId(int32_t slotId) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_I_SIM_MANAGER_H

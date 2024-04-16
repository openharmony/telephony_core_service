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

#ifndef OHOS_SIM_MANAGER_H
#define OHOS_SIM_MANAGER_H

#include "event_handler.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "multi_sim_controller.h"
#include "multi_sim_monitor.h"
#include "sim_state_manager.h"
#include "sim_file_manager.h"
#include "sim_sms_manager.h"
#include "sim_account_manager.h"
#include "icc_dialling_numbers_manager.h"
#include "stk_manager.h"

namespace OHOS {
namespace Telephony {
const int32_t SLOT_ID_ZERO = 0;
class SimManager : public ISimManager {
public:
    explicit SimManager(std::shared_ptr<ITelRilManager> telRilManager);
    virtual ~SimManager();
    // Init
    bool OnInit(int32_t slotCount) override;
    int32_t InitTelExtraModule(int32_t slotId) override;
    // SimState
    int32_t HasSimCard(int32_t slotId, bool &hasSimCard) override;
    int32_t GetSimState(int32_t slotId, SimState &simState) override;
    int32_t GetCardType(int32_t slotId, CardType &cardType) override;
    int32_t SetModemInit(int32_t slotId, bool state) override;
    int32_t UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response) override;
    int32_t UnlockPuk(
        int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response) override;
    int32_t AlterPin(
        int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response) override;
    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) override;
    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState) override;
    int32_t RefreshSimState(int32_t slotId) override;
    int32_t UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response) override;
    int32_t UnlockPuk2(
        int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response) override;
    int32_t AlterPin2(
        int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response) override;
    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) override;
    // SimAccount
    bool IsSimActive(int32_t slotId) override;
    int32_t SetActiveSim(int32_t slotId, int32_t enable) override;
    int32_t GetSimAccountInfo(int32_t slotId, bool denied, IccAccountInfo &info) override;
    int32_t SetDefaultVoiceSlotId(int32_t slotId) override;
    int32_t SetDefaultSmsSlotId(int32_t slotId) override;
    int32_t SetDefaultCellularDataSlotId(int32_t slotId) override;
    int32_t SetPrimarySlotId(int32_t slotId) override;
    int32_t SetShowNumber(int32_t slotId, const std::u16string &number) override;
    int32_t SetShowName(int32_t slotId, const std::u16string &name) override;
    int32_t GetDefaultVoiceSlotId() override;
    int32_t GetDefaultVoiceSimId(int32_t &simId) override;
    int32_t GetDefaultSmsSlotId() override;
    int32_t GetDefaultSmsSimId(int32_t &simId) override;
    int32_t GetDefaultCellularDataSlotId() override;
    int32_t GetDefaultCellularDataSimId(int32_t &simId) override;
    int32_t GetPrimarySlotId(int32_t &slotId) override;
    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber) override;
    int32_t GetShowName(int32_t slotId, std::u16string &showName) override;
    int32_t GetSlotId(int32_t simId) override;
    int32_t GetSimId(int32_t slotId) override;
    int32_t GetActiveSimAccountInfoList(bool denied, std::vector<IccAccountInfo> &iccAccountInfoList) override;
    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) override;
    int32_t UpdateOperatorConfigs(int32_t slotId) override;
    int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges) override;
    int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response) override;
    int32_t GetRadioProtocolTech(int32_t slotId) override;
    void GetRadioProtocol(int32_t slotId) override;
    int32_t GetDsdsMode(int32_t &dsdsMode) override;
    int32_t SetDsdsMode(int32_t dsdsMode) override;
    int32_t SendSimMatchedOperatorInfo(
        int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey) override;
    // STK
    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd) override;
    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) override;
    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept) override;
    // SimFile
    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric) override;
    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode) override;
    int32_t GetSimSpn(int32_t slotId, std::u16string &spn) override;
    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) override;
    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId) override;
    int32_t GetIMSI(int32_t slotId, std::u16string &imsi) override;
    std::u16string GetLocaleFromDefaultSim(int32_t slotId) override;
    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1) override;
    std::u16string GetSimGid2(int32_t slotId) override;
    int32_t GetOpName(int32_t slotId, std::u16string &opname) override;
    int32_t GetOpKey(int32_t slotId, std::u16string &opkey) override;
    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt) override;
    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber) override;
    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber) override;
    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount) override;
    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount) override;
    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number) override;
    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier) override;
    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) override;
    std::u16string GetSimIst(int32_t slotId) override;
    int ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum) override;
    int32_t SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) override;
    int32_t IsCTSimCard(int32_t slotId, bool &isCTSimCard) override;
    // SimSms
    int32_t AddSmsToIcc(int32_t slotId, int status, std::string &pdu, std::string &smsc) override;
    int32_t UpdateSmsIcc(
        int32_t slotId, int index, int status, std::string &pduData, std::string &smsc) override;
    int32_t DelSmsIcc(int32_t slotId, int index) override;
    std::vector<std::string> ObtainAllSmsOfIcc(int32_t slotId) override;
    // IccDiallingNumbers
    int32_t AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;
    int32_t DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;
    int32_t UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;
    int32_t QueryIccDiallingNumbers(
        int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result) override;
    // Event register
    void RegisterCoreNotify(int32_t slotId, const HANDLE &handler, int what) override;
    void UnRegisterCoreNotify(int32_t slotId, const HANDLE &observerCallBack, int what) override;
    // Ims Switch
    int32_t SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue) override;
    int32_t QueryImsSwitch(int32_t, int32_t &imsSwitchValue) override;
    int32_t RegisterSimAccountCallback(
        const int32_t tokenId, const sptr<SimAccountCallback> &callback) override;
    int32_t UnregisterSimAccountCallback(const int32_t tokenId) override;

    bool IsSetActiveSimInProgress(int32_t slotId) override;
    bool IsSetPrimarySlotIdInProgress() override;
    int32_t GetSimIO(int32_t slotId, int32_t command, int32_t fileId,
        const std::string &data, const std::string &path, SimAuthenticationResponse &response) override;

private:
    bool IsValidSlotId(int32_t slotId);
    template<class N>
    bool IsValidSlotId(int32_t slotId, std::vector<N> vec);
    bool IsValidAuthType(AuthType authType);
    bool IsValidSlotIdForDefault(int32_t slotId);
    void InitMultiSimObject();
    void InitSingleSimObject();
    void InitBaseManager(int32_t slotId);
    bool HasSimCardInner(int32_t slotId);

private:
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_;
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    std::vector<std::shared_ptr<Telephony::SimSmsManager>> simSmsManager_;
    std::vector<std::shared_ptr<Telephony::SimAccountManager>> simAccountManager_;
    std::vector<std::shared_ptr<Telephony::IccDiallingNumbersManager>> iccDiallingNumbersManager_;
    std::vector<std::shared_ptr<Telephony::StkManager>> stkManager_;
    std::shared_ptr<MultiSimController> multiSimController_ = nullptr;
    std::shared_ptr<MultiSimMonitor> multiSimMonitor_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> controllerRunner_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> monitorRunner_;
    int32_t slotCount_ = SLOT_ID_ZERO;
    int32_t dsdsMode_ = DSDS_MODE_V2;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_MANAGER_H

/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MOCK_SIM_MANAGER_H
#define MOCK_SIM_MANAGER_H

#include "event_runner.h"
#include "i_sim_manager.h"
#include <gmock/gmock.h>
namespace OHOS {
namespace Telephony {
class MockSimManager : public ISimManager {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    MockSimManager() = default;
    virtual ~MockSimManager() = default;
    // Init
    MOCK_METHOD1(OnInit, bool(int32_t));
    MOCK_METHOD1(InitTelExtraModule, int32_t(int32_t));
    // SimState
    MOCK_METHOD2(HasSimCard, int32_t(int32_t, bool &));
    MOCK_METHOD2(GetSimState, int32_t(int32_t, SimState &));
    MOCK_METHOD2(GetSimIccStatus, int32_t(int32_t, IccSimStatus &));
    MOCK_METHOD2(GetCardType, int32_t(int32_t, CardType &));
    MOCK_METHOD2(SetModemInit, int32_t(int32_t, bool));
    MOCK_METHOD3(UnlockPin, int32_t(int32_t, const std::string &, LockStatusResponse &));
    MOCK_METHOD4(UnlockPuk, int32_t(int32_t, const std::string &, const std::string &, LockStatusResponse &));
    MOCK_METHOD4(AlterPin, int32_t(int32_t, const std::string &, const std::string &, LockStatusResponse &));
    MOCK_METHOD3(SetLockState, int32_t(int32_t, const LockInfo &, LockStatusResponse &));
    MOCK_METHOD3(GetLockState, int32_t(int32_t, LockType, LockState &));
    MOCK_METHOD1(RefreshSimState, int32_t(int32_t));
    MOCK_METHOD3(UnlockPin2, int32_t(int32_t, const std::string &, LockStatusResponse &));
    MOCK_METHOD4(UnlockPuk2, int32_t(int32_t, const std::string &, const std::string &, LockStatusResponse &));
    MOCK_METHOD4(AlterPin2, int32_t(int32_t, const std::string &, const std::string &, LockStatusResponse &));
    MOCK_METHOD3(UnlockSimLock, int32_t(int32_t, const PersoLockInfo &, LockStatusResponse &));
    MOCK_METHOD1(IsSimActive, bool(int32_t));
    MOCK_METHOD2(SetActiveSim, int32_t(int32_t, int32_t));
    MOCK_METHOD2(SetActiveSimSatellite, int32_t(int32_t, int32_t));
    MOCK_METHOD1(ResetSimLoadAccount, int32_t(int32_t));
    MOCK_METHOD3(GetSimAccountInfo, int32_t(int32_t, bool, IccAccountInfo &));
    MOCK_METHOD1(SetDefaultVoiceSlotId, int32_t(int32_t));
    MOCK_METHOD1(SetDefaultSmsSlotId, int32_t(int32_t));
    MOCK_METHOD1(SetDefaultCellularDataSlotId, int32_t(int32_t));
    MOCK_METHOD1(SetPrimarySlotId, int32_t(int32_t));
    MOCK_METHOD2(SetShowNumber, int32_t(int32_t, const std::u16string &));
    MOCK_METHOD2(SetShowName, int32_t(int32_t, const std::u16string &));
    MOCK_METHOD0(GetDefaultVoiceSlotId, int32_t(void));
    MOCK_METHOD1(GetDefaultVoiceSimId, int32_t(int32_t &));
    MOCK_METHOD0(GetDefaultSmsSlotId, int32_t(void));
    MOCK_METHOD1(GetDefaultSmsSimId, int32_t(int32_t &));
    MOCK_METHOD0(GetDefaultCellularDataSlotId, int32_t(void));
    MOCK_METHOD1(GetDefaultCellularDataSimId, int32_t(int32_t &));
    MOCK_METHOD2(RegisterSimAccountCallback, int32_t(int32_t, const sptr<SimAccountCallback> &));
    MOCK_METHOD1(UnregisterSimAccountCallback, int32_t(const sptr<SimAccountCallback> &));
    MOCK_METHOD1(GetPrimarySlotId, int32_t(int32_t &));
    MOCK_METHOD2(GetShowNumber, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetShowName, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetActiveSimAccountInfoList, int32_t(bool, std::vector<IccAccountInfo> &));
    MOCK_METHOD2(GetOperatorConfigs, int32_t(int, OperatorConfig &));
    MOCK_METHOD1(UpdateOperatorConfigs, int32_t(int32_t));
    MOCK_METHOD2(HasOperatorPrivileges, int32_t(int32_t, bool &));
    MOCK_METHOD4(SimAuthentication, int32_t(int32_t, AuthType, const std::string &, SimAuthenticationResponse &));
    MOCK_METHOD1(GetRadioProtocolTech, int32_t(int32_t));
    MOCK_METHOD1(GetRadioProtocol, void(int32_t));
    MOCK_METHOD1(GetDsdsMode, int32_t(int32_t &));
    MOCK_METHOD1(SetDsdsMode, int32_t(int32_t));
    MOCK_METHOD4(SendSimMatchedOperatorInfo, int32_t(int32_t, int32_t, const std::string &, const std::string &));
    MOCK_METHOD2(SendEnvelopeCmd, int32_t(int32_t, const std::string &));
    MOCK_METHOD2(SendTerminalResponseCmd, int32_t(int32_t, const std::string &));
    MOCK_METHOD2(SendCallSetupRequestResult, int32_t(int32_t, bool));
    MOCK_METHOD2(GetSimOperatorNumeric, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetISOCountryCodeForSim, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetSimSpn, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetSimIccId, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetIMSI, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetSpdiPlmns, int32_t(int32_t, std::set<std::string> &));
    MOCK_METHOD2(GetEhPlmns, int32_t(int32_t, std::set<std::string> &));
    MOCK_METHOD1(GetLocaleFromDefaultSim, std::u16string(int32_t));
    MOCK_METHOD1(GetSlotId, int32_t(int32_t));
    MOCK_METHOD1(GetSimId, int32_t(int32_t));
    MOCK_METHOD2(GetSimGid1, int32_t(int32_t, std::u16string &));
    MOCK_METHOD1(GetSimGid2, std::u16string(int32_t));
    MOCK_METHOD2(GetOpName, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetOpKey, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetOpKeyExt, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetSimTelephoneNumber, int32_t(int32_t, std::u16string &));
    MOCK_METHOD1(GetSimTeleNumberIdentifier, std::u16string(const int32_t));
    MOCK_METHOD2(GetVoiceMailIdentifier, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetVoiceMailNumber, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetVoiceMailCount, int32_t(int32_t, int32_t &));
    MOCK_METHOD2(SetVoiceMailCount, int32_t(int32_t, int32_t));
    MOCK_METHOD3(SetVoiceCallForwarding, int32_t(int32_t, bool, const std::string &));
    MOCK_METHOD1(GetSimIst, std::u16string(int32_t));
    MOCK_METHOD3(ObtainSpnCondition, int(int32_t, bool, std::string));
    MOCK_METHOD3(SetVoiceMailInfo, int32_t(int32_t, const std::u16string &, const std::u16string &));
    MOCK_METHOD4(GetSimEons, std::u16string(int32_t, const std::string &, int32_t, bool));
    MOCK_METHOD2(IsCTSimCard, int32_t(int32_t, bool &));
    MOCK_METHOD4(AddSmsToIcc, int32_t(int32_t, int, std::string &, std::string &));
    MOCK_METHOD5(UpdateSmsIcc, int32_t(int32_t, int, int, std::string &, std::string &));
    MOCK_METHOD2(DelSmsIcc, int32_t(int32_t, int));
    MOCK_METHOD1(ObtainAllSmsOfIcc, std::vector<std::string>(int32_t));
    MOCK_METHOD3(QueryIccDiallingNumbers, int32_t(int, int, std::vector<std::shared_ptr<DiallingNumbersInfo>> &));
    MOCK_METHOD3(AddIccDiallingNumbers, int32_t(int, int, const std::shared_ptr<DiallingNumbersInfo> &));
    MOCK_METHOD3(DelIccDiallingNumbers, int32_t(int, int, const std::shared_ptr<DiallingNumbersInfo> &));
    MOCK_METHOD3(UpdateIccDiallingNumbers, int32_t(int, int, const std::shared_ptr<DiallingNumbersInfo> &));
    MOCK_METHOD3(RegisterCoreNotify, void(int32_t, const HANDLE &, int));
    MOCK_METHOD3(UnRegisterCoreNotify, void(int32_t, const HANDLE &, int));
    MOCK_METHOD2(SaveImsSwitch, int32_t(int32_t, int32_t));
    MOCK_METHOD2(QueryImsSwitch, int32_t(int32_t, int32_t &));
    MOCK_METHOD1(IsSetActiveSimInProgress, bool(int32_t));
    MOCK_METHOD0(IsSetPrimarySlotIdInProgress, bool(void));
    MOCK_METHOD6(GetSimIO, int32_t(int32_t, int32_t, int32_t, const std::string &, const std::string &,
                                   SimAuthenticationResponse &));
    MOCK_METHOD1(SavePrimarySlotId, int32_t(int32_t));
    MOCK_METHOD0(IsDataShareError, bool(void));
    MOCK_METHOD0(ResetDataShareError, void(void));
    MOCK_METHOD2(UpdateImsCapFromChip, void(int32_t, const ImsCapFromChip &));
    MOCK_METHOD0(GetDefaultMainSlotByIccId, int32_t(void));
};
}
}
#endif
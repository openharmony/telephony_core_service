/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef ESIM_CORE_SERVICE_STUB_TEST_H
#define ESIM_CORE_SERVICE_STUB_TEST_H

#include "i_core_service.h"
#include "core_service_stub.h"

#include "gmock/gmock.h"

#define private public
#define protected public

namespace OHOS {
namespace Telephony {
class MockCoreServiceStub : public CoreServiceStub {
public:
    MockCoreServiceStub() = default;
    ~MockCoreServiceStub() override {};

    int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech) override
    {
        return 0;
    }

    int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech) override
    {
        return 0;
    }

    std::u16string GetOperatorNumeric(int32_t slotId) override
    {
        return u"";
    }

    std::string GetResidentNetworkNumeric(int32_t slotId) override
    {
        return "";
    }

    int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName) override
    {
        return 0;
    }

    int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals) override
    {
        return 0;
    }

    int32_t GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState) override
    {
        return 0;
    }

    int32_t SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t GetImei(int32_t slotId, std::u16string &imei) override
    {
        return 0;
    }

    int32_t GetImeiSv(int32_t slotId, std::u16string &imeiSv) override
    {
        return 0;
    }

    int32_t GetMeid(int32_t slotId, std::u16string &meid) override
    {
        return 0;
    }

    int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId) override
    {
        return 0;
    }

    bool IsNrSupported(int32_t slotId) override
    {
        return true;
    }

    int32_t SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t HasSimCard(int32_t slotId, bool &hasSimCard) override
    {
        return 0;
    }

    int32_t GetSimState(int32_t slotId, SimState &simState) override
    {
        return 0;
    }

    int32_t GetDsdsMode(int32_t &dsdsMode) override
    {
        return 0;
    }

    int32_t GetCardType(int32_t slotId, CardType &cardType) override
    {
        return 0;
    }

    int32_t UnlockPin(int32_t slotId, const std::u16string &pin, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t UnlockPuk(
        int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t AlterPin(int32_t slotId, const std::u16string &newPin,
        const std::u16string &oldPin, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t UnlockPin2(int32_t slotId, const std::u16string &pin2, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t UnlockPuk2(int32_t slotId, const std::u16string &newPin2,
        const std::u16string &puk2, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t AlterPin2(int32_t slotId, const std::u16string &newPin2,
        const std::u16string &oldPin2, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState) override
    {
        return 0;
    }

    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric) override
    {
        return 0;
    }

    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode) override
    {
        return 0;
    }

    int32_t GetSimSpn(int32_t slotId, std::u16string &spn) override
    {
        return 0;
    }

    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId) override
    {
        return 0;
    }

    int32_t GetIMSI(int32_t slotId, std::u16string &imsi) override
    {
        return 0;
    }

    int32_t IsCTSimCard(int32_t slotId, bool &isCTSimCard) override
    {
        return 0;
    }

    bool IsSimActive(int32_t slotId) override
    {
        return true;
    }

    int32_t GetSlotId(int32_t simId) override
    {
        return 0;
    }

    int32_t GetSimId(int32_t slotId) override
    {
        return 0;
    }

    int32_t GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    std::u16string GetLocaleFromDefaultSim() override
    {
        return 0;
    }

    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1) override
    {
        return 0;
    }

    std::u16string GetSimGid2(int32_t slotId) override
    {
        return u"";
    }

    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) override
    {
        return u"";
    }

    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode) override
    {
        return 0;
    }

    int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) override
    {
        return 0;
    }

    int32_t SetDefaultVoiceSlotId(int32_t slotId) override
    {
        return 0;
    }

    int32_t GetDefaultVoiceSlotId() override
    {
        return 0;
    }

    int32_t GetDefaultVoiceSimId(int32_t &simId) override
    {
        return 0;
    }

    int32_t SetPrimarySlotId(int32_t slotId) override
    {
        return 0;
    }

    int32_t GetPrimarySlotId(int32_t &slotId) override
    {
        return 0;
    }

    int32_t SetShowNumber(int32_t slotId, const std::u16string &number) override
    {
        return 0;
    }

    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber) override
    {
        return 0;
    }

    int32_t SetShowName(int32_t slotId, const std::u16string &name) override
    {
        return 0;
    }

    int32_t GetShowName(int32_t slotId, std::u16string &showName) override
    {
        return 0;
    }

    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) override
    {
        return 0;
    }

    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) override
    {
        return 0;
    }

    int32_t RefreshSimState(int32_t slotId) override
    {
        return 0;
    }

    int32_t SetActiveSim(int32_t slotId, int32_t enable) override
    {
        return 0;
    }

    int32_t GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) override
    {
        return 0;
    }

    int32_t GetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState) override
    {
        return 0;
    }

    int32_t SetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState) override
    {
        return 0;
    }

    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber) override
    {
        return 0;
    }

    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) override
    {
        return u"";
    }

    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier) override
    {
        return 0;
    }

    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber) override
    {
        return 0;
    }

    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount) override
    {
        return 0;
    }

    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount) override
    {
        return 0;
    }

    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number) override
    {
        return 0;
    }

    int32_t QueryIccDiallingNumbers(
        int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result) override
    {
        return 0;
    }

    int32_t AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override
    {
        return 0;
    }

    int32_t DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override
    {
        return 0;
    }

    int32_t UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override
    {
        return 0;
    }

    int32_t SetVoiceMailInfo(
        const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) override
    {
        return 0;
    }

    int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) override
    {
        return 0;
    }

    int32_t GetMaxSimCount() override
    {
        return 0;
    }

    int32_t GetOpKey(int32_t slotId, std::u16string &opkey) override
    {
        return 0;
    }

    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt) override
    {
        return 0;
    }

    int32_t GetOpName(int32_t slotId, std::u16string &opname) override
    {
        return 0;
    }

    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd) override
    {
        return 0;
    }

    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) override
    {
        return 0;
    }

    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept) override
    {
        return 0;
    }

    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) override
    {
        return 0;
    }

    int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo) override
    {
        return 0;
    }

    int32_t SendUpdateCellLocationRequest(int32_t slotId) override
    {
        return 0;
    }

    int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges) override
    {
        return 0;
    }

    int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response) override
    {
        return 0;
    }

    int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback) override
    {
        return 0;
    }

    int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType) override
    {
        return 0;
    }

    int32_t GetBasebandVersion(int32_t slotId, std::string &version) override
    {
        return 0;
    }

    int32_t FactoryReset(int32_t slotId) override
    {
        return 0;
    }

    int32_t GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation) override
    {
        return 0;
    }

    int32_t InitExtraModule(int32_t slotId) override
    {
        return 0;
    }

    bool IsAllowedInsertApn(std::string &value) override
    {
        return true;
    }

    int32_t GetTargetOpkey(int32_t slotId, std::u16string &opkey) override
    {
        return 0;
    }

    int32_t GetOpkeyVersion(std::string &versionInfo) override
    {
        return 0;
    }

    int32_t GetSimIO(int32_t slotId, int32_t command,
        int32_t fileId, const std::string &data, const std::string &path, SimAuthenticationResponse &response) override
    {
        return 0;
    }

    int32_t GetEid(int32_t slotId, std::u16string &eId) override
    {
        return 0;
    }

    int32_t GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResult &euiccProfileInfoList) override
    {
        return 0;
    }

    int32_t GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo) override
    {
        return 0;
    }

    int32_t DeleteProfile(int32_t slotId, const std::u16string &iccId, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t SwitchToProfile(int32_t slotId, int32_t portIndex,
        const std::u16string &iccId, bool forceDeactivateSim, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t SetProfileNickname(
        int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t ResetMemory(int32_t slotId, ResetOption resetOption, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t SetDefaultSmdpAddress(
        int32_t slotId, const std::u16string &defaultSmdpAddress, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress) override
    {
        return 0;
    }

    int32_t CancelSession(int32_t slotId, const std::u16string &transactionId, CancelReason cancelReason,
        ResponseEsimResult &responseResult) override
    {
        return 0;
    }

    bool IsEsimSupported(int32_t slotId) override
    {
        return true;
    }

    int32_t GetProfile(
        int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile) override
    {
        return 0;
    }

    int32_t DisableProfile(
        int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress) override
    {
        return 0;
    }

    int32_t GetRulesAuthTable(
        int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable) override
    {
        return 0;
    }

    int32_t GetEuiccChallenge(
        int32_t slotId, int32_t portIndex, ResponseEsimResult &responseResult) override
    {
        return 0;
    }

    int32_t GetEuiccInfo2(int32_t slotId, int32_t portIndex, ResponseEsimResult &responseResult) override
    {
        return 0;
    }

    int32_t AuthenticateServer(
        int32_t slotId, int32_t portIndex,
        const std::u16string &matchingId,
        const std::u16string &serverSigned1,
        const std::u16string &serverSignature1,
        const std::u16string &euiccCiPkIdToBeUsed,
        const std::u16string &serverCertificate,
        ResponseEsimResult &responseResult) override
    {
        return 0;
    }

    int32_t PrepareDownload(
        int32_t slotId, int32_t portIndex,
        const std::u16string &hashCc,
        const std::u16string &smdpSigned2,
        const std::u16string &smdpSignature2,
        const std::u16string &smdpCertificate,
        ResponseEsimResult &responseResult) override
    {
        return 0;
    }

    int32_t LoadBoundProfilePackage(int32_t slotId, int32_t portIndex,
        const std::u16string &boundProfilePackage, ResponseEsimBppResult &responseResult) override
    {
        return 0;
    }

    int32_t ListNotifications(
        int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList) override
    {
        return 0;
    }

    int32_t RetrieveNotificationList(
        int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList) override
    {
        return 0;
    }

    int32_t RetrieveNotification(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification) override
    {
        return 0;
    }

    int32_t RemoveNotificationFromList(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, ResultState &enumResult) override
    {
        return 0;
    }

    int32_t SendApduData(int32_t slotId, const std::u16string &aid,
        const std::u16string &apduData, ResponseEsimResult &responseResult) override
    {
        return 0;
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // ESIM_CORE_SERVICE_STUB_TEST_H
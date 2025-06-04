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

#ifndef MOCK_I_CORE_SERVICE_H
#define MOCK_I_CORE_SERVICE_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "i_core_service.h"

namespace OHOS {
namespace Telephony {

class MockICoreService : public ICoreService {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
    MOCK_METHOD(int32_t, GetPsRadioTech, (int32_t slotId, int32_t &psRadioTech), (override));
    MOCK_METHOD(int32_t, GetCsRadioTech, (int32_t slotId, int32_t &csRadioTech), (override));
    MOCK_METHOD(std::u16string, GetOperatorNumeric, (int32_t slotId), (override));
    MOCK_METHOD(std::string, GetResidentNetworkNumeric, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetOperatorName, (int32_t slotId, std::u16string &operatorName), (override));
    MOCK_METHOD(int32_t, GetSignalInfoList, (int32_t slotId,
        std::vector<sptr<SignalInformation>> &signals), (override));
    MOCK_METHOD(int32_t, GetNetworkState, (int32_t slotId, sptr<NetworkState> &networkState), (override));
    MOCK_METHOD(int32_t, SetRadioState, (int32_t slotId, bool isOn,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetRadioState, (int32_t slotId, const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetImei, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetImeiSv, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetMeid, (int32_t slotId, std::u16string &meid), (override));
    MOCK_METHOD(int32_t, GetUniqueDeviceId, (int32_t slotId, std::u16string &deviceId), (override));
    MOCK_METHOD(bool, IsNrSupported, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, SetNrOptionMode, (int32_t slotId, int32_t mode,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetNrOptionMode, (int32_t slotId, const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, HasSimCard, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetSimState, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetDsdsMode, (int32_t &dsdsMode), (override));
    MOCK_METHOD(int32_t, GetCardType, (int32_t slotId, CardType &cardType), (override));
    MOCK_METHOD(int32_t, UnlockPin, (int32_t slotId, const std::u16string &pin,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnlockPuk, (int32_t slotId, const std::u16string &newPin,
        const std::u16string &puk, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, AlterPin, (int32_t slotId, const std::u16string &newPin,
        const std::u16string &oldPin, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnlockPin2, (int32_t slotId, const std::u16string &pin2,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnlockPuk2, (int32_t slotId, const std::u16string &newPin2,
        const std::u16string &puk2, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, AlterPin2, (int32_t slotId, const std::u16string &newPin2,
        const std::u16string &oldPin2, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetLockState, (int32_t slotId, const LockInfo &options,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetLockState, (int32_t slotId, LockType lockType,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetSimOperatorNumeric, (int32_t slotId, std::u16string &operatorNumeric), (override));
    MOCK_METHOD(int32_t, GetISOCountryCodeForSim, (int32_t slotId, std::u16string &countryCode), (override));
    MOCK_METHOD(int32_t, GetSimSpn, (int32_t slotId, std::u16string &spn), (override));
    MOCK_METHOD(int32_t, GetSimIccId, (int32_t slotId, std::u16string &iccId), (override));
    MOCK_METHOD(int32_t, GetIMSI, (int32_t slotId, std::u16string &imsi), (override));
    MOCK_METHOD(int32_t, IsCTSimCard, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(bool, IsSimActive, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetSlotId, (int32_t simId), (override));
    MOCK_METHOD(int32_t, GetSimId, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetNetworkSearchInformation, (int32_t slotId,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetNetworkSelectionMode, (int32_t slotId,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(std::u16string, GetLocaleFromDefaultSim, (), (override));
    MOCK_METHOD(int32_t, GetSimGid1, (int32_t slotId, std::u16string &gid1), (override));
    MOCK_METHOD(std::u16string, GetSimGid2, (int32_t slotId), (override));
    MOCK_METHOD(std::u16string, GetSimEons, (int32_t slotId, const std::string &plmn,
        int32_t lac, bool longNameRequired), (override));
    MOCK_METHOD(int32_t, SetNetworkSelectionMode, (int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetIsoCountryCodeForNetwork, (int32_t slotId, std::u16string &countryCode), (override));
    MOCK_METHOD(int32_t, GetSimAccountInfo, (int32_t slotId, IccAccountInfo &info), (override));
    MOCK_METHOD(int32_t, SetDefaultVoiceSlotId, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetDefaultVoiceSlotId, (), (override));
    MOCK_METHOD(int32_t, GetDefaultVoiceSimId, (const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetPrimarySlotId, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetPrimarySlotId, (int32_t &slotId), (override));
    MOCK_METHOD(int32_t, SetShowNumber, (int32_t slotId, const std::u16string &number,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetShowNumber, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetShowName, (int32_t slotId, const std::u16string &name,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetShowName, (int32_t slotId, const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetActiveSimAccountInfoList, (std::vector<IccAccountInfo> &iccAccountInfoList), (override));
    MOCK_METHOD(int32_t, GetOperatorConfigs, (int32_t slotId, OperatorConfig &poc), (override));
    MOCK_METHOD(int32_t, RefreshSimState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, SetActiveSim, (int32_t slotId, int32_t enable), (override));
    MOCK_METHOD(int32_t, SetActiveSimSatellite, (int32_t slotId, int32_t enable), (override));
    MOCK_METHOD(int32_t, GetPreferredNetwork, (int32_t slotId,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetPreferredNetwork, (int32_t slotId, int32_t networkMode,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetNetworkCapability, (int32_t slotId, int32_t networkCapabilityType,
        int32_t &networkCapabilityState), (override));
    MOCK_METHOD(int32_t, SetNetworkCapability, (int32_t slotId, int32_t networkCapabilityType,
        int32_t networkCapabilityState), (override));
    MOCK_METHOD(int32_t, GetSimTelephoneNumber, (int32_t slotId, std::u16string &telephoneNumber), (override));
    MOCK_METHOD(std::u16string, GetSimTeleNumberIdentifier, (const int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetVoiceMailIdentifier, (int32_t slotId, std::u16string &voiceMailIdentifier), (override));
    MOCK_METHOD(int32_t, GetVoiceMailNumber, (int32_t slotId, std::u16string &voiceMailNumber), (override));
    MOCK_METHOD(int32_t, GetVoiceMailCount, (int32_t slotId, int32_t &voiceMailCount), (override));
    MOCK_METHOD(int32_t, SetVoiceMailCount, (int32_t slotId, int32_t voiceMailCount), (override));
    MOCK_METHOD(int32_t, SetVoiceCallForwarding, (int32_t slotId, bool enable, const std::string &number), (override));
    MOCK_METHOD(int32_t, QueryIccDiallingNumbers, (int slotId, int type,
        std::vector<std::shared_ptr<DiallingNumbersInfo>> &result), (override));
    MOCK_METHOD(int32_t, AddIccDiallingNumbers, (int slotId, int type,
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber), (override));
    MOCK_METHOD(int32_t, DelIccDiallingNumbers, (int slotId, int type,
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber), (override));
    MOCK_METHOD(int32_t, UpdateIccDiallingNumbers, (int slotId, int type,
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber), (override));
    MOCK_METHOD(int32_t, SetVoiceMailInfo, (const int32_t slotId, const std::u16string &mailName,
        const std::u16string &mailNumber), (override));
    MOCK_METHOD(int32_t, GetImsRegStatus, (int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info), (override));
    MOCK_METHOD(int32_t, GetMaxSimCount, (), (override));
    MOCK_METHOD(int32_t, GetOpKey, (int32_t slotId, std::u16string &opkey), (override));
    MOCK_METHOD(int32_t, GetOpKeyExt, (int32_t slotId, std::u16string &opkeyExt), (override));
    MOCK_METHOD(int32_t, GetOpName, (int32_t slotId, std::u16string &opname), (override));
    MOCK_METHOD(int32_t, SendEnvelopeCmd, (int32_t slotId, const std::string &cmd), (override));
    MOCK_METHOD(int32_t, SendTerminalResponseCmd, (int32_t slotId, const std::string &cmd), (override));
    MOCK_METHOD(int32_t, SendCallSetupRequestResult, (int32_t slotId, bool accept), (override));
    MOCK_METHOD(int32_t, UnlockSimLock, (int32_t slotId, const PersoLockInfo &lockInfo,
        LockStatusResponse &response), (override));
    MOCK_METHOD(int32_t, GetCellInfoList, (int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo), (override));
    MOCK_METHOD(int32_t, GetNeighboringCellInfoList, (int32_t slotId,
        std::vector<sptr<CellInformation>> &cellInfo), (override));
    MOCK_METHOD(int32_t, SendUpdateCellLocationRequest, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, HasOperatorPrivileges, (const int32_t slotId,
        const sptr<IRawParcelCallback> &callback), (override));
    MOCK_METHOD(int32_t, SimAuthentication, (int32_t slotId, AuthType authType, const std::string &authData,
        SimAuthenticationResponse &response), (override));
    MOCK_METHOD(int32_t, RegisterImsRegInfoCallback, (int32_t slotId, ImsServiceType imsSrvType,
        const sptr<ImsRegInfoCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnregisterImsRegInfoCallback, (int32_t slotId, ImsServiceType imsSrvType), (override));
    MOCK_METHOD(int32_t, GetBasebandVersion, (int32_t slotId, std::string &version), (override));
    MOCK_METHOD(int32_t, FactoryReset, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetNrSsbIdInfo, (int32_t slotId,
        const std::shared_ptr<NrSsbInformation> &nrSsbInformation), (override));
    MOCK_METHOD(bool, IsAllowedInsertApn, (std::string &value), (override));
    MOCK_METHOD(int32_t, GetTargetOpkey, (int32_t slotId, std::u16string &opkey), (override));
    MOCK_METHOD(int32_t, GetOpkeyVersion, (std::string &versionInfo), (override));
    MOCK_METHOD(int32_t, GetOpnameVersion, (std::string &versionInfo), (override));
    MOCK_METHOD(int32_t, GetSimIO, (int32_t slotId, int32_t command, int32_t fileId, const std::string &data,
        const std::string &path, SimAuthenticationResponse &response), (override));
#ifdef CORE_SERVICE_SUPPORT_ESIM
    MOCK_METHOD(int32_t, SendApduData, (int32_t slotId, const std::u16string &aid, const EsimApduData &apduData,
        ResponseEsimResult &responseResult), (override));
#endif
};
} // namespace Telephony
} // namespace OHOS
#endif // MOCK_CORE_SERVICE_H
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

#ifndef CORE_SERVICE_CLIENT_H
#define CORE_SERVICE_CLIENT_H

#include <cstdint>
#include <iremote_object.h>
#include <singleton.h>
#include <string_ex.h>

#include "i_core_service.h"

namespace OHOS {
namespace Telephony {
class CoreServiceClient : public DelayedRefSingleton<CoreServiceClient> {
    DECLARE_DELAYED_REF_SINGLETON(CoreServiceClient);

public:
    sptr<ICoreService> GetProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);

    int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals);
    bool IsNrSupported(int32_t slotId);
    int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech);
    int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech);
    int32_t GetNrOptionMode(int32_t slotId, NrMode &mode);
    int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId);
    int32_t GetMeid(int32_t slotId, std::u16string &meid);
    std::u16string GetOperatorNumeric(int32_t slotId);
    int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName);
    int32_t GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState);
    int32_t SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback);
    int32_t GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t GetImei(int32_t slotId, std::u16string &imei);
    int32_t HasSimCard(int32_t slotId, bool &hasSimCard);
    int32_t GetSimState(int32_t slotId, SimState &simState);
    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric);
    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode);
    int32_t GetSimSpn(int32_t slotId, std::u16string &spn);
    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId);
    int32_t GetIMSI(int32_t slotId, std::u16string &imsi);
    bool IsSimActive(int32_t slotId);
    int32_t GetSlotId(int32_t simId);
    int32_t GetSimId(int32_t slotId);
    int32_t GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    std::u16string GetLocaleFromDefaultSim();
    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1);
    std::u16string GetSimGid2(int32_t slotId);
    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired);
    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode);
    int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    int32_t SetDefaultVoiceSlotId(int32_t slotId);
    int32_t GetDefaultVoiceSlotId();
    int32_t SetShowNumber(int32_t slotId, const std::u16string &number);
    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber);
    int32_t SetShowName(int32_t slotId, const std::u16string &name);
    int32_t GetShowName(int32_t slotId, std::u16string &showName);
    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);

    int32_t UnlockPin(int32_t slotId, const std::u16string &pin, LockStatusResponse &response);
    int32_t UnlockPuk(
        int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response);
    int32_t AlterPin(
        int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin, LockStatusResponse &response);
    int32_t UnlockPin2(int32_t slotId, const std::u16string &pin2, LockStatusResponse &response);
    int32_t UnlockPuk2(
        int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2, LockStatusResponse &response);
    int32_t AlterPin2(
        int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2, LockStatusResponse &response);
    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);
    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState);
    int32_t RefreshSimState(int32_t slotId);
    int32_t SetActiveSim(const int32_t slotId, int32_t enable);
    int32_t GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);
    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber);
    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier);
    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber);
    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount);
    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount);
    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number);
    int32_t QueryIccDiallingNumbers(int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result);
    int32_t AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    int32_t DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    int32_t UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    int32_t SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info);
    int32_t GetMaxSimCount();
    int32_t GetOpKey(int32_t slotId, std::u16string &opkey);
    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkey);
    int32_t GetOpName(int32_t slotId, std::u16string &opname);
    int32_t GetCardType(int32_t slotId, CardType &cardType);
    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd);
    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd);
    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept);
    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges);
    int32_t SimAuthentication(
        int32_t slotId, const std::string &aid, const std::string &authData, SimAuthenticationResponse &response);
    int32_t GetPrimarySlotId(int32_t &slotId);
    int32_t SetPrimarySlotId(int32_t slotId);
    int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo);
    int32_t SendUpdateCellLocationRequest(int32_t slotId);
    int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback);
    int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType);
    int32_t GetBasebandVersion(int32_t slotId, std::string &version);

private:
    void RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied);
    class CoreServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit CoreServiceDeathRecipient(CoreServiceClient &client) : client_(client) {}
        ~CoreServiceDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        CoreServiceClient &client_;
    };

private:
    std::mutex mutexProxy_;
    sptr<ICoreService> proxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
};
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_CLIENT_H

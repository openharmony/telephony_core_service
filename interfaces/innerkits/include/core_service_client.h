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

    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId);
    bool IsNrSupported(int32_t slotId);
    int32_t GetPsRadioTech(int32_t slotId);
    int32_t GetCsRadioTech(int32_t slotId);
    NrMode GetNrOptionMode(int32_t slotId);
    std::u16string GetUniqueDeviceId(int32_t slotId);
    std::u16string GetMeid(int32_t slotId);
    std::u16string GetOperatorNumeric(int32_t slotId);
    std::u16string GetOperatorName(int32_t slotId);
    const sptr<NetworkState> GetNetworkState(int32_t slotId);
    bool SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback);
    bool GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    std::u16string GetImei(int32_t slotId);
    bool HasSimCard(int32_t slotId);
    int32_t GetSimState(int32_t slotId);
    std::u16string GetSimOperatorNumeric(int32_t slotId);
    std::u16string GetISOCountryCodeForSim(int32_t slotId);
    std::u16string GetSimSpn(int32_t slotId);
    std::u16string GetSimIccId(int32_t slotId);
    std::u16string GetIMSI(int32_t slotId);
    bool IsSimActive(int32_t slotId);
    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    std::u16string GetLocaleFromDefaultSim();
    std::u16string GetSimGid1(int32_t slotId);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId);
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    bool SetDefaultVoiceSlotId(int32_t slotId);
    int32_t GetDefaultVoiceSlotId();
    bool SetShowNumber(int32_t slotId, const std::u16string number);
    std::u16string GetShowNumber(int32_t slotId);
    bool SetShowName(int32_t slotId, const std::u16string name);
    std::u16string GetShowName(int32_t slotId);
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);

    bool UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response);
    bool UnlockPuk(int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response);
    bool AlterPin(int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response);
    bool UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response);
    bool UnlockPuk2(int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response);
    bool AlterPin2(int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response);
    bool SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);
    int32_t GetLockState(int32_t slotId, LockType lockType);
    int32_t RefreshSimState(int32_t slotId);
    bool SetActiveSim(const int32_t slotId, int32_t enable);
    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);
    std::u16string GetSimTelephoneNumber(int32_t slotId);
    std::u16string GetVoiceMailIdentifier(int32_t slotId);
    std::u16string GetVoiceMailNumber(int32_t slotId);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type);
    bool AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    ImsRegInfo GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType);
    int32_t GetMaxSimCount();
    int32_t GetCardType(int32_t slotId);
    bool SendEnvelopeCmd(int32_t slotId, const std::string &cmd);
    bool SendTerminalResponseCmd(int32_t slotId, const std::string &cmd);
    bool UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    bool HasOperatorPrivileges(const int32_t slotId);
    int32_t GetPrimarySlotId();
    bool SetPrimarySlotId(int32_t slotId);
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId);
    bool SendUpdateCellLocationRequest(int32_t slotId);
    int32_t RegImsVoiceCallback(int32_t slotId, const sptr<ImsVoiceCallback> &callback);
    int32_t UnRegImsVoiceCallback(int32_t slotId, const sptr<ImsVoiceCallback> &callback);
    int32_t RegImsVideoCallback(int32_t slotId, const sptr<ImsVideoCallback> &callback);
    int32_t UnRegImsVideoCallback(int32_t slotId, const sptr<ImsVideoCallback> &callback);
    int32_t RegImsUtCallback(int32_t slotId, const sptr<ImsUtCallback> &callback);
    int32_t UnRegImsUtCallback(int32_t slotId, const sptr<ImsUtCallback> &callback);
    int32_t RegImsSmsCallback(int32_t slotId, const sptr<ImsSmsCallback> &callback);
    int32_t UnRegImsSmsCallback(int32_t slotId, const sptr<ImsSmsCallback> &callback);

private:
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
    sptr<ICoreService> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_CLIENT_H

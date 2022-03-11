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

#ifndef BASE_PHONE_SERVICE_PROXY_H
#define BASE_PHONE_SERVICE_PROXY_H

#include "i_core_service.h"

namespace OHOS {
namespace Telephony {
class CoreServiceProxy : public IRemoteProxy<ICoreService> {
public:
    explicit CoreServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ICoreService>(impl) {}
    virtual ~CoreServiceProxy() = default;
    int32_t GetPsRadioTech(int32_t slotId) override;
    int32_t GetCsRadioTech(int32_t slotId) override;
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) override;
    std::u16string GetOperatorNumeric(int32_t slotId) override;
    std::u16string GetOperatorName(int32_t slotId) override;
    const sptr<NetworkState> GetNetworkState(int32_t slotId) override;
    bool SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback) override;
    bool GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    std::u16string GetImei(int32_t slotId) override;
    std::u16string GetMeid(int32_t slotId) override;
    std::u16string GetUniqueDeviceId(int32_t slotId) override;
    bool IsNrSupported(int32_t slotId) override;
    NrMode GetNrOptionMode(int32_t slotId) override;
    bool HasSimCard(int32_t slotId) override;
    int32_t GetSimState(int32_t slotId) override;
    int32_t GetCardType(int32_t slotId) override;
    std::u16string GetSimOperatorNumeric(int32_t slotId) override;
    std::u16string GetISOCountryCodeForSim(int32_t slotId) override;
    std::u16string GetSimSpn(int32_t slotId) override;
    std::u16string GetSimIccId(int32_t slotId) override;
    std::u16string GetIMSI(int32_t slotId) override;
    bool IsSimActive(int32_t slotId) override;
    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    std::u16string GetLocaleFromDefaultSim() override;
    std::u16string GetSimGid1(int32_t slotId) override;
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override;
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) override;
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) override;
    bool SetDefaultVoiceSlotId(int32_t slotId) override;
    int32_t GetDefaultVoiceSlotId() override;
    int32_t GetPrimarySlotId() override;
    bool SetPrimarySlotId(int32_t slotId) override;
    bool SetShowNumber(int32_t slotId, const std::u16string number) override;
    std::u16string GetShowNumber(int32_t slotId) override;
    bool SetShowName(int32_t slotId, const std::u16string name) override;
    std::u16string GetShowName(int32_t slotId) override;
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) override;
    bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) override;
    bool IsValidSlotId(int32_t slotId);
    bool IsValidStringLength(std::u16string str);

    bool UnlockPin(const int32_t slotId, std::u16string pin, LockStatusResponse &response) override;
    bool UnlockPuk(
        const int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response) override;
    bool AlterPin(
        const int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response) override;
    bool UnlockPin2(const int32_t slotId, std::u16string pin2, LockStatusResponse &response) override;
    bool UnlockPuk2(
        const int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response) override;
    bool AlterPin2(
        const int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response) override;
    bool SetLockState(const int32_t slotId, const LockInfo &options, LockStatusResponse &response) override;
    int32_t GetLockState(int32_t slotId, LockType lockType) override;
    int32_t RefreshSimState(int32_t slotId) override;
    bool SetActiveSim(int32_t slotId, int32_t enable) override;
    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    bool SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) override;
    std::u16string GetSimTelephoneNumber(int32_t slotId) override;
    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) override;
    std::u16string GetVoiceMailIdentifier(int32_t slotId) override;
    std::u16string GetVoiceMailNumber(int32_t slotId) override;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type) override;
    bool AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;
    bool DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;
    bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) override;
    bool SetVoiceMailInfo(
        const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) override;
    bool GetImsRegStatus(int32_t slotId) override;
    int32_t GetMaxSimCount() override;
    bool SendEnvelopeCmd(int32_t slotId, const std::string &cmd) override;
    bool SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) override;
    bool UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) override;
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) override;
    bool SendUpdateCellLocationRequest(int32_t slotId) override;
    bool HasOperatorPrivileges(const int32_t slotId) override;

private:
    template<class T>
    void ProcessReply(MessageParcel &reply, std::vector<sptr<CellInformation>> &cells)
    {
        std::unique_ptr<T> cell = std::make_unique<T>();
        if (cell != nullptr) {
            cell->ReadFromParcel(reply);
            cells.emplace_back(cell.release());
        }
    }
    static inline BrokerDelegator<CoreServiceProxy> delegator_;
    bool WriteInterfaceToken(MessageParcel &data);
    void ProcessSignalInfo(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result);
    void ProcessCellInfo(MessageParcel &reply, std::vector<sptr<CellInformation>> &cells);
    std::vector<IccAccountInfo> activeIccAccountInfo_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_PROXY_H

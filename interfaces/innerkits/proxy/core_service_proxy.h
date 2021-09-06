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
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

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
    bool HasSimCard(int32_t slotId) override;
    int32_t GetSimState(int32_t slotId) override;
    std::u16string GetSimOperatorNumeric(int32_t slotId) override;
    std::u16string GetIsoCountryCodeForSim(int32_t slotId) override;
    std::u16string GetSimSpn(int32_t slotId) override;
    std::u16string GetSimIccId(int32_t slotId) override;
    std::u16string GetIMSI(int32_t slotId) override;
    bool IsSimActive(int32_t slotId) override;
    bool GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    std::u16string GetLocaleFromDefaultSim() override;
    std::u16string GetSimGid1(int32_t slotId) override;
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override;
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) override;
    bool GetSimAccountInfo(int32_t subId, IccAccountInfo &info) override;
    bool SetDefaultVoiceSlotId(int32_t subId) override;
    int32_t GetDefaultVoiceSlotId() override;
    bool IsValidSimId(int32_t subId);

    bool UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId) override;
    bool UnlockPuk(
        std::u16string newPin, std::u16string puk, LockStatusResponse &response, int32_t phoneId) override;
    bool AlterPin(
        std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int32_t phoneId) override;
    bool SetLockState(std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId) override;
    int32_t GetLockState(int32_t phoneId) override;
    int32_t RefreshSimState(int32_t slotId) override;

private:
    bool WriteInterfaceToken(MessageParcel &data);
    void ProcessSignalInfo(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result);

private:
    static inline BrokerDelegator<CoreServiceProxy> delegator_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_PROXY_H

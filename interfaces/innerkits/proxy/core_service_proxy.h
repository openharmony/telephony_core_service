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
#include <iremote_proxy.h>
#include "i_core_service.h"

namespace OHOS {
class CoreServiceProxy : public IRemoteProxy<ICoreService> {
public:
    explicit CoreServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ICoreService>(impl) {}
    virtual ~CoreServiceProxy() = default;

    int32_t GetPsRadioTech(int32_t slotId) override;
    int32_t GetCsRadioTech(int32_t slotId) override;
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) override;
    std::u16string GetOperatorNumeric(int32_t slotId) override;
    std::u16string GetOperatorName(int32_t slotId) override;
    const sptr<NetworkState> GetNetworkStatus(int32_t slotId) override;
    void SetHRilRadioState(int32_t slotId, bool isOn) override;
    int32_t GetRadioState(int32_t slotId) override;

    bool HasSimCard(int32_t slotId) override;
    int32_t GetSimState(int32_t slotId) override;
    std::u16string GetSimOperator(int32_t slotId) override;
    std::u16string GetIsoCountryCode(int32_t slotId) override;
    std::u16string GetSpn(int32_t slotId) override;
    std::u16string GetIccId(int32_t slotId) override;
    std::u16string GetIMSI(int32_t slotId) override;
    bool IsSimActive(int32_t slotId) override;

private:
    static inline BrokerDelegator<CoreServiceProxy> delegator_;
};
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_PROXY_H

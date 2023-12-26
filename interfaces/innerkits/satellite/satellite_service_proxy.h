/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SATELLITE_SERVICE_PROXY_H
#define SATELLITE_SERVICE_PROXY_H

#include "i_satellite_service.h"

namespace OHOS {
namespace Telephony {
class SatelliteServiceProxy : public IRemoteProxy<ISatelliteService> {
public:
    explicit SatelliteServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ISatelliteService>(impl) {}
    virtual ~SatelliteServiceProxy() = default;

    bool IsSatelliteEnabled() override;
    int32_t RegisterCoreNotify(int32_t slotId, int32_t what, const sptr<ISatelliteCoreCallback> &callback) override;
    int32_t UnRegisterCoreNotify(int32_t slotId, int32_t what) override;
    int32_t SetRadioState(int32_t slotId, int32_t isRadioOn, int32_t rst) override;
    int32_t GetImei(int32_t slotId) override;
    int32_t GetSatelliteCapability(int32_t slotId) override;
    sptr<IRemoteObject> GetProxyObjectPtr(SatelliteServiceProxyType proxyType) override;

private:
    bool WriteInterfaceToken(MessageParcel &data);

private:
    static inline BrokerDelegator<SatelliteServiceProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // SATELLITE_SERVICE_PROXY_H

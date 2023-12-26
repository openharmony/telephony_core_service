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

#ifndef SATELLITE_SERVICE_CLIENT_H
#define SATELLITE_SERVICE_CLIENT_H

#include <cstdint>

#include "i_satellite_service.h"
#include "iremote_object.h"
#include "network_search_handler.h"
#include "sim_state_handle.h"
#include "singleton.h"

namespace OHOS {
namespace Telephony {
class SatelliteServiceClient : public std::enable_shared_from_this<SatelliteServiceClient> {
    DECLARE_DELAYED_SINGLETON(SatelliteServiceClient);

public:
    sptr<ISatelliteService> GetProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);
    bool IsSatelliteEnabled();
    int32_t AddSimHandler(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t AddNetworkHandler(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    int32_t RegisterCoreNotify(int32_t slotId, int32_t what, const sptr<ISatelliteCoreCallback> &callback);
    int32_t UnRegisterCoreNotify(int32_t slotId, int32_t what);
    int32_t SetRadioState(int32_t slotId, int32_t isRadioOn, int32_t rst);
    int32_t GetImei(int32_t slotId);
    int32_t GetSatelliteCapability(int32_t slotId);
    sptr<IRemoteObject> GetProxyObjectPtr(SatelliteServiceProxyType type);

private:
    void RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied);
    void ServiceOn();
    void ServiceOff();

    class SatelliteServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit SatelliteServiceDeathRecipient(SatelliteServiceClient &client) : client_(client) {}
        ~SatelliteServiceDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        SatelliteServiceClient &client_;
    };

    class SystemAbilityListener : public SystemAbilityStatusChangeStub {
    public:
        SystemAbilityListener() {}
        ~SystemAbilityListener() {}

    public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    };

private:
    std::mutex mutexProxy_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    sptr<ISatelliteService> proxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
    std::map<int32_t, std::shared_ptr<AppExecFwk::EventHandler>> simHandlerMap_;
    std::map<int32_t, std::shared_ptr<AppExecFwk::EventHandler>> networkHandlerMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // SATELLITE_SERVICE_CLIENT_H

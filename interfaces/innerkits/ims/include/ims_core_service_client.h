/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_CORE_SERVICE_CLIENT_H
#define TELEPHONY_IMS_CORE_SERVICE_CLIENT_H

#include "singleton.h"
#include "rwlock.h"
#include "ims_core_service_interface.h"
#include "event_handler.h"
#include "radio_event.h"
#include "event_runner.h"
#include "iremote_stub.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace Telephony {
class ImsCoreServiceClient {
    DECLARE_DELAYED_SINGLETON(ImsCoreServiceClient);

public:
    /**
     * Get ImsCoreService Remote Object
     *
     * @return sptr<ImsCoreServiceInterface>
     */
    sptr<ImsCoreServiceInterface> GetImsCoreServiceProxy();

    void Init();
    void UnInit();
    int32_t RegisterImsCoreServiceCallbackHandler(int32_t slotId,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    /**
     * Get Handler
     *
     * @param slotId
     * @return AppExecFwk::EventHandler
     */
    std::shared_ptr<AppExecFwk::EventHandler> GetHandler(int32_t slotId);

    int32_t GetImsRegistrationStatus(int32_t slotId);

private:
    class SystemAbilityListener : public SystemAbilityStatusChangeStub {
    public:
        SystemAbilityListener() {}
        ~SystemAbilityListener() {}
    public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    };

    /**
     * Is Connect ImsCoreService Remote Object
     *
     * @return bool
     */
    bool IsConnect() const;
    int32_t RegisterImsCoreServiceCallback();
    int32_t ReConnectService();
    void Clean();

private:
    std::mutex mutex_;
    sptr<ImsCoreServiceInterface> imsCoreServiceProxy_ = nullptr;
    sptr<ImsCoreServiceCallbackInterface> imsCoreServiceCallback_ = nullptr;
    std::map<int32_t, std::shared_ptr<AppExecFwk::EventHandler>> handlerMap_;
    Utils::RWLock rwClientLock_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_CLIENT_H

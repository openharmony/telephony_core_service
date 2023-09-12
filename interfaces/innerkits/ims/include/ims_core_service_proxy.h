/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_CORE_SERVICE_PROXY_H
#define TELEPHONY_IMS_CORE_SERVICE_PROXY_H

#include "iremote_proxy.h"
#include "ims_core_service_interface.h"
#include "ims_core_service_ipc_interface_code.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ImsCoreServiceProxy : public IRemoteProxy<ImsCoreServiceInterface> {
public:
    explicit ImsCoreServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ImsCoreServiceInterface>(impl) {}
    ~ImsCoreServiceProxy() = default;
    int32_t GetImsRegistrationStatus(int32_t slotId) override;
    int32_t RegisterImsCoreServiceCallback(const sptr<ImsCoreServiceCallbackInterface> &callback) override;
    sptr<IRemoteObject> GetProxyObjectPtr(ImsServiceProxyType proxyType) override;
    int32_t GetPhoneNumberFromIMPU(int32_t slotId, std::string &phoneNumber) override;

private:
    static inline BrokerDelegator<ImsCoreServiceProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_PROXY_H

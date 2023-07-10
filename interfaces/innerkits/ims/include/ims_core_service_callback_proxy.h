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

#ifndef TELEPHONY_IMS_CORE_SERVICE_CALLBACK_PROXY_H
#define TELEPHONY_IMS_CORE_SERVICE_CALLBACK_PROXY_H

#include "iremote_proxy.h"
#include "ims_core_service_callback_interface.h"
#include "ims_core_service_callback_ipc_interface_code.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ImsCoreServiceCallbackProxy : public IRemoteProxy<ImsCoreServiceCallbackInterface> {
public:
    explicit ImsCoreServiceCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~ImsCoreServiceCallbackProxy() = default;
    int32_t UpdateImsServiceStatusChanged(int32_t slotId, const ImsServiceStatus &imsServiceStatus) override;
    int32_t GetImsRegistrationStatusResponse(int32_t slotId, const ImsRegistrationStatus &imsRegStatus) override;

private:
    int32_t WriteCommonInfo(std::string funcName, MessageParcel &in, int32_t slotId);
    int32_t SendRequest(MessageParcel &in, int32_t slotId, int32_t eventId);

private:
    static inline BrokerDelegator<ImsCoreServiceCallbackProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_CALLBACK_PROXY_H

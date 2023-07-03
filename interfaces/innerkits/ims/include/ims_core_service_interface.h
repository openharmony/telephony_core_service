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

#ifndef TELEPHONY_IMS_CORE_SERVICE_INTERFACE_H
#define TELEPHONY_IMS_CORE_SERVICE_INTERFACE_H

#include "iremote_broker.h"
#include "ims_core_service_types.h"
#include "ims_core_service_callback_interface.h"

namespace OHOS {
namespace Telephony {
enum ImsServiceProxyType {
    PROXY_IMS_CALL = 0,
    PROXY_IMS_SMS = 1,
};
class ImsCoreServiceInterface : public IRemoteBroker {
public:
    /**
     * GetImsRegistrationStatus
     *
     * @param slotId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t GetImsRegistrationStatus(int32_t slotId) = 0;

    /**
     * Register CallBack
     *
     * @param sptr<ImsCallback>
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t RegisterImsCoreServiceCallback(const sptr<ImsCoreServiceCallbackInterface> &callback) = 0;

    /**
     * GetProxyObjectPtr
     *
     * @brief get callManager proxy object ptr
     * @param proxyType[in], proxy type
     * @return Returns nullptr on failure, others on success.
     */
    virtual sptr<IRemoteObject> GetProxyObjectPtr(ImsServiceProxyType proxyType) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ImsCoreServiceInterface");
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_IMS_CORE_SERVICE_INTERFACE_H

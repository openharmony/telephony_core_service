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

#ifndef INTERFACES_INNERKITS_API_SERVICE_INTERFACE_DEATH_RECIPIENT_HPP
#define INTERFACES_INNERKITS_API_SERVICE_INTERFACE_DEATH_RECIPIENT_HPP

#include "iremote_object.h"
#include "singleton.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
template<typename T>
class ServiceInterfaceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    ServiceInterfaceDeathRecipient() = default;
    virtual ~ServiceInterfaceDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        TELEPHONY_LOGI("service died, remove the proxy object");
        DelayedSingleton<T>::GetInstance()->ResetServiceProxy();
    }
};
} // namespace Telephony
} // namespace OHOS

#endif // INTERFACES_INNERKITS_API_SERVICE_INTERFACE_DEATH_RECIPIENT_HPP
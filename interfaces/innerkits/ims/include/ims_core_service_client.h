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
#include "ims_core_service_interface.h"

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

    /**
     * Is Connect ImsCoreService Remote Object
     *
     * @return bool
     */
    bool IsConnect() const;
    void Init();
    int32_t GetImsRegistrationStatus(int32_t slotId);
    int32_t RegisterImsCoreServiceCallback();

private:
    sptr<ImsCoreServiceInterface> imsCoreServiceProxy_ = nullptr;
    sptr<ImsCoreServiceCallbackInterface> imsCoreServiceCallback_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_CLIENT_H

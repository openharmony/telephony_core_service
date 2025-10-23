/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef I_CORE_SERVICE_COMMON_EVENT_HUB_H
#define I_CORE_SERVICE_COMMON_EVENT_HUB_H

#include <memory>
#include <vector>
#include "core_service_common_event_callback.h"

namespace OHOS {
namespace Telephony {

class ICoreServiceCommonEventHub {
public:
    virtual ~ICoreServiceCommonEventHub() = default;
    virtual void RegisterCallback(const std::shared_ptr<CoreServiceCommonEventCallback> &cb,
        const std::vector<TelCommonEvent> &events) = 0;
    virtual void UnregisterCallback(const std::shared_ptr<CoreServiceCommonEventCallback> &cb) = 0;
};
}  // namespace Telephony
}  // namespace OHOS
#endif
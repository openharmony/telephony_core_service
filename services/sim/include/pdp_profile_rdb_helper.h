/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_PDP_PROFILE_RDB_HELPER_H
#define OHOS_PDP_PROFILE_RDB_HELPER_H

#include <singleton.h>
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "datashare_values_bucket.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace Telephony {
class PdpProfileRdbHelper : public DelayedSingleton<PdpProfileRdbHelper> {
    DECLARE_DELAYED_SINGLETON(PdpProfileRdbHelper);

public:
    void notifyInitApnConfigs(int32_t slotId);
private:
    std::shared_ptr<DataShare::DataShareHelper> CreatePdpProfileDataHelper();
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // OHOS_PDP_PROFILE_RDB_HELPER_H
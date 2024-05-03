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

#ifndef OHOS_BASE_DATA_HELPER_H
#define OHOS_BASE_DATA_HELPER_H

#include <mutex>
#include <singleton.h>
#include "datashare_helper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace Telephony {
class BaseDataHelper : public DelayedSingleton<BaseDataHelper> {
    DECLARE_DELAYED_SINGLETON(BaseDataHelper);

public:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper(const char *uri);

private:
    std::mutex lock_;
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // OHOS_BASE_DATA_HELPER_H
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

#include "base_data_helper.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
BaseDataHelper::BaseDataHelper() {}

BaseDataHelper::~BaseDataHelper() = default;

std::shared_ptr<DataShare::DataShareHelper> BaseDataHelper::CreateDataHelper(const char *uri)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("GetSystemAbility Service Failed.");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(lock_);
    TELEPHONY_LOGI("CreateDataHelper start.");
    return DataShare::DataShareHelper::Creator(remoteObj, uri);
}
} // namespace Telephony
} // namespace OHOS

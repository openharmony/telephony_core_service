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

#include "telephony_data_helper.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
TelephonyDataHelper::TelephonyDataHelper() {}

TelephonyDataHelper::~TelephonyDataHelper() = default;

std::shared_ptr<OHOS::DataShare::DataShareHelper> TelephonyDataHelper::CreateDataHelper(
    const std::string &strUri, const std::string &extUri, const int waitTime)
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
    auto result = DataShare::DataShareHelper::Creator(remoteObj, strUri, extUri, waitTime);
    if (result == nullptr && strUri == OPKEY_DB_URI) {
        isDataShareError_ = true;
        TELEPHONY_LOGE("CreateDataHelper error");
    }
    return result;
}

std::shared_ptr<OHOS::DataShare::DataShareHelper> TelephonyDataHelper::CreateOpKeyHelper()
{
    return CreateDataHelper(OPKEY_DB_URI, OPKEY_URI);
}

std::shared_ptr<OHOS::DataShare::DataShareHelper> TelephonyDataHelper::CreateSimHelper()
{
    return CreateDataHelper(SIM_DB_URI, SIM_URI);
}

std::shared_ptr<OHOS::DataShare::DataShareHelper> TelephonyDataHelper::CreatePdpHelper()
{
    return CreateDataHelper(PDP_DB_URI, PDP_URI);
}

std::shared_ptr<OHOS::DataShare::DataShareHelper> TelephonyDataHelper::CreateSimHelper(const int waitTime)
{
    return CreateDataHelper(SIM_DB_URI, SIM_URI, waitTime);
}

bool TelephonyDataHelper::IsDataShareError()
{
    std::lock_guard<std::mutex> lock(lock_);
    return isDataShareError_;
}

void TelephonyDataHelper::ResetDataShareError()
{
    std::lock_guard<std::mutex> lock(lock_);
    isDataShareError_ = false;
}
} // namespace Telephony
} // namespace OHOS

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

#include "pdp_profile_rdb_helper.h"
#include "telephony_data_helper.h"
#include "telephony_log_wrapper.h"

static constexpr const char *PDP_PROFILE_RDB_URI = "datashare:///com.ohos.pdpprofileability/net";
static constexpr const char *PDP_PROFILE_RDB_INIT_URI =
    "datashare:///com.ohos.pdpprofileability/net/pdp_profile/init";
static constexpr const char *SLOT_ID = "slotId";

namespace OHOS {
namespace Telephony {
PdpProfileRdbHelper::PdpProfileRdbHelper() {}

PdpProfileRdbHelper::~PdpProfileRdbHelper() = default;

std::shared_ptr<DataShare::DataShareHelper> PdpProfileRdbHelper::CreatePdpProfileDataHelper()
{
    TELEPHONY_LOGI("PdpProfileRdbHelper::CreatePdpProfileDataHelper");
    auto helper = TelephonyDataHelper::GetInstance();
    if (helper == nullptr) {
        TELEPHONY_LOGE("get CreatePdpProfileDataHelper Failed");
    }
    return helper->CreatePdpHelper();
}

void PdpProfileRdbHelper::notifyInitApnConfigs(int32_t slotId)
{
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreatePdpProfileDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("dataShareHelper is nullptr");
        return;
    }
    std::vector<DataShare::DataShareValuesBucket> values;
    DataShare::DataShareValuesBucket value;
    value.Put(SLOT_ID, slotId);
    values.push_back(value);
    Uri pdpProfileUri(PDP_PROFILE_RDB_INIT_URI);
    dataShareHelper->BatchInsert(pdpProfileUri, values);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
}
}  // namespace Telephony
}  // namespace OHOS
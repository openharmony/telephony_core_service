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

#include "ims_reg_info_callback_gtest.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
int32_t ImsRegInfoCallbackGtest::OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    TELEPHONY_LOGI(
        "slotId is %{public}d, imsSrvType is %{public}d, imsRegState is %{public}d,  imsRegTech is %{public}d", slotId,
        imsSrvType, info.imsRegState, info.imsRegTech);
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
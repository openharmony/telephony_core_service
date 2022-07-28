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

#include "telephony_common_utils.h"

#include "ipc_skeleton.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
std::string GetBundleName()
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = "";
    TelephonyPermission::GetBundleNameByUid(uid, bundleName);
    if (bundleName.empty()) {
        bundleName.append(std::to_string(uid));
        bundleName.append(std::to_string(IPCSkeleton::GetCallingPid()));
    }
    return bundleName;
}
} // namespace Telephony
} // namespace OHOS
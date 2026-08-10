/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "multi_sims_capability_manager.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "telephony_log_wrapper.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Telephony {
#undef TELEPHONY_LOG_TAG
#define TELEPHONY_LOG_TAG "MultiSimsCapabilityMgr"

bool MultiSimsCapabilityMgr::IsMultiSimsCapabilitySupported(int32_t slotId)
{
    if (slotId != SLOT_3_INDEX) {
        return false;
    }
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        TELEPHONY_LOGD("tokenType check passed.");
        return true;
    }
    auto selfToken = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}
} // namespace Telephony
} // namespace OHOS

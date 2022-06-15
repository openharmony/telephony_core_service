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

#include "napi_ims_ut_callback.h"
#include "napi_ims_callback_manager.h"

namespace OHOS {
namespace Telephony {
NapiImsUtCallback::NapiImsUtCallback(const ImsRegInfo &info) : info_(info)
{}

void NapiImsUtCallback::OnImsUtStateChange(const ImsRegInfo &info)
{
    info_ = info;
    int32_t ret = DelayedSingleton<NapiImsCallbackManager>::GetInstance()->
        UpdateImsState(ImsServiceType::TYPE_UT, info);
    if (ret != SUCCESS) {
        TELEPHONY_LOGE("UpdateImsStateInfoHandler failed! errCode:%{public}d", ret);
    } else {
        TELEPHONY_LOGI("UpdateImsStateInfoHandler success! state:%{public}d", info.imsRegState);
    }
}
}  // namespace Telephony
}  // namespace OHOS
/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "hdf_death_recipient.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
HdfDeathRecipient::HdfDeathRecipient(sptr<TelRilManager> telRilManager)
{
    telRilManager_ = telRilManager;
}

HdfDeathRecipient::HdfDeathRecipient(int32_t slotId) {}

void HdfDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    TELEPHONY_LOGI("HdfDeathRecipient OnRemoteDied start!");
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("HdfDeathRecipient telRilManager_ is nullptr!");
        return;
    }
    bool res = false;
    int32_t i = 0;

    do {
        TELEPHONY_LOGI("HdfDeathRecipient ConnectRilAdapterService!");
        res = telRilManager_->ConnectRilAdapterService();
        if (!res) {
            i++;
            sleep(1);
        } else {
            TELEPHONY_LOGE("HdfDeathRecipient ResetRemoteObject!");
            telRilManager_->ResetRemoteObject();
        }
    } while (!res && (i < TelRilManager::RIL_INIT_COUNT_MAX));
    if (!res) {
        TELEPHONY_LOGE("Reset Remote Object is failed!");
    }
}
} // namespace Telephony
} // namespace OHOS
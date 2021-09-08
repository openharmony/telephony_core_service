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
#include "core_manager.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
HdfDeathRecipient::HdfDeathRecipient(int32_t slotId)
{
    slotId_ = slotId;
}

void HdfDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    sleep(2);
    TELEPHONY_LOGD("HdfDeathRecipient OnRemoteDied id %{public}d start!", slotId_);
    std::shared_ptr<Core> core = CoreManager::GetInstance().getCore(slotId_);
    if (core != nullptr) {
        bool res;
        int i = 0;
        do {
            res = core->InitCellularRadio(false);
            if (!res) {
                sleep(1);
                i++;
                TELEPHONY_LOGD("Initialization cellular radio failed. Try initialization again!");
            }
        } while (!res && (i < RilManager::RIL_INIT_COUNT_MAX));
    } else {
        TELEPHONY_LOGE("coreId:%{public}d is null, !", slotId_);
    }
}
} // namespace Telephony
} // namespace OHOS
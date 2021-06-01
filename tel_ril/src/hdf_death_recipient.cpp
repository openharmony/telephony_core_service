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
#include "phone_manager.h"
#include "telephony_log.h"

namespace OHOS {
HdfDeathRecipient::HdfDeathRecipient()
{
    TELEPHONY_INFO_LOG("HdfDeathRecipient");
}

void HdfDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    sleep(2);
    TELEPHONY_INFO_LOG("HdfDeathRecipient OnRemoteDied start");
    PhoneManager ::GetInstance().Init();
    TELEPHONY_INFO_LOG("HdfDeathRecipient OnRemoteDied end");
}
} // namespace OHOS
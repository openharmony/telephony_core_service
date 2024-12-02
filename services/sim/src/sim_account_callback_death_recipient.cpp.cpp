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

#include "sim_account_callback_death_recipient.h"
#include "multi_sim_monitor.h"
#include "iremote_object.h"
#include <memory>

namespace OHOS {
namespace Telephony {

void SimAccountCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    sptr<SimAccountCallback> callback = iface_cast<SimAccountCallback>(remote.promote());
    TELEPHONY_LOGE("OnRemoteDied remote server death");
    handler_.UnregisterSimAccountCallback(callback);
}
}
}
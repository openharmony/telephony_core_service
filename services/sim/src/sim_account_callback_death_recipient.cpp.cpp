/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
 * Description: SimAccountCallbackDeathRecipient
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
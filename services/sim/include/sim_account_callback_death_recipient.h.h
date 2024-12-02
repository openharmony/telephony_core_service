/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
 * Description: SimAccountCallbackDeathRecipient
 */

#ifndef SIM_ACCOUNT_CALLBACK_DEATH_RECIPIENT_H
#define SIM_ACCOUNT_CALLBACK_DEATH_RECIPIENT_H

#include "iremote_broker.h"
#include "multi_sim_monitor.h"
#include <memory>

namespace OHOS {
namespace Telephony {
class SimAccountCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SimAccountCallbackDeathRecipient(MultiSimMonitor &handler): handler_(handler) {}
    ~SimAccountCallbackDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    MultiSimMonitor &handler_;
};
} // namespace Telephony
} // namespace OHOS

#endif // SIM_ACCOUNT_CALLBACK_DEATH_RECIPIENT_H
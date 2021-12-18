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

#ifndef CALL_MANAGER_DEATH_RECIPIENT_H
#define CALL_MANAGER_DEATH_RECIPIENT_H

#include "iremote_broker.h"

namespace OHOS {
namespace Telephony {
class CallManagerDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CallManagerDeathRecipient(const std::function<void(const wptr<IRemoteObject> &object)> &deathCallback);
    virtual ~CallManagerDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

private:
    std::function<void(const wptr<IRemoteObject> &object)> deathCallback_;
};
} // namespace Telephony
} // namespace OHOS

#endif // CALL_MANAGER_DEATH_RECIPIENT_H

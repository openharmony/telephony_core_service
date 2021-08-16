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

#ifndef HDF_DEATH_RECIPIENT_H
#define HDF_DEATH_RECIPIENT_H

#include <unistd.h>
#include <ipc_object_stub.h>

namespace OHOS {
namespace Telephony {
class HdfDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    HdfDeathRecipient(int32_t slotId);
    ~HdfDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    int32_t slotId_;
};
} // namespace Telephony
} // namespace OHOS
#endif // HDF_DEATH_RECIPIENT_H

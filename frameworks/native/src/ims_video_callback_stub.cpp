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

#include "ims_video_callback_stub.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
int ImsVideoCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_LOGI("ImsVideoCallbackStub Enter!");
    int32_t imsRegState = data.ReadInt32();
    int32_t imsRegTech = data.ReadInt32();
    const ImsRegInfo info = {static_cast<ImsRegState>(imsRegState), static_cast<ImsRegTech>(imsRegTech)};
    return OnImsStateCallback(info);
}

int32_t ImsVideoCallbackStub::OnImsStateCallback(const ImsRegInfo &info)
{
    OnImsVideoStateChange(info);
    return SUCCESS;
}

void ImsVideoCallbackStub::OnImsVideoStateChange(const ImsRegInfo &info) {}
}  // namespace Telephony
}  // namespace OHOS
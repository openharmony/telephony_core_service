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

#include "ims_sms_callback_stub.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
int ImsSmsCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_LOGI("ImsSmsCallbackStub Enter!");
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        TELEPHONY_LOGE("descriptor checked fail");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    int32_t imsRegState = data.ReadInt32();
    int32_t imsRegTech = data.ReadInt32();
    const ImsRegInfo info = {static_cast<ImsRegState>(imsRegState), static_cast<ImsRegTech>(imsRegTech)};
    return OnImsStateCallback(info);
}

int32_t ImsSmsCallbackStub::OnImsStateCallback(const ImsRegInfo &info)
{
    OnImsSmsStateChange(info);
    return SUCCESS;
}

void ImsSmsCallbackStub::OnImsSmsStateChange(const ImsRegInfo &info) {}
}  // namespace Telephony
}  // namespace OHOS

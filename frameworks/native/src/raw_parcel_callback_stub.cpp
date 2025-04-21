/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
#include "raw_parcel_callback_stub.h"
#include "telephony_log_wrapper.h"
#include "telephony_errors.h"
 
namespace OHOS {
namespace Telephony {
RawParcelCallbackStub::RawParcelCallbackStub(std::function<void(MessageParcel &data)> callback)
    : callback_(callback)
{
}

void RawParcelCallbackStub::Transfer(std::function<void(MessageParcel&)> func, MessageParcel &data)
{
    if (func) {
        func(data);
    }
    done_ = true;
    cv_.notify_one();
}

int RawParcelCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string myDescriptor = RawParcelCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (myDescriptor != remoteDescriptor) {
        TELEPHONY_LOGE("descriptor check fail!");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    if (callback_) {
        Transfer([=](MessageParcel &data) {
            callback_(data);
        },
        data);
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool RawParcelCallbackStub::WaitForResult(int64_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(mtx_);
    return cv_.wait_for(lock, std::chrono::microseconds(timeoutMs), [this] { return done_; });
}

} // namespace Telephony
} // namespace OHOS
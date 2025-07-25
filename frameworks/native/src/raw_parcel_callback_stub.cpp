/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
    : reader_(callback)
{
}

void RawParcelCallbackStub::Transfer(std::function<void(MessageParcel&)> writer, MessageParcel &data)
{
    if (writer) { // same process ipc call
        writer(data);
    } else {
        if (!CheckCurrentDescriptor(data)) {
            return;
        }
    }
    if (reader_) {
        reader_(data);
        NotifyReceiveDone();
    }
}

int RawParcelCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    Transfer(nullptr, data);
    return TELEPHONY_ERR_SUCCESS;
}

bool RawParcelCallbackStub::WaitForResult(int64_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(mtx_);
    return cv_.wait_for(lock, std::chrono::microseconds(timeoutMs), [this] { return done_; });
}

bool RawParcelCallbackStub::CheckCurrentDescriptor(MessageParcel &data)
{
    std::u16string myDescriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (myDescriptor != remoteDescriptor) {
        TELEPHONY_LOGE("descriptor check fail!");
        return false;
    }
    return true;
}
 
void RawParcelCallbackStub::NotifyReceiveDone()
{
    std::unique_lock<std::mutex> lock(mtx_);
    done_ = true;
    cv_.notify_one();
}

} // namespace Telephony
} // namespace OHOS
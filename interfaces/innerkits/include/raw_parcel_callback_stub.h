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
#ifndef RAW_PARCEL_CALLBACK_STUB_H
#define RAW_PARCEL_CALLBACK_STUB_H

#include <condition_variable>
#include "i_raw_parcel_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Telephony {
constexpr int64_t DEFAULT_TIMEOUT_MS = 30 * 1000;

class RawParcelCallbackStub : public IRemoteStub<IRawParcelCallback> {
public:
    explicit RawParcelCallbackStub(std::function<void(MessageParcel &data, MessageParcel &reply)> callback);
    bool WaitForResult(int64_t timeoutMs = DEFAULT_TIMEOUT_MS);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    std::mutex mtx_;
    std::condition_variable cv_;
    bool done_ = false;
    std::function<void(MessageParcel &data, MessageParcel &reply)> callback_;
};

} // namespace Telephony
} // namespace OHOS
#endif // !RAW_PARCEL_CALLBACK_STUB_H
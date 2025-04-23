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
#ifndef RAW_PARCEL_CALLBACK_PROXY_H
#define RAW_PARCEL_CALLBACK_PROXY_H
#include "i_raw_parcel_callback.h"
#include "iremote_proxy.h"
namespace OHOS {
namespace Telephony {
class RawParcelCallbackProxy : public IRemoteProxy<IRawParcelCallback> {
public:
    explicit RawParcelCallbackProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<IRawParcelCallback>(impl) {}
    void Transfer(std::function<void(MessageParcel &)> func, MessageParcel &data) override;
private:
    static BrokerDelegator<RawParcelCallbackProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // !RAW_PARCEL_CALLBACK_PROXY_H
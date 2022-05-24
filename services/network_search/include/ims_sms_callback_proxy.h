/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef IMS_SMS_CALLBACK_PROXY_H
#define IMS_SMS_CALLBACK_PROXY_H

#include "ims_sms_callback.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ImsSmsCallbackProxy : public IRemoteProxy<ImsSmsCallback> {
public:
    explicit ImsSmsCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~ImsSmsCallbackProxy() = default;
    int32_t OnImsStateCallback(const ImsRegInfo &info) override;

private:
    static inline BrokerDelegator<ImsSmsCallbackProxy> delegator_;
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // IMS_SMS_CALLBACK_PROXY_H
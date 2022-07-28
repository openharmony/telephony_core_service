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

#ifndef IMS_REG_INFO_CALLBACK_PROXY_H
#define IMS_REG_INFO_CALLBACK_PROXY_H

#include "ims_reg_info_callback.h"

namespace OHOS {
namespace Telephony {
class ImsRegInfoCallbackProxy : public IRemoteProxy<ImsRegInfoCallback> {
public:
    explicit ImsRegInfoCallbackProxy(const sptr<IRemoteObject> &impl);
    int32_t OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info) override;

private:
    static inline BrokerDelegator<ImsRegInfoCallbackProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // IMS_REG_INFO_CALLBACK_PROXY_H
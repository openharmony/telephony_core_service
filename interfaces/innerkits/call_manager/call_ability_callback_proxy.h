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

#ifndef CALL_ABILITY_CALLBACK_PROXY_H
#define CALL_ABILITY_CALLBACK_PROXY_H

#include "iremote_proxy.h"

#include "i_call_ability_callback.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class CallAbilityCallbackProxy : public IRemoteProxy<ICallAbilityCallback> {
public:
    explicit CallAbilityCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~CallAbilityCallbackProxy() = default;

    int32_t OnCallDetailsChange(const CallAttributeInfo &info) override;
    int32_t OnCallEventChange(const CallEventInfo &info) override;
    int32_t OnSupplementResult(CallResultReportId reportId, AppExecFwk::PacMap &resultInfo) override;

private:
    static inline BrokerDelegator<CallAbilityCallbackProxy> delegator_;
    static constexpr HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_DOMAIN, "CallManager"};
};
} // namespace Telephony
} // namespace OHOS

#endif
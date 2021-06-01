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

#ifndef CALL_MANAGER_SERVICE_PROXY_H
#define CALL_MANAGER_SERVICE_PROXY_H
#include <cfloat>
#include <cstdio>
#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "pac_map.h"

#include "call_manager_type.h"
#include "call_types.h"
#include "i_call_manager_service.h"

namespace OHOS {
namespace TelephonyCallManager {
class CallManagerServiceProxy : public IRemoteProxy<ICallManagerService> {
public:
    /**
     * CallManagerServiceProxy
     *
     * @param impl
     */
    explicit CallManagerServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~CallManagerServiceProxy() = default;

    /**
     * Call diale interface
     *
     * @param number[in], dial param.
     * @param extras[in], extras date.
     * @param callId[out], call id.
     * @return Returns callId when the value is greater than zero, others on failure.
     */
    int32_t DialCall(std::u16string number, AppExecFwk::PacMap &extras, int32_t &callId) override;

    /**
     * Answer call
     *
     * @param callId[in], call id
     * @param videoState[in], 0: audio, 1: video
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t AcceptCall(int32_t callId, int32_t videoState) override;

    /**
     * Reject call
     *
     * @param callId[in], call id
     * @param isSendSms[in], Whether to enter the reason for rejection,true:yes false:no
     * @param content[in], The reason you reject the call
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t RejectCall(int32_t callId, bool isSendSms, std::u16string content) override;

    /**
     * Disconnect call
     *
     * @param callId[in], call id
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t HangUpCall(int32_t callId) override;

    /**
     * app get call state
     *
     * @return Returns call state.
     */
    int32_t GetCallState() override;

private:
    static inline BrokerDelegator<CallManagerServiceProxy> delegator_;
};
} // namespace TelephonyCallManager
} // namespace OHOS
#endif // CALL_MANAGER_SERVICE_PROXY_H
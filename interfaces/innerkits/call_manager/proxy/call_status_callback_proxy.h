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

#ifndef CALL_STATUS_CALLBACK_PROXY_H
#define CALL_STATUS_CALLBACK_PROXY_H

#include "iremote_proxy.h"
#include "i_call_status_callback.h"

namespace OHOS {
namespace Telephony {
class CallStatusCallbackProxy : public IRemoteProxy<ICallStatusCallback> {
public:
    explicit CallStatusCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~CallStatusCallbackProxy() = default;

    int32_t OnUpdateCallReportInfo(const CallReportInfo &info) override;
    int32_t OnUpdateCallsReportInfo(const CallsReportInfo &info) override;
    int32_t OnUpdateDisconnectedCause(const DisconnectedDetails &cause) override;
    int32_t OnUpdateEventResultInfo(const CellularCallEventInfo &info) override;
    int32_t OnUpdateGetWaitingResult(const CallWaitResponse &callWaitResponse) override;
    int32_t OnUpdateSetWaitingResult(int32_t result) override;
    int32_t OnUpdateGetRestrictionResult(const CallRestrictionResponse &callLimitResult) override;
    int32_t OnUpdateSetRestrictionResult(int32_t result) override;
    int32_t OnUpdateGetTransferResult(const CallTransferResponse &callTransferResponse) override;
    int32_t OnUpdateSetTransferResult(int32_t result) override;
    int32_t OnUpdateGetCallClipResult(const ClipResponse &clipResponse) override;
    int32_t OnUpdateGetCallClirResult(const ClirResponse &clirResponse) override;
    int32_t OnUpdateSetCallClirResult(int32_t result) override;

private:
    static inline BrokerDelegator<CallStatusCallbackProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS

#endif

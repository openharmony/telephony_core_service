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

#ifndef I_CALL_STATUS_CALLBACK_H
#define I_CALL_STATUS_CALLBACK_H

#include "call_manager_inner_type.h"

#include "iremote_broker.h"

namespace OHOS {
namespace Telephony {
class ICallStatusCallback : public IRemoteBroker {
public:
    virtual ~ICallStatusCallback() = default;

    virtual int32_t OnUpdateCallReportInfo(const CallReportInfo &info) = 0;
    virtual int32_t OnUpdateCallsReportInfo(const CallsReportInfo &info) = 0;
    virtual int32_t OnUpdateDisconnectedCause(const DisconnectedDetails &cause) = 0;
    virtual int32_t OnUpdateEventResultInfo(const CellularCallEventInfo &info) = 0;
    virtual int32_t OnUpdateGetWaitingResult(const CallWaitResponse &callWaitResponse) = 0;
    virtual int32_t OnUpdateSetWaitingResult(int32_t result) = 0;
    virtual int32_t OnUpdateGetRestrictionResult(const CallRestrictionResponse &callLimitResult) = 0;
    virtual int32_t OnUpdateSetRestrictionResult(int32_t result) = 0;
    virtual int32_t OnUpdateGetTransferResult(const CallTransferResponse &callTransferResponse) = 0;
    virtual int32_t OnUpdateSetTransferResult(int32_t result) = 0;
    virtual int32_t OnUpdateGetCallClipResult(const ClipResponse &clipResponse) = 0;
    virtual int32_t OnUpdateGetCallClirResult(const ClirResponse &clirResponse) = 0;
    virtual int32_t OnUpdateSetCallClirResult(int32_t result) = 0;

    enum TelephonyCallManagerUpdateCode {
        UPDATE_CALL_INFO = 0,
        UPDATE_CALLS_INFO,
        UPDATE_DISCONNECTED_CAUSE,
        UPDATE_EVENT_RESULT_INFO,
        UPDATE_GET_WAITING,
        UPDATE_SET_WAITING,
        UPDATE_GET_RESTRICTION,
        UPDATE_SET_RESTRICTION,
        UPDATE_GET_TRANSFER,
        UPDATE_SET_TRANSFER,
        UPDATE_GET_CALL_CLIP,
        UPDATE_GET_CALL_CLIR,
        UPDATE_SET_CALL_CLIR,
    };

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ICallStatusCallback");
};
} // namespace Telephony
} // namespace OHOS

#endif

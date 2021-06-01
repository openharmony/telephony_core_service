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
#include "iremote_broker.h"
#include "call_manager_type.h"

namespace OHOS {
namespace TelephonyCallManager {
class ICallStatusCallback : public IRemoteBroker {
public:
    virtual ~ICallStatusCallback() = default;

    virtual int32_t OnUpdateCallReportInfo(const CallReportInfo &info) = 0;
    virtual int32_t OnUpdateCallsReportInfo(const CallsReportInfo &info) = 0;
    virtual int32_t OnUpdateDisconnectedCause(const DisconnectedDetails &cause) = 0;

    enum {
        UPDATE_CALL_INFO = 0,
        UPDATE_CALLS_INFO,
        UPDATE_DISCONNECTED_CAUSE,
    };

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.callManager.ICallStatusCallback");
};
} // namespace TelephonyCallManager
} // namespace OHOS
#endif

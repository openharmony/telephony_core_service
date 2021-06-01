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

#include "call_status_callback_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

#include "call_manager_log.h"

namespace OHOS {
namespace TelephonyCallManager {
CallStatusCallbackProxy::CallStatusCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICallStatusCallback>(impl)
{}

int32_t CallStatusCallbackProxy::OnUpdateCallReportInfo(const CallReportInfo &info)
{
    CALLMANAGER_ERR_LOG("CallStatusCallbackProxy::OnUpdateCallReportInfo Enter -->");
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int error = -1;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return -1;
    }
    int32_t length = sizeof(CallReportInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    error = Remote()->SendRequest(UPDATE_CALL_INFO, dataParcel, replyParcel, option);
    if (error != 0) {
        CALLMANAGER_ERR_LOG("update cellular call info failed, error: %{public}d", error);
        return -1;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateCallsReportInfo(const CallsReportInfo &info)
{
    CALLMANAGER_ERR_LOG("CallStatusCallbackProxy::OnUpdateCallsReportInfo Enter -->");
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t length = sizeof(CallReportInfo);
    int error = -1;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return -1;
    }
    dataParcel.WriteInt32(info.callVec.size());
    for (auto &it : info.callVec) {
        dataParcel.WriteInt32(length);
        dataParcel.WriteRawData((const void *)&it, length);
        CALLMANAGER_DEBUG_LOG(
            "accountId:%{public}d,callType:%{public}d,state:%{public}d\n", it.accountId, it.callType, it.state);
    }
    dataParcel.WriteInt32(info.slotId);

    error = Remote()->SendRequest(UPDATE_CALLS_INFO, dataParcel, replyParcel, option);
    if (error != 0) {
        CALLMANAGER_ERR_LOG("update cellular cs call info failed, error: %{public}d", error);
        return -1;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateDisconnectedCause(const DisconnectedDetails &)
{
    return 0;
}
} // namespace TelephonyCallManager
} // namespace OHOS

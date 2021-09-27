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

#include "call_ability_callback_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

#include "call_manager_errors.h"

namespace OHOS {
namespace Telephony {
CallAbilityCallbackProxy::CallAbilityCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICallAbilityCallback>(impl)
{}

int32_t CallAbilityCallbackProxy::OnCallDetailsChange(const CallAttributeInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_UPDATE_CALL_STATE_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallAbilityCallbackProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallAttributeInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_CALL_STATE_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("update call state info failed, error: %{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallAbilityCallbackProxy::OnCallEventChange(const CallEventInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_UPDATE_CALL_EVENT_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallAbilityCallbackProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallEventInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_CALL_EVENT, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("update call event failed, error: %{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallAbilityCallbackProxy::OnSupplementResult(CallResultReportId reportId, AppExecFwk::PacMap &resultInfo)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = TELEPHONY_FAIL;
    if (!dataParcel.WriteInterfaceToken(CallAbilityCallbackProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(reportId);
    dataParcel.WriteInt32(resultInfo.GetIntValue("result"));
    switch (reportId) {
        case CallResultReportId::GET_CALL_WAITING_REPORT_ID:
        case CallResultReportId::GET_CALL_RESTRICTION_REPORT_ID:
            dataParcel.WriteInt32(resultInfo.GetIntValue("status"));
            dataParcel.WriteInt32(resultInfo.GetIntValue("classCw"));
            break;
        case CallResultReportId::GET_CALL_TRANSFER_REPORT_ID:
            dataParcel.WriteInt32(resultInfo.GetIntValue("status"));
            dataParcel.WriteInt32(resultInfo.GetIntValue("classx"));
            dataParcel.WriteString(resultInfo.GetStringValue("number"));
            dataParcel.WriteInt32(resultInfo.GetIntValue("type"));
            break;
        case CallResultReportId::GET_CALL_CLIP_ID:
            dataParcel.WriteInt32(resultInfo.GetIntValue("action"));
            dataParcel.WriteInt32(resultInfo.GetIntValue("clipStat"));
            break;
        case CallResultReportId::GET_CALL_CLIR_ID:
            dataParcel.WriteInt32(resultInfo.GetIntValue("action"));
            dataParcel.WriteInt32(resultInfo.GetIntValue("clirStat"));
            break;
        default:
            break;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_CALL_SUPPLEMENT_REQUEST, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("update call event failed, error: %{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}
} // namespace Telephony
} // namespace OHOS
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

#include "ims_core_service_callback_stub.h"

#include "telephony_log_wrapper.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
ImsCoreServiceCallbackStub::ImsCoreServiceCallbackStub()
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub");
    InitFuncMap();
}

ImsCoreServiceCallbackStub::~ImsCoreServiceCallbackStub()
{
    requestFuncMap_.clear();
}

void ImsCoreServiceCallbackStub::InitFuncMap()
{
    /****************** ims basic ability ******************/
    requestFuncMap_[IMS_SERVICE_STATUS_REPORT] = &ImsCoreServiceCallbackStub::OnImsServiceStatusReportInner;
    requestFuncMap_[IMS_REGISTRATION_STATUS_RESPONSE] =
        &ImsCoreServiceCallbackStub::OnImsRegistrationStatusResponseInner;
    requestFuncMap_[IMS_NETWORK_STATE_CHANGE_REPORT] = &ImsCoreServiceCallbackStub::OnImsNetworkStateChangeInner;
}

int32_t ImsCoreServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string myDescriptor = ImsCoreServiceCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (myDescriptor != remoteDescriptor) {
        TELEPHONY_LOGE("OnRemoteRequest return, descriptor checked fail");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::OnRemoteRequest, default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ImsCoreServiceCallbackStub::OnImsServiceStatusReportInner(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::onImsServiceStatusReportInner entry");
    int32_t slotId = data.ReadInt32();
    auto imsServiceStatus = (ImsServiceStatus *)data.ReadRawData(sizeof(ImsServiceStatus));
    if (imsServiceStatus == nullptr) {
        TELEPHONY_LOGE("onImsServiceStatusReportInner return, imsServiceStatus is nullptr.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(ImsServiceStatusReport(slotId, *imsServiceStatus));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::ImsServiceStatusReport(int32_t slotId, const ImsServiceStatus &imsServiceStatus)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::ImsServiceStatusReport entry");
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::OnImsRegistrationStatusResponseInner(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::onImsRegistrationStatusResponseInner entry");
    auto info = (ImsResponseInfo *)data.ReadRawData(sizeof(ImsResponseInfo));
    if (info == nullptr) {
        TELEPHONY_LOGE("info is nullptr.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    auto imsRegStatus = (ImsRegistrationStatus *)data.ReadRawData(sizeof(ImsRegistrationStatus));
    if (imsRegStatus == nullptr) {
        TELEPHONY_LOGE("imsRegStatus is nullptr.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(ImsRegistrationStatusResponse(*info, *imsRegStatus));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::ImsRegistrationStatusResponse(
    const ImsResponseInfo &info, const ImsRegistrationStatus &imsRegStatus)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::ImsRegistrationStatusResponse entry");
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::OnImsNetworkStateChangeInner(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::OnImsNetworkStateChangeInner entry");
    int32_t slotId = data.ReadInt32();
    reply.WriteInt32(ImsNetworkStateChange(slotId));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::ImsNetworkStateChange(int32_t slotId)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::ImsNetworkStateChange entry");
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

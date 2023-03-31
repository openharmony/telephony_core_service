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

#include "ims_core_service_client.h"
#include "radio_event.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

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
    requestFuncMap_[IMS_GET_REGISTRATION_STATUS] = &ImsCoreServiceCallbackStub::OnGetImsRegistrationStatusResponseInner;
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
    reply.WriteInt32(UpdateImsServiceStatusChanged(slotId, *imsServiceStatus));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::UpdateImsServiceStatusChanged(
    int32_t slotId, const ImsServiceStatus &imsServiceStatus)
{
    TELEPHONY_LOGD("ImsCoreServiceCallbackStub::UpdateImsServiceStatusChanged entry");
    std::shared_ptr<ImsCoreServiceClient> imsCoreServiceClient = DelayedSingleton<ImsCoreServiceClient>::GetInstance();
    if (imsCoreServiceClient->GetHandler(slotId) == nullptr) {
        TELEPHONY_LOGE("get handler was null! slotId is %{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ImsServiceStatus> imsServiceState = std::make_shared<ImsServiceStatus>();
    if (imsServiceState.get() == nullptr) {
        TELEPHONY_LOGE("make_shared ImsServiceStatus failed!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    *imsServiceState = imsServiceStatus;
    imsCoreServiceClient->GetHandler(slotId)->SendEvent(RadioEvent::RADIO_IMS_SERVICE_STATUS_UPDATE, imsServiceState);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::OnGetImsRegistrationStatusResponseInner(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::OnGetImsRegistrationStatusResponseInner entry");
    int32_t slotId = data.ReadInt32();
    auto imsRegStatus = (ImsRegistrationStatus *)data.ReadRawData(sizeof(ImsRegistrationStatus));
    if (imsRegStatus == nullptr) {
        TELEPHONY_LOGE("imsRegStatus is nullptr.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    reply.WriteInt32(GetImsRegistrationStatusResponse(slotId, *imsRegStatus));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackStub::GetImsRegistrationStatusResponse(
    int32_t slotId, const ImsRegistrationStatus &imsRegStatus)
{
    TELEPHONY_LOGI("ImsCoreServiceCallbackStub::GetImsRegistrationStatusResponse entry");
    std::shared_ptr<ImsCoreServiceClient> imsCoreServiceClient = DelayedSingleton<ImsCoreServiceClient>::GetInstance();
    if (imsCoreServiceClient->GetHandler(slotId) == nullptr) {
        TELEPHONY_LOGE("get handler was null! slotId is %{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<int32_t> isRegisterd = std::make_shared<int32_t>();
    *isRegisterd = imsRegStatus.isRegisterd ? 1 : 0;
    imsCoreServiceClient->GetHandler(slotId)->SendEvent(RadioEvent::RADIO_IMS_REGISTER_STATE_UPDATE, isRegisterd);
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

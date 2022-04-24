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

#include "ims_core_service_client.h"

#include "iservice_registry.h"
#include "telephony_log_wrapper.h"
#include "telephony_errors.h"
#include "ims_core_service_callback_stub.h"

namespace OHOS {
namespace Telephony {
ImsCoreServiceClient::ImsCoreServiceClient() = default;

ImsCoreServiceClient::~ImsCoreServiceClient()
{
    if (imsCoreServiceProxy_ != nullptr) {
        imsCoreServiceProxy_.clear();
        imsCoreServiceProxy_ = nullptr;
    }
}

void ImsCoreServiceClient::Init()
{
    if (!IsConnect()) {
        GetImsCoreServiceProxy();
    }
    // register callback
    RegisterImsCoreServiceCallback();
}

int32_t ImsCoreServiceClient::GetImsRegistrationStatus(int32_t slotId)
{
    if (imsCoreServiceProxy_ != nullptr) {
        return imsCoreServiceProxy_->GetImsRegistrationStatus(slotId);
    } else {
        TELEPHONY_LOGE("imsCoreServiceProxy_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

sptr<ImsCoreServiceInterface> ImsCoreServiceClient::GetImsCoreServiceProxy()
{
    if (imsCoreServiceProxy_ != nullptr) {
        return imsCoreServiceProxy_;
    }
    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        TELEPHONY_LOGE("GetImsCoreServiceProxy return, get system ability manager error.");
        return nullptr;
    }
    auto remoteObjectPtr = managerPtr->CheckSystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID);
    if (remoteObjectPtr == nullptr) {
        TELEPHONY_LOGE("GetImsCoreServiceProxy return, remote service not exists.");
        return nullptr;
    }
    imsCoreServiceProxy_ = iface_cast<ImsCoreServiceInterface>(remoteObjectPtr);
    if (imsCoreServiceProxy_ == nullptr) {
        TELEPHONY_LOGE("GetImsCoreServiceProxy return, iface_cast is nullptr.");
        return nullptr;
    }
    TELEPHONY_LOGI("GetImsCoreServiceProxy success.");
    return imsCoreServiceProxy_;
}

bool ImsCoreServiceClient::IsConnect() const
{
    return (imsCoreServiceProxy_ != nullptr);
}

int32_t ImsCoreServiceClient::RegisterImsCoreServiceCallback()
{
    if (imsCoreServiceProxy_ == nullptr) {
        TELEPHONY_LOGE("imsCoreServiceProxy_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsCoreServiceCallback_ = (std::make_unique<ImsCoreServiceCallbackStub>()).release();
    if (imsCoreServiceCallback_ == nullptr) {
        TELEPHONY_LOGE("RegisterImsCoreServiceCallback return, make unique error.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = imsCoreServiceProxy_->RegisterImsCoreServiceCallback(imsCoreServiceCallback_);
    if (ret) {
        TELEPHONY_LOGE("RegisterImsCoreServiceCallback return, register callback error.");
        return TELEPHONY_ERR_FAIL;
    }
    TELEPHONY_LOGI("RegisterImsCoreServiceCallback success.");
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

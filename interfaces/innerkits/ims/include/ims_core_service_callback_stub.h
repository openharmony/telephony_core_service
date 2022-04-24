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

#ifndef TELEPHONY_IMS_CORE_SERVICE_CALLBACK_STUB_H
#define TELEPHONY_IMS_CORE_SERVICE_CALLBACK_STUB_H

#include <map>
#include "iremote_stub.h"
#include "ims_core_service_callback_interface.h"

namespace OHOS {
namespace Telephony {
class ImsCoreServiceCallbackStub : public IRemoteStub<ImsCoreServiceCallbackInterface> {
public:
    ImsCoreServiceCallbackStub();
    virtual ~ImsCoreServiceCallbackStub();
    void InitFuncMap();
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t ImsServiceStatusReport(int32_t slotId, const ImsServiceStatus &imsServiceStatus) override;
    int32_t ImsRegistrationStatusResponse(
        const ImsResponseInfo &info, const ImsRegistrationStatus &imsRegStatus) override;
    int32_t ImsNetworkStateChange(int32_t slotId) override;

private:
    int32_t OnImsServiceStatusReportInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnImsRegistrationStatusResponseInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnImsNetworkStateChangeInner(MessageParcel &data, MessageParcel &reply);
    using RequestFuncType = int32_t (ImsCoreServiceCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_IMS_CORE_SERVICE_CALLBACK_STUB_H

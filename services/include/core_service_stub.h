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
#ifndef BASE_PHONE_SERVICE_STUB_H
#define BASE_PHONE_SERVICE_STUB_H
#include <map>
#include "iremote_stub.h"
#include "i_core_service.h"

namespace OHOS {
class CoreServiceStub : public IRemoteStub<ICoreService> {
public:
    CoreServiceStub();
    virtual ~CoreServiceStub() {};
    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    using CoreServiceFunc = int32_t (CoreServiceStub::*)(MessageParcel &data, MessageParcel &reply);

    int32_t OnGetPsRadioTech(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetCsRadioTech(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOperatorNumeric(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetOperatorName(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSignalInfoList(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetNetworkState(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetHRilRadioState(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetHRilRadioState(MessageParcel &data, MessageParcel &reply);

    int32_t OnHasSimCard(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimState(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetIsoCountryCode(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSpn(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetIccId(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetSimOperator(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetIMSI(MessageParcel &data, MessageParcel &reply);
    int32_t OnIsSimActive(MessageParcel &data, MessageParcel &reply);

private:
    std::map<uint32_t, CoreServiceFunc> memberFuncMap_;
};
} // namespace OHOS
#endif // BASE_PHONE_SERVICE_STUB_H

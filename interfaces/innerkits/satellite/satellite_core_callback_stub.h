/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SATELLITE_CORE_CALLBACK_STUB_H
#define SATELLITE_CORE_CALLBACK_STUB_H

#include <map>

#include "i_satellite_core_callback.h"
#include "iremote_stub.h"
#include "satellite_core_callback_ipc_interface_code.h"

namespace OHOS {
namespace Telephony {
class SatelliteCoreCallbackStub : public IRemoteStub<ISatelliteCoreCallback> {
public:
    SatelliteCoreCallbackStub();
    virtual ~SatelliteCoreCallbackStub();
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void InitFuncMap();

    int32_t OnSetRadioStateResponse(MessageParcel &data, MessageParcel &reply);
    int32_t OnRadioStateChanged(MessageParcel &data, MessageParcel &reply);
    int32_t OnSatelliteStatusChanged(MessageParcel &data, MessageParcel &reply);
    int32_t OnSimStateChanged(MessageParcel &data, MessageParcel &reply);

private:
    using RequestFuncType = int32_t (SatelliteCoreCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // namespace Telephony
} // namespace OHOS

#endif // SATELLITE_CORE_CALLBACK_STUB_H

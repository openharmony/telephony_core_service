/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
#ifndef RAW_PARCEL_CALLBACK_H
#define RAW_PARCEL_CALLBACK_H
 
#include "iremote_broker.h"
 
namespace OHOS {
namespace Telephony {
class IRawParcelCallback : public IRemoteBroker {
public:
    // only override by proxy
    virtual void Transfer([[maybe_unused]] std::function<void(MessageParcel &)> func, [[maybe_unused]] MessageParcel &data) {
    }
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.IRawParcelCallback");
};
}
}
#endif // !RAW_PARCEL_CALLBACK_H
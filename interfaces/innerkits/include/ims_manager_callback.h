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

#ifndef IMS_MANAGER_CALLBACK_H
#define IMS_MANAGER_CALLBACK_H

#include <iremote_proxy.h>

#include "ims_reg_types.h"

namespace OHOS {
namespace Telephony {
class ImsManagerCallback : public IRemoteBroker {
public:
    ImsManagerCallback() = default;
    ~ImsManagerCallback() = default;

    const int32_t IMS_VOICE = 0;
    const int32_t IMS_VIDEO = 1;
    const int32_t IMS_UT = 2;
    const int32_t IMS_SMS = 3;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ImsManagerCallback");
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // IMS_MANAGER_CALLBACK_H
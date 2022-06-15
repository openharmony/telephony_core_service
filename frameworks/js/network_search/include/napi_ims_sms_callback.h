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

#ifndef NAPI_IMS_SMS_CALLBACK_H
#define NAPI_IMS_SMS_CALLBACK_H

#include "ims_sms_callback_stub.h"

namespace OHOS {
namespace Telephony {
class NapiImsSmsCallback : public ImsSmsCallbackStub {
public:
    explicit NapiImsSmsCallback(const ImsRegInfo &info);
    void OnImsSmsStateChange(const ImsRegInfo &info) override;
private:
    ImsRegInfo info_;
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // NAPI_IMS_SMS_CALLBACK_H
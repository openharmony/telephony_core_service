/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef GET_SUPPORTED_PKIDS_CALLBACK_H
#define GET_SUPPORTED_PKIDS_CALLBACK_H

#include "iesim_service_callback_stub.h"
#include "napi_esim.h"

namespace OHOS {
namespace Telephony {
class GetSupportedPkidsResultCallback : public IEsimServiceCallbackStub {
public:
    explicit GetSupportedPkidsResultCallback(AsyncContext<std::string> *context);
    void OnGetSupportedPkids(const std::string &result, const int32_t errorCode) override;

private:
    AsyncContext<std::string> *asyncContext_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // GET_SUPPORTED_PKIDS_CALLBACK_H
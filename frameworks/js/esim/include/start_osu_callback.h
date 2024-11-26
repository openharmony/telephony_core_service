/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef START_OSU_CALLBACK_H
#define START_OSU_CALLBACK_H

#include "iesim_service_callback_stub.h"
#include "napi_esim.h"

namespace OHOS {
namespace Telephony {
class StartOsuResultCallback : public IEsimServiceCallbackStub {
public:
    explicit StartOsuResultCallback(AsyncContext<int32_t> *context);
    void OnStartOsu(const OsuStatus &result, const int32_t errorCode) override;

private:
    AsyncContext<int32_t> *asyncContext_;
};
} // namespace Telephony
} // namespace OHOS
#endif // START_OSU_CALLBACK_H
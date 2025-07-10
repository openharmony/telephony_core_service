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

#ifndef ANI_RS_RESET_MEMORY_CALLBACK_H
#define ANI_RS_RESET_MEMORY_CALLBACK_H

#include <cstdint>
#include <mutex>
#include <condition_variable>
#include "iesim_service_callback_stub.h"
#include "telephony_napi_common_error.h"

namespace OHOS {
using namespace Telephony;
namespace EsimAni {

struct AniAsyncResetMemory {
    std::mutex callbackMutex;
    std::condition_variable cv;
    bool isCallbackEnd = false;
    int32_t callbackVal;
    int32_t errorCode = ERROR_DEFAULT;
};

class AniResetMemoryCallback : public IEsimServiceCallbackStub {
public:
    explicit AniResetMemoryCallback(AniAsyncResetMemory *context);
    void OnResetMemory(const int32_t &result, const int32_t errorCode) override;

private:
    AniAsyncResetMemory *asyncContext_ = nullptr;
};

} // namespace EsimAni
} // namespace OHOS

#endif

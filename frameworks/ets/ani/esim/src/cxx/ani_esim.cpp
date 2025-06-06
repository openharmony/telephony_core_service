/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <iostream>
#include <memory>
#include "ani_esim.h"
#include "ani_reset_memory_callback.h"
#include "wrapper.rs.h"
#include "cxx.h"
#include "esim_service_client.h"
#include "napi_util.h"
#include "telephony_types.h"
#include "telephony_permission.h"

using namespace std;

namespace OHOS {
using namespace Telephony;
namespace EsimAni {


static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static inline ArktsError ConvertArktsErrorWithPermission(int32_t errorCode, const std::string &funcName,
                                                         const std::string &permission)
{
    JsError error = NapiUtil::ConverEsimErrorMessageWithPermissionForJs(
        errorCode, funcName, permission);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

ArktsError resetMemory(int32_t slotId, int32_t options, int32_t &resultCode)
{
    int32_t errorCode = ERROR_DEFAULT;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "ResetMemory",
                                               Permission::SET_TELEPHONY_ESIM_STATE);
    }

    std::unique_ptr<AniAsyncResetMemory> profileContextUnique = std::make_unique<AniAsyncResetMemory>();
    AniAsyncResetMemory *profileContext = profileContextUnique.get();

    std::unique_ptr<AniResetMemoryCallback> callback = std::make_unique<AniResetMemoryCallback>(profileContext);

    std::unique_lock<std::mutex> callbackLock(profileContext->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().ResetMemory(
        slotId, options, callback.release());
    profileContext->errorCode = errorCode;

    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->isCallbackEnd; });
    }

    if ((!profileContext->isCallbackEnd) && (profileContext->errorCode == TELEPHONY_SUCCESS)) {
        profileContext->errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
    }
    resultCode = profileContext->callbackVal;

    return ConvertArktsErrorWithPermission(profileContext->errorCode, "ResetMemory",
                                           Permission::SET_TELEPHONY_ESIM_STATE);
}

} // namespace EsimAni
} // namespace OHOS

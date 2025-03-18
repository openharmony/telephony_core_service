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

#include <ani.h>
#include <array>
#include <iostream>
#include "core_service_client.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

static int32_t getDefaultVoiceSlotIdExecute([[maybe_unused]]ani_env* env, [[maybe_unused]]ani_object obj,
    ani_object callback)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(callback, &isUndefined);
    if (isUndefined) {
        TELEPHONY_LOGE("ANI_GetDefaultVoiceSlotId create promise.");
    }
    int32_t status = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSlotId();
    TELEPHONY_LOGI("GetDefaultVoiceSlotId end. status:%{public}d", status);
    return 0;
}

static int32_t getISOCountryCodeForSimExecute([[maybe_unused]]ani_env* env, [[maybe_unused]]ani_object obj,
    ani_object callback)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(callback, &isUndefined);
    if (isUndefined) {
        TELEPHONY_LOGE("ANI_getISOCountryCodeForSim create promise.");
    }
    int32_t slotId = 0;
    std::u16string countryCode;
    int32_t status = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetISOCountryCodeForSim(slotId, countryCode);
    TELEPHONY_LOGI("getISOCountryCodeForSim end. status:%{public}d", status);
    return 0;
}


ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    TELEPHONY_LOGI("ANI_Constructor call.");
    ani_env* env;
    ani_status status = ANI_ERROR;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        TELEPHONY_LOGE("Unsupported ANI_VERSION_1.");
        return ANI_ERROR;
    }

    const char *spaceName = "L@ohos.sim.d.ets/SimAbility;";
    ani_namespace spc;
    status = env->FindNamespace(spaceName, &spc);
    if (ANI_OK != status) {
        TELEPHONY_LOGE("Not found L@ohos.sim.d.ets/SimAbility.");
        return ANI_INVALID_ARGS;
    }

    std::array methods = {
        ani_native_function { "getDefaultVoiceSlotIdExecute",
            ":I", reinterpret_cast<void*>(getDefaultVoiceSlotIdExecute) },
        ani_native_function { "getISOCountryCodeForSimExecute",
            ":I", reinterpret_cast<void*>(getISOCountryCodeForSimExecute) },
    };
    status = env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size());
    if (ANI_OK != status) {
        TELEPHONY_LOGE("Cannot bind native methods in L@ohos.sim.d.ets/SimAbility.");
        return ANI_INVALID_TYPE;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}

}
}
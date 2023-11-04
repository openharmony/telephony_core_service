/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const std::string TELEPHONY_EXT_WRAPPER_PATH = "libtelephony_ext_service.z.so";
} // namespace

TelephonyExtWrapper::TelephonyExtWrapper() {}
TelephonyExtWrapper::~TelephonyExtWrapper()
{
    TELEPHONY_LOGD("TelephonyExtWrapper::~TelephonyExtWrapper() start");
    dlclose(telephonyExtWrapperHandle_);
    telephonyExtWrapperHandle_ = nullptr;
}

void TelephonyExtWrapper::InitTelephonyExtWrapper()
{
    TELEPHONY_LOGD("TelephonyExtWrapper::InitTelephonyExtWrapper() start");
    telephonyExtWrapperHandle_ = dlopen(TELEPHONY_EXT_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (telephonyExtWrapperHandle_ == nullptr) {
        TELEPHONY_LOGE("libtelephony_ext_service.z.so was not loaded, error: %{public}s", dlerror());
        return;
    }

    checkOpcVersionIsUpdate_ = (CHECK_OPC_VERSION_IS_UPDATE)dlsym(telephonyExtWrapperHandle_,
        "CheckOpcVersionIsUpdate");
    if (checkOpcVersionIsUpdate_ == nullptr) {
        TELEPHONY_LOGE("telephony ext wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }

    updateOpcVersion_ = (UPDATE_OPC_VERSION)dlsym(telephonyExtWrapperHandle_, "UpdateOpcVersion");
    if (updateOpcVersion_ == nullptr) {
        TELEPHONY_LOGE("telephony ext wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    TELEPHONY_LOGI("telephony ext wrapper init success");
}
} // namespace Telephony
} // namespace OHOS

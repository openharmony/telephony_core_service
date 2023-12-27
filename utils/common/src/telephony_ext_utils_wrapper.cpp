/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include "telephony_ext_utils_wrapper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const std::string TELEPHONY_EXT_UTILS_WRAPPER_PATH = "libtelephony_ext_service.z.so";
} // namespace

TelephonyExtUtilsWrapper::TelephonyExtUtilsWrapper() {}
TelephonyExtUtilsWrapper::~TelephonyExtUtilsWrapper()
{
    TELEPHONY_LOGD("TelephonyExtUtilsWrapper::~TelephonyExtUtilsWrapper() start");
    dlclose(telephonyExtUtilsWrapperHandle_);
    telephonyExtUtilsWrapperHandle_ = nullptr;
}
void TelephonyExtUtilsWrapper::InitTelephonyExtUtilsWrapper()
{
    TELEPHONY_LOGD("TelephonyExtUtilsWrapper::InitTelephonyExtUtilsWrapper() start");
    telephonyExtUtilsWrapperHandle_ = dlopen(TELEPHONY_EXT_UTILS_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (telephonyExtUtilsWrapperHandle_ == nullptr) {
        TELEPHONY_LOGE("libtelephony_ext_service.z.so was not loaded, error: %{public}s", dlerror());
        return;
    }
    isNrSupported_ = (IS_NR_SUPPORTED)dlsym(telephonyExtUtilsWrapperHandle_, "IsNrSupportedExt");
    if (isNrSupported_ == nullptr) {
        TELEPHONY_LOGE("telephony ext utils wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    TELEPHONY_LOGI("telephony ext utils wrapper init success");
}
} // namespace Telephony
} // namespace OHOS

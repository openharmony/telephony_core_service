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

#ifndef TELEPHONY_EXT_UTILS_WRAPPER_H
#define TELEPHONY_EXT_UTILS_WRAPPER_H

#include "nocopyable.h"
#include "singleton.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class TelephonyExtUtilsWrapper final {
DECLARE_DELAYED_REF_SINGLETON(TelephonyExtUtilsWrapper);

public:
    DISALLOW_COPY_AND_MOVE(TelephonyExtUtilsWrapper);
    void InitTelephonyExtUtilsWrapper();
    typedef bool (*IS_NR_SUPPORTED)();
    IS_NR_SUPPORTED isNrSupported_ = nullptr;

private:
    void* telephonyExtUtilsWrapperHandle_ = nullptr;
};

#define TELEPHONY_EXT_UTILS_WRAPPER ::OHOS::DelayedRefSingleton<TelephonyExtUtilsWrapper>::GetInstance()
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_EXT_UTILS_WRAPPER_H

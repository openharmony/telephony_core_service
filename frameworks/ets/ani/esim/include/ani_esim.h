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

#ifndef ANI_RS_ESIM_H
#define ANI_RS_ESIM_H

#include <cstdint>

namespace OHOS {
namespace EsimAni {
    struct ArktsError;
    constexpr int WAIT_TIME_SECOND = 30;
    ArktsError ResetMemory(int32_t slotId, int32_t options, int32_t &resultCode);
} // namespace EsimAni
} // namespace OHOS

#endif

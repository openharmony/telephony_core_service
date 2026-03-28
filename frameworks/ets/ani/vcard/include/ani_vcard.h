/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANI_RS_VCARD_H
#define ANI_RS_VCARD_H

#include <cstdint>
#include "cxx.h"
#include "context.h"

namespace OHOS {
namespace Telephony {
namespace VcardAni {
using namespace OHOS::AbilityRuntime;
struct AniEnv;
struct AniObject;
struct ArktsError;

bool IsStageContext(AniEnv *env, AniObject *obj);
std::shared_ptr<Context> GetStageModeContext(AniEnv **env, AniObject *obj);
ArktsError ImportVcard(std::shared_ptr<AbilityRuntime::Context> context, const rust::String filePath,
    int32_t accountId);
ArktsError ExportVcard(std::shared_ptr<AbilityRuntime::Context> context, int64_t dataSharePredicatesPtr,
    int32_t cardType, const rust::String charset, rust::String &filePath);

} // namespace VcardAni
} // namespace Telephony
} // namespace OHOS


#endif
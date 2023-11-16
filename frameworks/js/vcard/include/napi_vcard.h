/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_VCARD_H
#define OHOS_NAPI_VCARD_H

#include <array>
#include <string>
#include <vector>

#include "base_context.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_predicates_proxy.h"
#include "napi_base_context.h"
#include "napi_vcard_type.h"
#include "telephony_napi_common_error.h"

namespace OHOS {
namespace Telephony {
const int32_t DEFAULT_ERROR = -1;
const int32_t DEFAULT_CARD_TYPE = 0;

struct ExportContext : BaseContext {
    std::shared_ptr<DataShare::DataShareHelper> datashareHelper;
    std::shared_ptr<DataShare::DataSharePredicates> predicates;
    int32_t cardType = DEFAULT_CARD_TYPE;
    std::string charset = "UTF-8";
    std::string result = "";
};

struct ImportContext : BaseContext {
    std::shared_ptr<DataShare::DataShareHelper> datashareHelper;
    std::string filePath = "";
    int32_t accountId = DEFAULT_ERROR;
};

} // namespace Telephony
} // namespace OHOS
#endif // OHOS_NAPI_VCARD_H

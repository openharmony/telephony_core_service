/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef CORE_SERVICE_ERRORS_H
#define CORE_SERVICE_ERRORS_H

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum CoreServiceErrorCode {};

enum CoreServiceSimErrorCode {
    CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE = CORE_SERVICE_SIM_ERR_OFFSET,
    CORE_ERR_SIM_CARD_LOAD_FAILED,
    CORE_ERR_SIM_CARD_UPDATE_FAILED,
    CORE_ERR_OPERATOR_KEY_NOT_EXIT,
    CORE_ERR_OPERATOR_CONF_NOT_EXIT,
};

enum CoreServiceNetworkSearchErrorCode {
    CORE_SERVICE_SEND_CALLBACK_FAILED = CORE_SERVICE_NETWORK_SEARCH_ERR_OFFSET,
    CORE_SERVICE_RADIO_PROTOCOL_TECH_UNKNOWN,
};
} // namespace Telephony
} // namespace OHOS
#endif // CALL_SERVICE_ERRORS_H

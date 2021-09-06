/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "network_search_callback_base.h"

#include "napi_util.h"

namespace OHOS {
namespace Telephony {

napi_value NetworkSearchCallbackBase::ParseErrorValue(
    napi_env env, const int32_t rilErrorCode, const std::string &funcName)
{
    switch (rilErrorCode) {
        case HRIL_ERR_NULL_POINT:
            return NapiUtil::CreateErrorMessage(env, funcName + " error because hril err null point", rilErrorCode);
        case HRIL_ERR_SUCCESS:
            return NapiUtil::CreateUndefined(env);
        case HRIL_ERR_GENERIC_FAILURE:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err generic failure", rilErrorCode);
        case HRIL_ERR_INVALID_PARAMETER:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err invalid parameter", rilErrorCode);
        case HRIL_ERR_CMD_SEND_FAILURE:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err cmd send failure", rilErrorCode);
        case HRIL_ERR_CMD_NO_CARRIER:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err cmd no carrier", rilErrorCode);
        case HRIL_ERR_INVALID_RESPONSE:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err invalid response", rilErrorCode);
        case HRIL_ERR_REPEAT_STATUS:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err repeat status", rilErrorCode);
        default:
            return NapiUtil::CreateUndefined(env);
    }
}
} // namespace Telephony
} // namespace OHOS
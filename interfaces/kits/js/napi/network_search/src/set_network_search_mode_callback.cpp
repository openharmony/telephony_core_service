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

#include "set_network_search_mode_callback.h"

#include "napi_util.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SetNetworkSearchModeCallback::SetNetworkSearchModeCallback(
    napi_env env, napi_ref thisVarRef, BaseContext *baseContext)
    : env_(env), thisVarRef_(thisVarRef), baseContext_(baseContext)
{}

void SetNetworkSearchModeCallback::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI("OnSetNetworkModeCallback setResult = %{public}d", setResult);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    bool resolved = errorCode == HRIL_ERR_SUCCESS;
    napi_value callbackValue = nullptr;
    if (resolved) {
        napi_get_boolean(env_, setResult, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env_, errorCode, "set network search mode");
    }
    if (baseContext_->callbackRef != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env_, baseContext_->callbackRef, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = resolved ? NapiUtil::CreateUndefined(env_) :
                            NapiUtil::CreateErrorMessage(env_, "SetNetworkModelCallback err");
        callbackValues[1] = NapiUtil::CreateUndefined(env_);
        napi_value callbackResult = nullptr;
        napi_value thisVar = nullptr;
        napi_get_reference_value(env_, thisVarRef_, &thisVar);
        napi_call_function(env_, thisVar, callbackFunc, std::size(callbackValues), callbackValues, &callbackResult);
        napi_delete_reference(env_, baseContext_->callbackRef);
    } else if (baseContext_->deferred != nullptr) {
        if (resolved) {
            napi_resolve_deferred(env_, baseContext_->deferred, callbackValue);
        } else {
            napi_reject_deferred(env_, baseContext_->deferred, callbackValue);
        }
    }
    napi_delete_reference(env_, thisVarRef_);
    napi_delete_async_work(env_, baseContext_->work);
    napi_close_handle_scope(env_, scope);
    delete baseContext_;
    baseContext_ = nullptr;
}
} // namespace Telephony
} // namespace OHOS
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

#include "get_network_search_info_callback.h"
#include "napi_radio.h"
#include "napi_util.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
GetNetworkSearchInfoCallback::GetNetworkSearchInfoCallback(napi_env env, napi_ref thisVarRef, BaseContext *context)
    : env_(env), thisVarRef_(thisVarRef), baseContext_(context)
{}

int32_t WrapToJsPlmnState(int32_t nativeState)
{
    switch (nativeState) {
        case NETWORK_PLMN_STATE_AVAILABLE: {
            return NETWORK_AVAILABLE;
        }
        case NETWORK_PLMN_STATE_REGISTERED: {
            return NETWORK_CURRENT;
        }
        case NETWORK_PLMN_STATE_FORBIDDEN: {
            return NETWORK_FORBIDDEN;
        }
        default: {
            return NETWORK_UNKNOWN;
        }
    }
}

std::string GetRadioTech(int32_t radioTech)
{
    switch (radioTech) {
        case NETWORK_GSM_OR_GPRS: {
            return "GSM";
        }
        case NETWORK_WCDMA: {
            return "WCDMA";
        }
        case NETWORK_LTE: {
            return "LTE";
        }
        default: {
            return "";
        }
    }
}

void GetNetworkSearchInfoCallback::OnGetNetworkSearchResult(
    const sptr<NetworkSearchResult> &networkSearchResult, const int32_t errorCode)
{
    TELEPHONY_LOGD("OnGetNetworkSearchInfoCallback start");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    napi_value callbackValue = nullptr;
    bool resolved = (errorCode == HRIL_ERR_SUCCESS) && (networkSearchResult != nullptr);
    TELEPHONY_LOGD("OnGetNetworkSearchResult resolved = %{public}d", resolved);
    if (resolved) {
        int32_t searchResultSize = networkSearchResult->GetNetworkSearchResultSize();
        TELEPHONY_LOGD("OnGetNetworkSearchResult SearchResultSize = %{public}d", searchResultSize);
        napi_create_object(env_, &callbackValue);
        bool isNetworkSearchSuccess = searchResultSize > 0;
        NapiUtil::SetPropertyBoolean(env_, callbackValue, "isNetworkSearchSuccess", isNetworkSearchSuccess);
        napi_value searchResultArray = nullptr;
        napi_create_array(env_, &searchResultArray);
        std::vector<NetworkInformation> resultList = networkSearchResult->GetNetworkSearchResult();
        int32_t resultListSize = static_cast<int32_t>(resultList.size());
        for (int32_t i = 0; i < resultListSize; i++) {
            napi_value info = nullptr;
            napi_create_object(env_, &info);
            NapiUtil::SetPropertyStringUtf8(env_, info, "operatorName", resultList[i].GetOperatorLongName());
            NapiUtil::SetPropertyStringUtf8(env_, info, "operatorNumeric", resultList[i].GetOperatorNumeric());
            NapiUtil::SetPropertyInt32(env_, info, "state", WrapToJsPlmnState(resultList[i].GetNetworkState()));
            NapiUtil::SetPropertyStringUtf8(env_, info, "radioTech", GetRadioTech(resultList[i].GetRadioTech()));
            napi_set_element(env_, searchResultArray, i, info);
        }
        napi_set_named_property(env_, callbackValue, "networkSearchResult", searchResultArray);
    } else {
        callbackValue = ParseErrorValue(env_, errorCode, "get network search result");
        TELEPHONY_LOGD("OnGetNetworkSearchResult create error message code = %{public}d", errorCode);
    }
    if (baseContext_->callbackRef != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env_, baseContext_->callbackRef, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = resolved ? NapiUtil::CreateUndefined(env_) : callbackValue;
        callbackValues[1] = resolved ? callbackValue : NapiUtil::CreateUndefined(env_);
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
    TELEPHONY_LOGD("OnGetNetworkSearchInfoCallback end");
}
} // namespace Telephony
} // namespace OHOS
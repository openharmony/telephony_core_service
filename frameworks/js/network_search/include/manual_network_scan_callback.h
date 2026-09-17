/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef MANUAL_NETWORK_SCAN_CALLBACK_H
#define MANUAL_NETWORK_SCAN_CALLBACK_H

#include "i_network_search_callback_stub.h"
#include "network_search_result.h"
#include "napi_radio.h"

namespace OHOS {
namespace Telephony {

class ManualNetworkScanCallback : public INetworkSearchCallbackStub {
public:
    void SetScanContext(IsManualScanningContext *ctx)
    {
        scanCtx_ = ctx;
    }
    IsManualScanningContext *GetScanContext() const
    {
        return scanCtx_;
    }
    bool CreateNapiCbRef(napi_env env, napi_value thisVar, napi_value argv[]);
    void OnGetManualNetworkScanStateCallback(const bool isScanning, const int32_t errorCode) override;
    void OnStartManualNetworkScanCallback(const sptr<NetworkSearchResult> &networkSearchResult,
        const bool isFinish, int32_t slotId) override;

private:
    static void ReportManualScanInfo(napi_env env, napi_ref thisRef, napi_ref funcRef,
        const sptr<NetworkSearchResult> &networkSearchResult, bool isFinish);
    static napi_value CreateCallbackObject(napi_env env);
    static napi_value CreateSearchResultArray(napi_env env, const sptr<NetworkSearchResult> &networkSearchResult);
    static napi_status SetCallbackProperties(napi_env env, napi_value callbackValue,
        napi_value searchResultArray, bool isFinish);
    static napi_status CallJavaScriptCallback(napi_env env, napi_ref thisRef, napi_ref funcRef,
        napi_value callbackValue);
    static void DestroyNapiCbRef(napi_env env, napi_ref thisRef, napi_ref funcRef);

    IsManualScanningContext *scanCtx_ = nullptr;
    napi_env cbEnv_ = nullptr;
    napi_ref cbThis_ = nullptr;
    napi_ref cbFunc_ = nullptr;
};

} // namespace Telephony
} // namespace OHOS

#endif // MANUAL_NETWORK_SCAN_CALLBACK_H

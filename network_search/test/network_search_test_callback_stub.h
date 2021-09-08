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

#ifndef NETWORK_SEARCH_TEST_CALLBACK_STUB_H
#define NETWORK_SEARCH_TEST_CALLBACK_STUB_H

#include "i_network_search_callback_stub.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchTestCallbackStub : public INetworkSearchCallbackStub {
public:
    void OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode) override;
    void OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode) override;
    void OnSetRadioStatusCallback(const bool setResult, const int32_t errorCode) override;
    void OnGetRadioStatusCallback(const bool setResult, const int32_t errorCode) override;
    void OnGetNetworkSearchResult(
        const sptr<NetworkSearchResult> &networkSearchResult, const int32_t errorCode) override;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_TEST_CALLBACK_STUB_H

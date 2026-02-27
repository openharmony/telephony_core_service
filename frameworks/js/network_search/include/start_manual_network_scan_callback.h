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

#ifndef START_MANUAL_SCAN_CALLBACK_H
#define START_MANUAL_SCAN_CALLBACK_H

#include "i_network_search_callback_stub.h"

namespace OHOS {
namespace Telephony {
class NapiStartManualScanCallback : public INetworkSearchCallbackStub {
public:
    void OnStartManualNetworkScanCallback(const sptr<NetworkSearchResult> &networkSearchResult,
        const bool isFinish, int32_t slotId) override;
};
} // namespace Telephony
} // namespace OHOS
#endif // START_MANUAL_SCAN_CALLBACK_H
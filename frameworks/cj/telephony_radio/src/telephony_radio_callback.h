/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_RADIO_CALLBACK_H
#define TELEPHONY_RADIO_CALLBACK_H

#include "i_network_search_callback_stub.h"
#include "telephony_log_wrapper.h"
#include "telephony_radio_utils.h"

namespace OHOS {
namespace Telephony {
class GetNetworkSearchModeCallback : public INetworkSearchCallbackStub {
public:
    explicit GetNetworkSearchModeCallback(GetSelectModeContext *asyncContext);
    void OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode) override;

private:
    GetSelectModeContext *asyncContext_;
};

class GetRadioStateCallback : public INetworkSearchCallbackStub {
public:
    explicit GetRadioStateCallback(IsRadioOnContext *context);
    void OnGetRadioStateCallback(const bool isOn, const int32_t errorCode) override;

private:
    IsRadioOnContext *asyncContext_;
};
} // namespace Telephony
} // namespace OHOS
#endif
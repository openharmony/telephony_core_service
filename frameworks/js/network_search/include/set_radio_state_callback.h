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

#ifndef SET_RADIO_STATUS_CALLBACK_H
#define SET_RADIO_STATUS_CALLBACK_H

#include "i_network_search_callback_stub.h"
#include "napi_radio.h"
#include "napi/native_api.h"

namespace OHOS {
namespace Telephony {
class SetRadioStateCallback : public INetworkSearchCallbackStub {
public:
    SetRadioStateCallback(SwitchRadioContext *context);
    void OnSetRadioStateCallback(const bool setResult, const int32_t errorCode) override;

private:
    SwitchRadioContext *asyncContext_;
};
} // namespace Telephony
} // namespace OHOS
#endif // GET_NETWORK_SEARCH_MODE_CALLBACK_H
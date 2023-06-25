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

#ifndef GET_NR_OPTION_MODE_CALLBACK_H
#define GET_NR_OPTION_MODE_CALLBACK_H

#include "i_network_search_callback_stub.h"
#include "napi_radio.h"
#include "napi/native_api.h"

namespace OHOS {
namespace Telephony {
class GetNrOptionModeCallback : public INetworkSearchCallbackStub {
public:
    explicit GetNrOptionModeCallback(NrOptionModeContext *asyncContext);
    void OnGetNrOptionModeCallback(const int32_t mode, const int32_t errorCode) override;

private:
    NrOptionModeContext *asyncContext_;
};
} // namespace Telephony
} // namespace OHOS
#endif // GET_NR_OPTION_MODE_CALLBACK_H

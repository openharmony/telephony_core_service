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

#include "sim_operator_brocast_test.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
sptr<ICoreService> SimOperatorBrocastTest::telephonyService_ = nullptr;
void SimOperatorBrocastTest::OnReceiveEvent(const CommonEventData &data)
{
    TELEPHONY_LOGI(
        "SimOperatorBrocastTest::OnReceiveEvent:event=%{public}s, data=%{public}s, code=%{public}d slotId=%{public}d",
        data.GetWant().GetAction().c_str(), data.GetData().c_str(), data.GetCode(),
        data.GetWant().GetIntParam("slotId", -1));
    auto eventName = data.GetWant().GetAction();
    if (telephonyService_ != nullptr) {
        OperatorConfig poc;
        int32_t slotId = data.GetWant().GetIntParam("slotId", -1);
        telephonyService_->GetOperatorConfigs(slotId, poc);
        TELEPHONY_LOGI("SimOperatorBrocastTest::OnReceiveEvent:event=%{public}d", poc.intValue["int"]);
    }
}
} // namespace Telephony
} // namespace OHOS

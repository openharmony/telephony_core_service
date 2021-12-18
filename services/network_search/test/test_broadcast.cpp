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

#include "test_broadcast.h"
#include "network_state.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
void TestBroadCast::OnReceiveEvent(const CommonEventData &data)
{
    TELEPHONY_LOGI("TestBroadCast::OnReceiveEvent:event=%{public}s, data=%{public}s, code=%{public}d",
        data.GetWant().GetAction().c_str(), data.GetData().c_str(), data.GetCode());
    auto eventName = data.GetWant().GetAction();
    if (eventName.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SPN_INFO_UPDATED) == 0 &&
        MSG_NS_SPN_UPDATED == data.GetCode()) {
        std::string target = data.GetData();
        int32_t rule = data.GetWant().GetIntParam(CUR_SPN_SHOW_RULE, 0);
        int32_t regStatus = data.GetWant().GetIntParam(CUR_SPN_SHOW_RULE, 0);
        bool showPlmn = data.GetWant().GetBoolParam(CUR_PLMN_SHOW, false);
        std::string plmn = data.GetWant().GetStringParam(CUR_PLMN);
        bool showSpn = data.GetWant().GetBoolParam(CUR_SPN_SHOW, false);
        std::string spn = data.GetWant().GetStringParam(CUR_SPN);
        TELEPHONY_LOGI(
            "TestBroadCast::OnReceiveEvent rule:%{public}d, regStatus:%{public}d, showPlmn:%{public}d,"
            "plmn:%{public}s, showSpn:%{public}d, spn:%{public}s,",
            rule, regStatus, showPlmn, plmn.c_str(), showSpn, spn.c_str());
    }
}
} // namespace Telephony
} // namespace OHOS

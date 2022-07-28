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

#ifndef SIM_OPERATOR_BROCAST_TEST_H
#define SIM_OPERATOR_BROCAST_TEST_H

#include <gtest/gtest.h>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_service_client.h"
#include "operator_config_cache.h"

namespace OHOS {
namespace Telephony {
class SimOperatorBrocastTest : public EventFwk::CommonEventSubscriber {
public:
    explicit SimOperatorBrocastTest(const EventFwk::CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp) {}
    virtual void OnReceiveEvent(const EventFwk::CommonEventData &data);
    ~SimOperatorBrocastTest() = default;
    static sptr<ICoreService> telephonyService_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_TEST_BROADCAST_H

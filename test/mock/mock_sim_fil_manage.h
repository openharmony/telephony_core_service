/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MOCK_SIM_FILE_MANAGER_H
#define MOCK_SIM_FILE_MANAGER_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "event_handler.h"
#include "event_runner.h"
#include "i_tel_ril_manager.h"
#include "sim_file_manager.h"
#include <memory>
#include <string>

namespace OHOS {
namespace Telephony {
class MockSimFileManager : public SimFileManager {
public:
    using HANDLE = std::shared_ptr<AppExecFwk::EventHandler>;
    
    MockSimFileManager(
        const EventFwk::CommonEventSubscribeInfo &sp,
        std::weak_ptr<Telephony::ITelRilManager> telRilManager,
        std::weak_ptr<Telephony::SimStateManager> state)
        : SimFileManager(sp, telRilManager, state) {}

    virtual ~MockSimFileManager() = default;

    MOCK_METHOD0(GetSimOperatorNumeric, std::u16string());
    MOCK_METHOD0(GetISOCountryCodeForSim, std::u16string());
    MOCK_METHOD0(GetSimSpn, std::u16string());
    MOCK_METHOD0(GetSimIccId, std::u16string());
    // 根据需要mock其他方法
};
} // namespace Telephony
} // namespace OHOS

#endif // MOCK_SIM_FILE_MANAGER_H
/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_SIM_MANAGER_H
#define OHOS_SIM_MANAGER_H

#include "mock_sim_manager.h"

namespace OHOS {
namespace Telephony {

class SimManager : public testing::NiceMock<MockSimManager>, public std::enable_shared_from_this<SimManager> {
public:
    explicit SimManager(std::shared_ptr<ITelRilManager> telRilManager)
    {
        testing::Mock::AllowLeak(this);
    }
};

}
}

#endif
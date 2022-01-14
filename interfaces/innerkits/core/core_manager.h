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

#ifndef OHOS_CORE_MANAGER_H
#define OHOS_CORE_MANAGER_H

#include "singleton.h"
#include "core.h"

namespace OHOS {
namespace Telephony {
class CoreManager {
public:
    static const int32_t SLOT_ID0 = 0;
    static const int32_t SLOT_ID1 = 1;
    static const int32_t DEFAULT_SLOT_ID = SLOT_ID0;

    static CoreManager &GetInstance();

    virtual ~CoreManager() = default;
    std::shared_ptr<Core> getCore(int slotId);

private:
    CoreManager() = default;
    CoreManager(const CoreManager &) = delete;
    CoreManager &operator=(const CoreManager &) = delete;
    CoreManager(CoreManager &&) = delete;
    CoreManager &operator=(CoreManager &&) = delete;

    int32_t Init();
    void ReleaseCore();

    std::map<int, std::shared_ptr<Core>> core_;

    static std::unique_ptr<CoreManager> coreManager_;
    static std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CORE_MANAGER_H
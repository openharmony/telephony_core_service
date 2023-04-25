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

#ifndef RUNNER_POOL_H
#define RUNNER_POOL_H

#include <mutex>
#include "event_runner.h"

namespace OHOS {
namespace Telephony {
class RunnerPool {
public:
    static RunnerPool &GetInstance();
    void Init();
    std::shared_ptr<AppExecFwk::EventRunner> GetCommonRunner();
    std::shared_ptr<AppExecFwk::EventRunner> GetSimDbAndFileRunner();

private:
    std::shared_ptr<AppExecFwk::EventRunner> CreateRunner(const std::string &name);
    RunnerPool() = default;
    ~RunnerPool() = default;

private:
    std::shared_ptr<AppExecFwk::EventRunner> commonRunner_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> simDbAndFileRunner_ = nullptr;
    static RunnerPool runnerPool_;
    bool isInit_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // RUNNER_POOL_H

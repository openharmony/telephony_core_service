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

#include "runner_pool.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
RunnerPool RunnerPool::runnerPool_;

RunnerPool &RunnerPool::GetInstance()
{
    return runnerPool_;
}

void RunnerPool::Init()
{
    if (isInit_) {
        TELEPHONY_LOGI("RunnerPool has init");
        return;
    }
    commonRunner_ = CreateRunner("CoreServiceCommonRunner");
    simDbAndFileRunner_ = CreateRunner("SimDbAndFileRunner");
    if (commonRunner_ == nullptr || simDbAndFileRunner_ == nullptr) {
        return;
    }
    isInit_ = true;
    TELEPHONY_LOGI("RunnerPool init success");
}

std::shared_ptr<AppExecFwk::EventRunner> RunnerPool::CreateRunner(const std::string &name)
{
    auto runner = AppExecFwk::EventRunner::Create(name);
    if (runner == nullptr) {
        TELEPHONY_LOGE("%{public}s runner create thread fail!", name.c_str());
        return nullptr;
    }
    runner->Run();
    return runner;
}

std::shared_ptr<AppExecFwk::EventRunner> RunnerPool::GetCommonRunner()
{
    return commonRunner_;
}

std::shared_ptr<AppExecFwk::EventRunner> RunnerPool::GetSimDbAndFileRunner()
{
    return simDbAndFileRunner_;
}

} // namespace Telephony
} // namespace OHOS
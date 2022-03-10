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

#include "core_service_test_helper.h"
#include <thread>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool CoreServiceTestHelper::Run(void (*func)(CoreServiceTestHelper &), CoreServiceTestHelper &helper)
{
    std::thread t(func, std::ref(helper));
    t.detach();
    return WaitForResult(WAIT_TIME_SECOND);
}
 
void CoreServiceTestHelper::NotifyAll()
{
    std::unique_lock<std::mutex> lock(mtx_);
    cv_.notify_all();
}

bool CoreServiceTestHelper::WaitForResult(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (cv_.wait_for(lock, std::chrono::seconds(timeoutSecond)) == std::cv_status::timeout) {
        return false;
    }
    return true;
}

void CoreServiceTestHelper::SetBoolResult(bool result)
{
    boolResult_ = result;
}

void CoreServiceTestHelper::SetIntResult(int32_t result)
{
    result_ = result;
}

void CoreServiceTestHelper::SetStringResult(std::string &str)
{
    strResult_ = str;
}

bool CoreServiceTestHelper::GetBoolResult()
{
    return boolResult_;
}

int32_t CoreServiceTestHelper::GetIntResult()
{
    return result_;
}

std::string CoreServiceTestHelper::GetStringResult()
{
    return strResult_;
}
} // Telephony
} // OHOS

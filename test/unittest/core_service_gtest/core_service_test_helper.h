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
#ifndef CORE_SERVICE_TEST_HELPER_H
#define CORE_SERVICE_TEST_HELPER_H

#include <mutex>

namespace OHOS {
namespace Telephony {
class CoreServiceTestHelper {
public:
    bool Run(void (*func)(CoreServiceTestHelper &), CoreServiceTestHelper &helper);
    void NotifyAll();
    bool WaitForResult(int32_t timeoutSecond);
    void SetBoolResult(bool result);
    void SetIntResult(int32_t result);
    void SetStringResult(std::string &str);
    bool GetBoolResult();
    int32_t GetIntResult();
    std::string GetStringResult();
private:
    int32_t result_ = 0;
    bool boolResult_ = false;
    std::string strResult_ = "";
    std::mutex mtx_;
    std::condition_variable cv_;
};
} // Telephony
} // OHOS

#endif // CORE_SERVICE_TEST_HELPER_H

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

#ifndef OHOS_BASE_PHONE_H
#define OHOS_BASE_PHONE_H

#include <memory>
#include <mutex>
#include "phone.h"
#include "singleton.h"

namespace OHOS {
class PhoneManager {
public:
    static PhoneManager &GetInstance();
    ~PhoneManager() = default;
    int32_t Init();
    void ReleasePhone();

    std::map<int, Phone *> phone_;

private:
    PhoneManager() = default;
    PhoneManager(const PhoneManager &) = delete;
    PhoneManager &operator=(const PhoneManager &) = delete;
    PhoneManager(PhoneManager &&) = delete;
    PhoneManager &operator=(PhoneManager &&) = delete;
    static PhoneManager *phoneManager_;
    static std::mutex mutex_;
};
} // namespace OHOS
#endif

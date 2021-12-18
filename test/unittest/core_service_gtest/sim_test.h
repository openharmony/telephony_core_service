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

#ifndef SIM_TEST_H
#define SIM_TEST_H

#include <gtest/gtest.h>

#include "core_service_client.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimTest : public testing::Test {
public:
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();
    static sptr<ICoreService> GetProxy();
    static sptr<ICoreService> telephonyService_;
    static const int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // SIM_TEST_H

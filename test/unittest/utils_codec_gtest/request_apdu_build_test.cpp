/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <cstdbool>
#include <gtest/gtest.h>
#include <iostream>
#include "telephony_log_wrapper.h"
#include "request_apdu_build.h"

using namespace testing::ext;
namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
class RequestApduBuildTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void RequestApduBuildTest::SetUpTestCase() {}

void RequestApduBuildTest::TearDownTestCase() {}

void RequestApduBuildTest::SetUp() {}

void RequestApduBuildTest::TearDown() {}

HWTEST_F(RequestApduBuildTest, BuildStoreData_001, Function | MediumTest | Level1)
{
    RequestApduBuild build(1);
    std::string cmdHex = "test cmdHex";
    build.BuildStoreData(cmdHex);
    std::list<std::unique_ptr<ApduCommand>> commands = build.GetCommands();
    EXPECT_EQ(1, commands.size());
}
#endif // TEL_TEST_UNSUPPORT
}
}
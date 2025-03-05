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
#define private public
#define protected public

#include "pdp_profile_rdb_helper.h"
#include "telephony_data_helper.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class PdpHelperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
 
void PdpHelperTest::SetUpTestCase() {}
 
void PdpHelperTest::TearDownTestCase() {}
 
void PdpHelperTest::SetUp() {}
 
void PdpHelperTest::TearDown() {}

HWTEST_F(PdpHelperTest, PdpHelperTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    auto pdpProfileRdbHelper = std::make_shared<PdpProfileRdbHelper>();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = pdpProfileRdbHelper->CreatePdpProfileDataHelper();
    pdpProfileRdbHelper->notifyInitApnConfigs(slotId);
    EXPECT_EQ(dataShareHelper, nullptr);
}

}
}
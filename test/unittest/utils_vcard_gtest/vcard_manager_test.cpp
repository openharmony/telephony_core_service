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


#define private public
#define protected public

#include "vcard_manager.h"

#include "contact_data_test.h"
#include "mock_datashare_helper.h"
#include "mock_data_share_result_set.h"
#include "telephony_errors.h"
#include "vcard_utils.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <iostream>

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;

class VcardManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void SetNameData(const std::string &family, const std::string &given, const std::string &middle,
        const std::string &prefix, const std::string &suffix);
    void SetNameData(const std::string &family, const std::string &given, const std::string &middle,
        const std::string &displayName);
    void SetNameDataInfo(const std::string &phoneticFamily, const std::string &phoneticGiven,
        const std::string &phoneticMiddle);
};

void VcardManagerTest::SetUpTestCase() {}

void VcardManagerTest::TearDownTestCase() {}

void VcardManagerTest::SetUp() {}

void VcardManagerTest::TearDown() {}

HWTEST_F(VcardManagerTest, Telephony_Common_ConstructVcardString_001, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShareResultSetMock> resultSet = std::make_shared<DataShareResultSetMock>();
    VCardManager vCardManager;
    int errorCode;
    EXPECT_CALL(*resultSet, GoToFirstRow()).WillOnce(Return(TELEPHONY_ERROR));
    EXPECT_EQ(vCardManager.ConstructVCardString(resultSet, 0, "UTF-8", errorCode), "");
}

HWTEST_F(VcardManagerTest, Telephony_Common_ConstructVcardString_002, Function | MediumTest | Level3)
{
    std::shared_ptr<DataShareResultSetMock> resultSet = std::make_shared<DataShareResultSetMock>();
    VCardManager vCardManager;
    int errorCode;
    EXPECT_CALL(*resultSet, GetColumnIndex(Contact::ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(0), Return(TELEPHONY_SUCCESS)));
    EXPECT_CALL(*resultSet, GoToFirstRow()).WillOnce(Return(TELEPHONY_SUCCESS));
    EXPECT_CALL(*resultSet, GoToNextRow()).Times(100).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSet, GoToNextRow()).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*resultSet, GetInt(0, _)).WillOnce(DoAll(SetArgReferee<1>(0), Return(TELEPHONY_SUCCESS)));
    EXPECT_EQ(vCardManager.ConstructVCardString(resultSet, 0, "UTF-8", errorCode), "");
}

} // namespace Telephony
} // namespace OHOS
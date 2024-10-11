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

#include <gtest/gtest.h>
#include "parcel.h"

#include "download_profile_config_info_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class DownloadProfileConfigInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DownloadProfileConfigInfoTest::SetUpTestCase(void) {}

void DownloadProfileConfigInfoTest::TearDownTestCase(void) {}

void DownloadProfileConfigInfoTest::SetUp() {}

void DownloadProfileConfigInfoTest::TearDown() {}

HWTEST_F(DownloadProfileConfigInfoTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(true);
    readBoolList.push_back(true);
    MockReadBool(true, &readBoolList);
    MockReadInt32(true);
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(true);
    readBoolList.push_back(true);
    MockReadBool(true, &readBoolList);
    MockReadInt32(false);
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(false);
    readBoolList.push_back(true);
    MockReadBool(true, &readBoolList);
    MockReadInt32(true);
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(true);
    readBoolList.push_back(false);
    MockReadBool(true, &readBoolList);
    MockReadInt32(true);
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Marshalling_0100, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> writeBoolList;
    writeBoolList.push_back(true);
    writeBoolList.push_back(true);
    MockWriteBool(true, &writeBoolList);
    MockWriteInt32(true);
    EXPECT_TRUE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Marshalling_0200, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> writeBoolList;
    writeBoolList.push_back(true);
    writeBoolList.push_back(true);
    MockWriteBool(true, &writeBoolList);
    MockWriteInt32(false);
    EXPECT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Marshalling_0300, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> writeBoolList;
    writeBoolList.push_back(false);
    writeBoolList.push_back(true);
    MockWriteBool(true, &writeBoolList);
    MockWriteInt32(true);
    EXPECT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Marshalling_0400, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> writeBoolList;
    writeBoolList.push_back(true);
    writeBoolList.push_back(false);
    MockWriteBool(true, &writeBoolList);
    MockWriteInt32(true);
    EXPECT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(true);
    readBoolList.push_back(true);
    MockReadBool(true, &readBoolList);
    MockReadInt32(true);
    EXPECT_NE(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(true);
    readBoolList.push_back(true);
    MockReadBool(true, &readBoolList);
    MockReadInt32(false);
    EXPECT_EQ(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Unmarshalling_0300, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(false);
    readBoolList.push_back(true);
    MockReadBool(true, &readBoolList);
    MockReadInt32(true);
    EXPECT_EQ(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(DownloadProfileConfigInfoTest, Unmarshalling_0400, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo info;
    Parcel parcel;
    std::list<bool> readBoolList;
    readBoolList.push_back(true);
    readBoolList.push_back(false);
    MockReadBool(true, &readBoolList);
    MockReadInt32(true);
    EXPECT_EQ(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS

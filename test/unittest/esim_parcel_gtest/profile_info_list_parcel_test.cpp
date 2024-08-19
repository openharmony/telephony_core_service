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

#include "profile_info_list_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class GetEuiccProfileInfoListResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void GetEuiccProfileInfoListResultTest::SetUpTestCase(void) {}

void GetEuiccProfileInfoListResultTest::TearDownTestCase(void) {}

void GetEuiccProfileInfoListResultTest::SetUp() {}

void GetEuiccProfileInfoListResultTest::TearDown() {}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_TRUE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(false);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0500, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0600, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0700, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0800, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_0900, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1000, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1100, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1200, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1300, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1400, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1500, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1600, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, ReadFromParcel_1700, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0100, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_TRUE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0200, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0300, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(false);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0400, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0500, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0600, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0700, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0800, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_0900, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1000, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1100, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1200, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1300, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1400, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1500, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(false);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1600, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1700, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Marshalling_1800, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    euiccProfileInfoListResult.profiles_.resize(5);
    EuiccProfile profile;
    profile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    MockWriteInt32(true, &writeInt32List);

    std::list<bool> writeUint32List;
    writeUint32List.push_back(true);
    writeUint32List.push_back(true);
    MockWriteUint32(true, &writeUint32List);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(euiccProfileInfoListResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_NE(euiccProfileInfoListResult.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(GetEuiccProfileInfoListResultTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoListResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(true);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_EQ(euiccProfileInfoListResult.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS0

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

#include "euicc_info_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class EuiccInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void EuiccInfoTest::SetUpTestCase(void) {}

void EuiccInfoTest::TearDownTestCase(void) {}

void EuiccInfoTest::SetUp() {}

void EuiccInfoTest::TearDown() {}

HWTEST_F(EuiccInfoTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_TRUE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(info.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Marshalling_0100, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_TRUE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Marshalling_0200, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> writeString16List;
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Marshalling_0300, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Marshalling_0400, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> writeString16List;
    writeString16List.push_back(false);
    writeString16List.push_back(false);
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_NE(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_EQ(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Unmarshalling_0300, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);
    EXPECT_EQ(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(EuiccInfoTest, Unmarshalling_0400, Function | MediumTest | Level1)
{
    EuiccInfo info;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);
    EXPECT_EQ(info.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS

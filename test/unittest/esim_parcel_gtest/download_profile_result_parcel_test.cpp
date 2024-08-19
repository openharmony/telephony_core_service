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

#include "download_profile_result_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class DownloadProfileResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DownloadProfileResultTest::SetUpTestCase(void) {}

void DownloadProfileResultTest::TearDownTestCase(void) {}

void DownloadProfileResultTest::SetUp() {}

void DownloadProfileResultTest::TearDown() {}

HWTEST_F(DownloadProfileResultTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);
    MockReadUint32(true);
    EXPECT_TRUE(downloadProfileResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);
    MockReadUint32(true);
    EXPECT_FALSE(downloadProfileResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    MockReadInt32(true, &readInt32List);
    MockReadUint32(true);
    EXPECT_FALSE(downloadProfileResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);
    MockReadUint32(false);
    EXPECT_FALSE(downloadProfileResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, Marshalling_0100, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);
    MockWriteUint32(true);
    EXPECT_TRUE(downloadProfileResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, Marshalling_0200, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> writeInt32List;
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);
    MockWriteUint32(true);
    EXPECT_FALSE(downloadProfileResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, Marshalling_0300, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    MockWriteInt32(true, &writeInt32List);
    MockWriteUint32(true);
    EXPECT_FALSE(downloadProfileResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, Marshalling_0400, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);
    MockWriteUint32(false);
    EXPECT_FALSE(downloadProfileResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);
    MockReadUint32(true);
    EXPECT_NE(downloadProfileResult.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(DownloadProfileResultTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    DownloadProfileResult downloadProfileResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);
    MockReadUint32(true);
    EXPECT_EQ(downloadProfileResult.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS

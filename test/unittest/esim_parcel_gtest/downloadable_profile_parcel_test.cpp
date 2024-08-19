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

#include "downloadable_profile_parcel.h"
#include "telephony_log_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class DownloadableProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DownloadableProfileTest::SetUpTestCase(void) {}

void DownloadableProfileTest::TearDownTestCase(void) {}

void DownloadableProfileTest::SetUp() {}

void DownloadableProfileTest::TearDown() {}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_TRUE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0500, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(false, 5);
    MockReadInt32(true);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0600, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0700, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, ReadFromParcel_0800, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(false);
    downloadableProfile.accessRules_.resize(5);
    EXPECT_FALSE(downloadableProfile.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0100, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(true);
    EXPECT_TRUE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0200, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(true);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0300, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(true);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0400, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(true);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0500, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(false);
    MockWriteInt32(true);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0600, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(true);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0700, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(true);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Marshalling_0800, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);
    MockWriteUint32(true);
    MockWriteInt32(false);
    EXPECT_FALSE(downloadableProfile.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(true, 5);
    MockReadInt32(true);
    EXPECT_NE(downloadableProfile.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(DownloadableProfileTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    DownloadableProfile downloadableProfile;
    Parcel parcel;
    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    MockReadUint32(false, 5);
    MockReadInt32(true);
    EXPECT_EQ(downloadableProfile.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS

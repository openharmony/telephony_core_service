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

#include "profile_metadata_result_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class ProfileMetadataResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ProfileMetadataResultTest::SetUpTestCase(void) {}

void ProfileMetadataResultTest::TearDownTestCase(void) {}

void ProfileMetadataResultTest::SetUp() {}

void ProfileMetadataResultTest::TearDown() {}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_TRUE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0500, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(false, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0600, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0700, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(false);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0800, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_0900, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_1000, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(false);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_1100, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, ReadFromParcel_1200, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(false);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_FALSE(metadata.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0100, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_TRUE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0200, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0300, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0400, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0500, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(false);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0600, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0700, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(false);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0800, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_0900, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_1000, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_1100, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(false);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_1200, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(false);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Marshalling_1300, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    metadata.downloadableProfiles_.accessRules_.resize(5);
    std::list<bool> writeInt32List;
    writeInt32List.push_back(true);
    writeInt32List.push_back(true);
    writeInt32List.push_back(false);
    writeInt32List.push_back(true);
    MockWriteInt32(true, &writeInt32List);

    MockWriteUint32(true);

    std::list<bool> writeString16List;
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    writeString16List.push_back(true);
    MockWriteString16(true, &writeString16List);

    MockWriteBool(true);
    EXPECT_FALSE(metadata.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_NE(metadata.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(ProfileMetadataResultTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    GetDownloadableProfileMetadataResult metadata;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    MockReadUint32(true, 5);

    std::list<bool> readString16List;
    readString16List.push_back(false);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);

    MockReadBool(true);
    EXPECT_EQ(metadata.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS0

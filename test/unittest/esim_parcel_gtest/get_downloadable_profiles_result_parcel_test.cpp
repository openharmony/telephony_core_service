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

#include "get_downloadable_profiles_result_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class GetDownloadableProfilesResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void GetDownloadableProfilesResultTest::SetUpTestCase(void) {}

void GetDownloadableProfilesResultTest::TearDownTestCase(void) {}

void GetDownloadableProfilesResultTest::SetUp() {}

void GetDownloadableProfilesResultTest::TearDown() {}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_TRUE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0500, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0600, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0700, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
    readInt32List.push_back(true);
    readInt32List.push_back(true);
    MockReadInt32(true, &readInt32List);

    std::list<bool> readUint32List;
    readUint32List.push_back(true);
    readUint32List.push_back(false);
    MockReadUint32(true, 5, &readUint32List);

    std::list<bool> readString16List;
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    readString16List.push_back(true);
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0800, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_0900, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, ReadFromParcel_1000, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_FALSE(downloadableProfilesResult.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0100, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_TRUE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0200, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0300, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0400, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0500, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0600, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0700, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0800, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_0900, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_FALSE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Marshalling_1000, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    downloadableProfilesResult.downloadableProfiles_.resize(5);
    DownloadableProfile downloadableProfile;
    downloadableProfile.accessRules_.resize(5);
    std::list<bool> writeInt32List;
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
    MockWriteString16(true, &writeString16List);
    EXPECT_TRUE(downloadableProfilesResult.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_NE(downloadableProfilesResult.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(GetDownloadableProfilesResultTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    GetDownloadableProfilesResult downloadableProfilesResult;
    Parcel parcel;
    std::list<bool> readInt32List;
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
    MockReadString16(true, &readString16List);
    EXPECT_EQ(downloadableProfilesResult.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS

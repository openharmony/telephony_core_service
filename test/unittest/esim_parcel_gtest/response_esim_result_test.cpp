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

#include "response_esim_result.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
class ResponseEsimResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ResponseEsimResultTest::SetUpTestCase(void) {}

void ResponseEsimResultTest::TearDownTestCase(void) {}

void ResponseEsimResultTest::SetUp() {}

void ResponseEsimResultTest::TearDown() {}

HWTEST_F(ResponseEsimResultTest, ReadFromParcel_0100, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(true);
    MockReadString16(true);
    EXPECT_TRUE(responseEsimResultTest.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, ReadFromParcel_0200, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(false);
    MockReadString16(true);
    EXPECT_FALSE(responseEsimResultTest.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, ReadFromParcel_0300, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(true);
    MockReadString16(false);
    EXPECT_FALSE(responseEsimResultTest.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, ReadFromParcel_0400, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(false);
    MockReadString16(false);
    EXPECT_FALSE(responseEsimResultTest.ReadFromParcel(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Marshalling_0100, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockWriteInt32(true);
    MockWriteString16(true);
    EXPECT_TRUE(responseEsimResultTest.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Marshalling_0200, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockWriteInt32(false);
    MockWriteString16(true);
    EXPECT_FALSE(responseEsimResultTest.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Marshalling_0300, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockWriteInt32(true);
    MockWriteString16(false);
    EXPECT_FALSE(responseEsimResultTest.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Marshalling_0400, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockWriteInt32(false);
    MockWriteString16(false);
    EXPECT_FALSE(responseEsimResultTest.Marshalling(parcel));
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(true);
    MockReadString16(true);
    EXPECT_NE(responseEsimResultTest.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Unmarshalling_0200, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(false);
    MockReadString16(true);
    EXPECT_EQ(responseEsimResultTest.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Unmarshalling_0300, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(true);
    MockReadString16(false);
    EXPECT_EQ(responseEsimResultTest.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}

HWTEST_F(ResponseEsimResultTest, Unmarshalling_0400, Function | MediumTest | Level1)
{
    ResponseEsimResult responseEsimResultTest;
    Parcel parcel;
    MockReadInt32(false);
    MockReadString16(false);
    EXPECT_EQ(responseEsimResultTest.Unmarshalling(parcel), nullptr);
    ResetParcelState();
}
} // namespace Telephony
} // namespace OHOS

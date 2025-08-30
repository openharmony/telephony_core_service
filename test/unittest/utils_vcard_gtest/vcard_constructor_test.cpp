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

#include "vcard_constructor.h"
#include "vcard_contact.h"

#include <fcntl.h>
#include <iostream>
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {

class VcardConstructorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void VcardConstructorTest::SetUpTestCase() {}

void VcardConstructorTest::TearDownTestCase() {}

void VcardConstructorTest::SetUp() {}

void VcardConstructorTest::TearDown() {}

HWTEST_F(VcardConstructorTest, Vcard_Constructor_AddPhotoLine_001, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardConstructor> constructor = std::make_shared<VCardConstructor>(0, "");
    constructor->result_.str("");
    constructor->AddPhotoLine("", "");
    EXPECT_EQ(constructor->result_.str(), "PHOTO;ENCODING=BASE64:\r\n\r\n");

    constructor->result_.str("");
    constructor->AddPhotoLine("Byte1Byte2Byte3Byte4Byte5Byte6Byte7Byte8Byte9Byte0"
        "Byte1Byte2Byte3Byte4Byte5Byte6Byte7Byte8Byte9Byte0", "");
    EXPECT_EQ(constructor->result_.str(),
        "PHOTO;ENCODING=BASE64:Byte1Byte2Byte3Byte4Byte5Byte6Byte7Byte8Byte9Byte0B\r\n"
        " yte1Byte2Byte3Byte4Byte5Byte6Byte7Byte8Byte9Byte0\r\n\r\n");
    
    constructor->result_.str("");
    constructor->AddPhotoLine("Byte", "JPEG");
    EXPECT_EQ(constructor->result_.str(), "PHOTO;ENCODING=BASE64;JPEG:Byte\r\n\r\n");

    constructor->isV30OrV40_ = true;
    constructor->result_.str("");
    constructor->AddPhotoLine("Byte", "");
    EXPECT_EQ(constructor->result_.str(), "PHOTO;ENCODING=B:Byte\r\n\r\n");

    constructor->result_.str("");
    constructor->AddPhotoLine("Byte", "JPEG");
    EXPECT_EQ(constructor->result_.str(), "PHOTO;ENCODING=B;TYPE=JPEG:Byte\r\n\r\n");
}

HWTEST_F(VcardConstructorTest, Vcard_Constructor_EncodeQuotedPrintable_001, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardConstructor> constructor = std::make_shared<VCardConstructor>(0, "");
    constructor->result_.str("");
    auto res = constructor->EncodeQuotedPrintable("Byte");
    EXPECT_EQ(res, "=42=79=74=65");

    constructor->result_.str("");
    res = constructor->EncodeQuotedPrintable("Byte1Byte2Byte3Byte4Byte5Byte6");
    EXPECT_EQ(res, "=42=79=74=65=31=42=79=74=65=32=42=79=74=65=33=42=79=74=65=34=42=79=74\r\n=65=35=42=79=74=65=36");
}

HWTEST_F(VcardConstructorTest, Vcard_Constructor_ContactEnd_001, Function | MediumTest | Level3)
{
    std::shared_ptr<VCardContact> contact = std::make_shared<VCardContact>();
    std::shared_ptr<VCardConstructor> constructor = std::make_shared<VCardConstructor>(0, "");
    constructor->result_.str("");
    constructor->ContactBegin();
    constructor->ContactEnd();
    EXPECT_EQ(constructor->result_.str(), "");

    int32_t errorCode = 0;
    constructor->result_.str("");
    contact->AddRawData(nullptr, errorCode);
    contact->AddEmail(static_cast<int32_t>(EmailType::EMAIL_HOME), "abc@gmail.com", "", "", true);
    constructor->ContactBegin();
    constructor->ConstructEmails(contact);
    constructor->ContactEnd();
    EXPECT_EQ(constructor->result_.str(),
        "BEGIN:VCARD\r\nVERSION:2.1\r\nEMAIL;HOME:abc@gmail.com\r\nEND:VCARD\r\n");
}

}  // namespace Telephony
}  // namespace OHOS
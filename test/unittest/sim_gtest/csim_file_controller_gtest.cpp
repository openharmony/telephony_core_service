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

#include <string>
#include <unistd.h>
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "csim_file_controller.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class CsimFileControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CsimFileControllerTest::TearDownTestCase() {}

void CsimFileControllerTest::SetUp() {}

void CsimFileControllerTest::TearDown() {}

void CsimFileControllerTest::SetUpTestCase() {}

/**
 * @tc.number   Telephony_csim_File_Controller_001
 * @tc.name     CsimFileController
 * @tc.desc     Function test
 */
HWTEST_F(CsimFileControllerTest, Telephony_csim_File_Controller_001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    auto csimFileController = std::make_shared<CsimFileController>(slotId);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SMS);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CST);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_FDN);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MSISDN);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_LI);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_MDN);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_IMSIM);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_CDMAHOME);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_EPRL);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_MIPUPP);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_IMPU);
    csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_ICCID);
    auto ret = csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_RUIM_SPN);
    auto strs = "3F007FFF";
    EXPECT_EQ(ret, strs);
}
}
}
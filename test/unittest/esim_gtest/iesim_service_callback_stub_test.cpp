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

#include "iesim_service_callback_stub.h"
#include "ipc_types.h"
#include "iremote_stub.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t DEFAULT_ERROR = -1;
constexpr int32_t DEFAULT_RESULT = 0;
class IEsimServiceCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IEsimServiceCallbackStubTest::SetUpTestCase()
{
}

void IEsimServiceCallbackStubTest::TearDownTestCase()
{
}

void IEsimServiceCallbackStubTest::SetUp() {}

void IEsimServiceCallbackStubTest::TearDown() {}

HWTEST_F(IEsimServiceCallbackStubTest, OnGetEuiccProfileInfoList, Function | MediumTest | Level1)
{
    MessageParcel data;
    std::shared_ptr<IEsimServiceCallbackStub> stub = std::make_shared<IEsimServiceCallbackStub>();
    int endIndex = static_cast<int>(IEsimServiceCallback::EsimServiceCallback::GET_EID_RESULT);
    for (int requestId = static_cast<int>(IEsimServiceCallback::EsimServiceCallback::GET_EUICCINFO_RESULT);
        requestId < endIndex + 1;
        requestId++) {
        int32_t ret = stub->OnEsimServiceCallback(
            static_cast<IEsimServiceCallback::EsimServiceCallback>(requestId), data);
        EXPECT_EQ(ret, DEFAULT_RESULT);
    }
}

HWTEST_F(IEsimServiceCallbackStubTest, OnGetEuiccProfileInfoListFailed, Function | MediumTest | Level1)
{
    MessageParcel data;
    std::shared_ptr<IEsimServiceCallbackStub> stub = std::make_shared<IEsimServiceCallbackStub>();
    constexpr uint32_t outIndex = 99;
    int32_t ret = stub->OnEsimServiceCallback(static_cast<IEsimServiceCallback::EsimServiceCallback>(outIndex), data);
    EXPECT_EQ(ret, DEFAULT_ERROR);
}
} // namespace Telephony
} // namespace OHOS
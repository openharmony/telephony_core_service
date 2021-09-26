/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_TEL_RIL_TEST_H
#define OHOS_TEL_RIL_TEST_H

#include <gtest/gtest.h>
#include "core_service_proxy.h"
#include "core.h"
namespace OHOS {
namespace Telephony {
using namespace std;

class TelRilTest : public testing::Test {
public:
    TelRilTest();
    ~TelRilTest();
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();

    std::shared_ptr<Telephony::IRilManager> rilManager_ = nullptr;

    void OnInitInterface();

    void OnInitCall();

    void OnInitSms();

    void OnInitSim();

    void OnInitNetwork();

    void OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnProcessTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetIccIDTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallSplitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkVoiceRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCmCellBroadcastTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRadioStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRadioStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkLocationUpdateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void SimTest();
    void CallTest();
    void SmsTest();

    const int CID = 1;
    const int REASON = 2;
    const int EVENT_3 = 3;
    const int AUTHTYPE_4 = 4;
    const int EVENT_5 = 5;
    const int EVENT_6 = 6;
    const int TYPE = 7;
    const int MAXCONNSTIME = 8;
    const int MAXCONNS = 9;
    const int WAITTIME = 10;
    const int EVENT_11 = 11;
    const int TYPESBITMAP = 12;
    const int EVENT_13 = 13;
    const int BEARERBITMAP = 14;
    const int P3 = 15;
    const int COMMAND = 192;
    const int FILEID = 20272;
    const int AUTHTYPE_1 = -1;

    class DemoHandler : public AppExecFwk::EventHandler {
    public:
        explicit DemoHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
            : AppExecFwk::EventHandler(runner)
        {}

        ~DemoHandler() {}

        void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    };

private:
    using RilManagerAndResponseTestFun = void (TelRilTest::*)(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    map<uint32_t, RilManagerAndResponseTestFun> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS

#endif
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
#define private public
#define protected public

#include <string>
#include <unistd.h>

#include "asn1_node.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "esim_file.h"
#include "gtest/gtest.h"
#include "icc_file.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "tel_ril_manager.h"
#include "telephony_tag_def.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimTest::TearDownTestCase() {}

void EsimTest::SetUp() {}

void EsimTest::TearDown() {}

void EsimTest::SetUpTestCase() {}

HWTEST_F(EsimTest, ObtainEuiccInfo2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    ResponseEsimResult responseInfo2Result;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(responseInfo2Result.resultCode, (esimFile->ObtainEuiccInfo2(portIndex)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(responseInfo2Result.resultCode, (esimFile->ObtainEuiccInfo2(portIndex)).resultCode);
}

HWTEST_F(EsimTest, ProcessObtainEUICCInfo2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo2 = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO2_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessObtainEUICCInfo2(slotId, eventEUICCInfo2), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessObtainEUICCInfo2(slotId, eventEUICCInfo2), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEUICCInfo2(slotId, eventEUICCInfo2), true);
}

HWTEST_F(EsimTest, EuiccInfo2ParseProfileVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseProfileVersion(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccFirmwareVer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccFirmwareVer(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseExtCardResource_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseExtCardResource(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseUiccCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseUiccCapability(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseTs102241Version_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseTs102241Version(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseGlobalPlatformVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseGlobalPlatformVersion(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseRspCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseRspCapability(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccCiPKIdListForVerification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForVerification(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccCiPKIdListForSigning_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForSigning(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccCategory_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccCategory(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, EuiccInfo2ParsePpVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 *euiccInfo2 = new EuiccInfo2();
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParsePpVersion(euiccInfo2, root);
    delete (euiccInfo2);
}

HWTEST_F(EsimTest, AuthenticateServer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    AuthenticateConfigInfo authenticateConfigInfo;
    ResponseEsimResult responseAuthenticateResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(responseAuthenticateResult.resultCode,
        (esimFile->AuthenticateServer(authenticateConfigInfo)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(responseAuthenticateResult.resultCode,
        (esimFile->AuthenticateServer(authenticateConfigInfo)).resultCode);
}

HWTEST_F(EsimTest, ObtainPrepareDownload_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string hashCc;
    std::u16string smdpSigned2;
    std::u16string smdpSignature2;
    std::u16string smdpCertificate;
    ResponseEsimResult preDownloadResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(preDownloadResult.resultCode, (esimFile->ObtainPrepareDownload(
        portIndex, hashCc, smdpSigned2, smdpSignature2, smdpCertificate)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(preDownloadResult.resultCode, (esimFile->ObtainPrepareDownload(
        portIndex, hashCc, smdpSigned2, smdpSignature2, smdpCertificate)).resultCode);
}

HWTEST_F(EsimTest, ObtainLoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult loadBPPResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(loadBPPResult.resultCode, (esimFile->ObtainLoadBoundProfilePackage(
        portIndex, boundProfilePackage)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(loadBPPResult.resultCode, (esimFile->ObtainLoadBoundProfilePackage(
        portIndex, boundProfilePackage)).resultCode);
}

HWTEST_F(EsimTest, ListNotifications_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    Event events = Event::EVENT_DONOTHING;
    esimFile->currentChannelId_ = 0;
    EXPECT_TRUE((esimFile->ListNotifications(portIndex, events)).euiccNotification.empty());
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE((esimFile->ListNotifications(portIndex, events)).euiccNotification.empty());
}

HWTEST_F(EsimTest, ProcessListNotifications_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventListNotif = iccFile->BuildCallerInfo(MSG_ESIM_LIST_NOTIFICATION);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
}

HWTEST_F(EsimTest, ProcessListNotificationsDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessListNotificationsDone(event));
    auto eventListNotif = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessListNotificationsDone(eventListNotif), false);
    eventListNotif = nullptr;
    EXPECT_EQ(esimFile->ProcessListNotificationsDone(eventListNotif), false);
}

HWTEST_F(EsimTest, RetrieveNotificationList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    Event events = Event::EVENT_DONOTHING;
    esimFile->currentChannelId_ = 0;
    EXPECT_TRUE((esimFile->RetrieveNotificationList(portIndex, events)).euiccNotification.empty());
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE((esimFile->RetrieveNotificationList(portIndex, events)).euiccNotification.empty());
}

HWTEST_F(EsimTest, ObtainRetrieveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(notification.seq, (esimFile->ObtainRetrieveNotification(portIndex, seqNumber)).seq);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(notification.seq, (esimFile->ObtainRetrieveNotification(portIndex, seqNumber)).seq);
}

HWTEST_F(EsimTest, RemoveNotificationFromList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultState removeNotifResult = ResultState::RESULT_OK;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(removeNotifResult, esimFile->RemoveNotificationFromList(portIndex, seqNumber));
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(removeNotifResult, esimFile->RemoveNotificationFromList(portIndex, seqNumber));
}

HWTEST_F(EsimTest, ProcessRemoveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRemoveNotif = iccFile->BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
}

HWTEST_F(EsimTest, ProcessRemoveNotificationDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3003800100";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRemoveNotificationDone(event));
    auto eventRemoveNotif = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRemoveNotificationDone(eventRemoveNotif), false);
    eventRemoveNotif = nullptr;
    EXPECT_EQ(esimFile->ProcessRemoveNotificationDone(eventRemoveNotif), false);
}

HWTEST_F(EsimTest, IsEsimSupported_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EXPECT_FALSE(esimFile->IsEsimSupported());
}

HWTEST_F(EsimTest, SendApduData_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::u16string aid;
    std::u16string apduData;
    ResponseEsimResult transApduDataResponse_;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(transApduDataResponse_.resultCode, (esimFile->SendApduData(aid, apduData)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(transApduDataResponse_.resultCode, (esimFile->SendApduData(aid, apduData)).resultCode);
}

HWTEST_F(EsimTest, ProcessObtainEuiccInfo1_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo1 = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1), true);
}

HWTEST_F(EsimTest, ProcessObtainEuiccInfo1Done_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF20618203020202A92C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30414C0BC70BA369"
        "29D43B467FF57570530E57AB8FCD8AA2C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30414C30C020BA55929D43B467FF3"
        "6360530E57AB8FCD8";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainEuiccInfo1Done(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1Done(event), false);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1Done(event1), false);
}

HWTEST_F(EsimTest, ProcessObtainEuiccInfo1Done_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF20068004AABBCCDD";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessObtainEuiccInfo1Done(event));
}

HWTEST_F(EsimTest, ProcessDeleteProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventDeleteProfile = iccFile->BuildCallerInfo(MSG_ESIM_DELETE_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));
    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));
    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));
}

HWTEST_F(EsimTest, ProcessDeleteProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF33038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessDeleteProfileDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessDeleteProfileDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessDeleteProfileDone(event1));
}

HWTEST_F(EsimTest, ProcessSwitchToProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSwitchToProfile = iccFile->BuildCallerInfo(MSG_ESIM_SWITCH_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));
    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));
    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_TRUE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));
}

HWTEST_F(EsimTest, ProcessSwitchToProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3103800100";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessSwitchToProfileDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessSwitchToProfileDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessSwitchToProfileDone(event1));
}

HWTEST_F(EsimTest, ProcessSetNickname_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSetNickName = iccFile->BuildCallerInfo(MSG_ESIM_SET_NICK_NAME);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));
    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessSetNickname(slotId, eventSetNickName));
    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_TRUE(esimFile->ProcessSetNickname(slotId, eventSetNickName));
}

HWTEST_F(EsimTest, ProcessSetNicknameDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF31038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessSetNicknameDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessSetNicknameDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessSetNicknameDone(event1));
}

HWTEST_F(EsimTest, ProcessEstablishDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSetSmdpAddress =
        iccFile->BuildCallerInfo(MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessEstablishDefaultSmdpAddress(slotId, eventSetSmdpAddress));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessEstablishDefaultSmdpAddress(slotId, eventSetSmdpAddress));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessEstablishDefaultSmdpAddress(slotId, eventSetSmdpAddress));
}

HWTEST_F(EsimTest, ProcessEstablishDefaultSmdpAddressDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3F19800C1630313233343536373839303132333435363712121212";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessEstablishDefaultSmdpAddressDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessEstablishDefaultSmdpAddressDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessEstablishDefaultSmdpAddressDone(event1));
}

HWTEST_F(EsimTest, ProcessObtainDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSmdpAddress =
        iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
}

HWTEST_F(EsimTest, ProcessObtainDefaultSmdpAddressDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3C148008534D44502E434F4D8108AA59BBCCDD1515159000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainDefaultSmdpAddressDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddressDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddressDone(event1));
}

HWTEST_F(EsimTest, ProcessCancelSession_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventCancelSession = iccFile->BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
}

HWTEST_F(EsimTest, ProcessCancelSessionDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF41009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessCancelSessionDone(event));
    std::shared_ptr<IccControllerHolder> holder1 = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg1 = std::make_unique<Telephony::IccFromRilMsg>(holder1);
    rcvMsg1->fileData.resultData = "BF4106810400000001";
    event = AppExecFwk::InnerEvent::Get(0, rcvMsg1);
    EXPECT_FALSE(esimFile->ProcessCancelSessionDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessCancelSessionDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessCancelSessionDone(event1));
}

HWTEST_F(EsimTest, ProcessGetProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventGetProfile = iccFile->BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    esimFile->currentChannelId_ = 2;
    std::string str = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    std::string iccIdstr = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdstr);
    EXPECT_TRUE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
}

HWTEST_F(EsimTest, ProcessGetProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2D8184A08181E37F"
                                 "5A0A89670000000000AABBCC" // ICCID
                                 "90046E69AABB" // Nickname
                                 "910374AABB" // Service provider name
                                 "9202CCDD" // Profile name
                                 "B70F800312F34581030102038211223344" // Operator id
                                 "9F70AACC" // Profile state
                                 "95DDCC" // Profile class
                                 "9902BBAA" // Policy rules
                                 "BF7645E243E135C114ABCD92CBB156B280FA4E1429A6ECEEB6AABBCCDD"
                                 "CA1D636F6D2E676F6F676C652E616E64726F69642E617070732E6DAABBCCDD"
                                 "E30ADB0800000000000000AA" // Carrier privilege rules
                                 "9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessGetProfileDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessGetProfileDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessGetProfileDone(event1));
}

HWTEST_F(EsimTest, ProcessGetProfileDone_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2D";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessGetProfileDone(event));
}

HWTEST_F(EsimTest, ProcessObtainSmdsAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventObtainSmdsAddress = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_SMDS_ADDRESS);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
}

HWTEST_F(EsimTest, ProcessObtainSmdsAddressDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3C148008534D44502E434F4D8108736D647AABBDDCCD9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainSmdsAddressDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event));
}

HWTEST_F(EsimTest, ProcessAuthenticateServer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessAuthenticateServer(slotId));
    esimFile->currentChannelId_ = 2;
    EXPECT_TRUE(esimFile->ProcessAuthenticateServer(slotId));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessAuthenticateServer(slotId));
}

HWTEST_F(EsimTest, ProcessAuthenticateServerDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.sw1 = 90;
    rcvMsg->fileData.sw2 = 00;
    rcvMsg->fileData.resultData = "BF388205E5A08205E13082011C8008D14FE1DE62C340D7831E31302E31302E31322E3136342F647"
        "02D706C75732D696E746572666163658410F31F2690404C42718528B2301082A071BF2281A68103020301820302020283030402008"
        "40D81010082040007AE2E83022F378505067F32F7C08603090200870302030088020490A92C0414F54172BDF98A95D65CBEB88A38A"
        "1C11D800A85C30414C0BC70BA36929D43B467FF57570530E57AB8FCD8AA2C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30"
        "414C0BC70BA36929D43B467FF57570530E57AB8FCD88B010004030100000C0D45442D5A492D55502D30383234A0348017503658313"
        "72D3833594C332D52345230592D4E56523332A119800468396860A10F80030B000081030B000085030B000082005F3740B939AD87D"
        "29B5505CB5C00ACAABD3E156C680EF9A15B99D8C4361A9B4CA59C112D9CC649463515A860F534A1822536F537F7D422651F9D19A40"
        "384C90A2FFCCC308201FE308201A5A0030201020209020000000000000001300A06082A8648CE3D0403023037310B3009060355040"
        "61302455331153013060355040A0C0C52535020546573742045554D3111300F06035504030C0845554D20546573743020170D32303"
        "03430313039343835385A180F37343936303132343039343835385A3064310B300906035504061302455331153013060355040A0C0"
        "C52535020546573742045554D312930270603550405132038393038363033303230323230303030303032343030303037303935313"
        "331393113301106035504030C0A546573742065554943433059301306072A8648CE3D020106082A8648CE3D030107034200046DB3F"
        "53ADC87DC2FF10C7BFCD87AD13AE97009AFA065A6757EE571B3F2EBB18F46C1D68F3EDEB0E74B2E5D542051E7D27F50952028605AF"
        "DEF79FE9FFFD03959A36B3069301F0603551D23041830168014DD3DA24D350C1CC5D0AF0965F40EC34C5EE409F1301D0603551D0E0"
        "4160414A52476AF5D50AA376437CCB1DA2172EF45F484F0300E0603551D0F0101FF04040302078030170603551D200101FF040D300"
        "B3009060767811201020101300A06082A8648CE3D040302034700304402200858D232D4649A8BDA7B9441C1215854B1BC48AB52D24"
        "1CF57BA7D6FA0EB5191022009ED2C93F2184ECD34F2E42FD64B1DC68CF38EAB6CDBA9ADDDBD0139629C55CC308202783082021FA00"
        "3020102020412345678300A06082A8648CE3D04030230443110300E06035504030C07546573742043493111300F060355040B0C085"
        "4455354434552543110300E060355040A0C0752535054455354310B30090603550406130249543020170D323030343031303932383"
        "3375A180F32303534303332343039323833375A3037310B300906035504061302455331153013060355040A0C0C525350205465737"
        "42045554D3111300F06035504030C0845554D20546573743059301306072A8648CE3D020106082A8648CE3D030107034200041330D"
        "59256AC0CB50BD928D0F4C68007C485FE3F42988AD3EE3875AE33F4983AB23B4DD4C31340D676DD8E11F9C5CBA1B11EB694EED0994"
        "DB529285E632C8906A382010830820104301F0603551D23041830168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3301D060"
        "3551D0E04160414DD3DA24D350C1CC5D0AF0965F40EC34C5EE409F1300E0603551D0F0101FF04040302020430170603551D200101F"
        "F040D300B3009060767811201020102300E0603551D1104073005880388370530120603551D130101FF040830060101FF020100303"
        "50603551D1F042E302C302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D422E63726"
        "C303E0603551D1E0101FF04343032A030302EA42C302A31153013060355040A0C0C52535020546573742045554D3111300F0603550"
        "40513083839303439303332300A06082A8648CE3D040302034700304402200C567BF01E45244863AD7A4613F7572EEF3439F698B47"
        "11AA397AEEFC5445CE702206E993AA0A505F260B0EEF62CC30A2BBE453B0E8248218FD53304EF7FAABBCCDD";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessAuthenticateServerDone(event))
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessAuthenticateServerDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessAuthenticateServerDone(event1));
}

HWTEST_F(EsimTest, ProcessPrepareDownload_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessPrepareDownload(slotId));
    esimFile->currentChannelId_ = 2;
    EXPECT_TRUE(esimFile->ProcessPrepareDownload(slotId));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessPrepareDownload(slotId));
}

HWTEST_F(EsimTest, ProcessPrepareDownloadDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF218196A08193304E8008D14FE1DE62C340D75F494104B067E0DF2D080C747D76DF98198D"
        "B8766625CB216E62A2796003287E41E8DAD1D28229C14B9F5D7901D03D224D6AEC6EF031BA9176D50298ECB42F56739014365"
        "F37400A3F852229A3A0606F5E90FF9D2F2DEDE548C5FF87473D6A49A7EED53672D2DF5A4555E9F314F65668AEE8F1C5B3229E"
        "629CD27CF9DC6A5768A93B01AABBCCDD";
    rcvMsg->fileData.sw1 = 0x90;
    rcvMsg->fileData.sw2 = 0x00;
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(event1));
}

HWTEST_F(EsimTest, ProcessRetrieveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRetrieveNotification =
        iccFile->BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
}

HWTEST_F(EsimTest, ObtainEuiccInfo1ParseTagCtx2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t tag = 0;
    std::string src;
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    asn1Node->constructed_ = false;
    bool ret = esimFile->ObtainEuiccInfo1ParseTagCtx2(asn1Node);
    EXPECT_EQ(ret, false);
}

HWTEST_F(EsimTest, GetProfileDoneParseProfileInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t tag = 0;
    std::string src;
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    asn1Node->constructed_ = false;
    EXPECT_FALSE(esimFile->GetProfileDoneParseProfileInfo(asn1Node));
}

HWTEST_F(EsimTest, ConvertAuthInputParaFromApiStru_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    Es9PlusInitAuthResp bytes;
    esimFile->ConvertAuthInputParaFromApiStru(bytes, esimFile->esimProfile_);
}

HWTEST_F(EsimTest, Asn1AddChildAsBase64_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_AUTHENTICATE_SERVER);
    Es9PlusInitAuthResp bytes;
    Es9PlusInitAuthResp *pbytes = &bytes;
    esimFile->Asn1AddChildAsBase64(builder, pbytes->serverSigned1);
    esimFile->Asn1AddChildAsBase64(builder, pbytes->serverSignature1);
    esimFile->Asn1AddChildAsBase64(builder, pbytes->euiccCiPKIdToBeUsed);
    esimFile->Asn1AddChildAsBase64(builder, pbytes->serverCertificate);
}

HWTEST_F(EsimTest, AddCtxParams1_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Builder> ctxParams1Builder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    Es9PlusInitAuthResp bytes;
    Es9PlusInitAuthResp *pbytes = &bytes;
    esimFile->AddCtxParams1(ctxParams1Builder, pbytes);
}

HWTEST_F(EsimTest, AddDeviceCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Builder> devCapsBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_1);
    Es9PlusInitAuthResp bytes;
    Es9PlusInitAuthResp *pbytes = &bytes;
    esimFile->AddDeviceCapability(devCapsBuilder, pbytes);
}

HWTEST_F(EsimTest, GetImeiBytes_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    Es9PlusInitAuthResp bytes;
    Es9PlusInitAuthResp *pbytes = &bytes;
    std::string imeiBytes;
    esimFile->GetImeiBytes(imeiBytes, pbytes->imei);
}

HWTEST_F(EsimTest, RealProcsessAuthenticateServerDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string recvCombineStr = "BF388205E5A08205E13082011C8008D14FE1DE62C340D7831E31302E31302E31322E3136342F647"
        "02D706C75732D696E746572666163658410F31F2690404C42718528B2301082A071BF2281A68103020301820302020283030402008"
        "40D81010082040007AE2E83022F378505067F32F7C08603090200870302030088020490A92C0414F54172BDF98A95D65CBEB88A38A"
        "1C11D800A85C30414C0BC70BA36929D43B467FF57570530E57AB8FCD8AA2C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30"
        "414C0BC70BA36929D43B467FF57570530E57AB8FCD88B010004030100000C0D45442D5A492D55502D30383234A0348017503658313"
        "72D3833594C332D52345230592D4E56523332A119800468396860A10F80030B000081030B000085030B000082005F3740B939AD87D"
        "29B5505CB5C00ACAABD3E156C680EF9A15B99D8C4361A9B4CA59C112D9CC649463515A860F534A1822536F537F7D422651F9D19A40"
        "384C90A2FFCCC308201FE308201A5A0030201020209020000000000000001300A06082A8648CE3D0403023037310B3009060355040"
        "61302455331153013060355040A0C0C52535020546573742045554D3111300F06035504030C0845554D20546573743020170D32303"
        "03430313039343835385A180F37343936303132343039343835385A3064310B300906035504061302455331153013060355040A0C0"
        "C52535020546573742045554D312930270603550405132038393038363033303230323230303030303032343030303037303935313"
        "331393113301106035504030C0A546573742065554943433059301306072A8648CE3D020106082A8648CE3D030107034200046DB3F"
        "53ADC87DC2FF10C7BFCD87AD13AE97009AFA065A6757EE571B3F2EBB18F46C1D68F3EDEB0E74B2E5D542051E7D27F50952028605AF"
        "DEF79FE9FFFD03959A36B3069301F0603551D23041830168014DD3DA24D350C1CC5D0AF0965F40EC34C5EE409F1301D0603551D0E0"
        "4160414A52476AF5D50AA376437CCB1DA2172EF45F484F0300E0603551D0F0101FF04040302078030170603551D200101FF040D300"
        "B3009060767811201020101300A06082A8648CE3D040302034700304402200858D232D4649A8BDA7B9441C1215854B1BC48AB52D24"
        "1CF57BA7D6FA0EB5191022009ED2C93F2184ECD34F2E42FD64B1DC68CF38EAB6CDBA9ADDDBD0139629C55CC308202783082021FA00"
        "3020102020412345678300A06082A8648CE3D04030230443110300E06035504030C07546573742043493111300F060355040B0C085"
        "4455354434552543110300E060355040A0C0752535054455354310B30090603550406130249543020170D323030343031303932383"
        "3375A180F32303534303332343039323833375A3037310B300906035504061302455331153013060355040A0C0C525350205465737"
        "42045554D3111300F06035504030C0845554D20546573743059301306072A8648CE3D020106082A8648CE3D030107034200041330D"
        "59256AC0CB50BD928D0F4C68007C485FE3F42988AD3EE3875AE33F4983AB23B4DD4C31340D676DD8E11F9C5CBA1B11EB694EED0994"
        "DB529285E632C8906A382010830820104301F0603551D23041830168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3301D060"
        "3551D0E04160414DD3DA24D350C1CC5D0AF0965F40EC34C5EE409F1300E0603551D0F0101FF04040302020430170603551D200101F"
        "F040D300B3009060767811201020102300E0603551D1104073005880388370530120603551D130101FF040830060101FF020100303"
        "50603551D1F042E302C302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D422E63726"
        "C303E0603551D1E0101FF04343032A030302EA42C302A31153013060355040A0C0C52535020546573742045554D3111300F0603550"
        "40513083839303439303332300A06082A8648CE3D040302034700304402200C567BF01E45244863AD7A4613F7572EEF3439F698B47"
        "11AA397AEEFC5445CE702206E993AA0A505F260B0EEF62CC30A2BBE453B0E8248218FD53304EF7F90AABBCC";
    EXPECT_TRUE(esimFile->RealProcsessAuthenticateServerDone(recvCombineStr));
}

HWTEST_F(EsimTest, CombineResponseDataFinish_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    IccFileData fileData;
    fileData.resultData = "";
    EXPECT_FALSE(esimFile->CombineResponseDataFinish(fileData));
    fileData.resultData = "123456";
    fileData.sw1 = 0x90;
    fileData.sw2 = 0x00;
    EXPECT_TRUE(esimFile->CombineResponseDataFinish(fileData));
}

HWTEST_F(EsimTest, CovertAuthToApiStruct_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    ResponseEsimResult dst;
    AuthServerResponse src;
    esimFile->CovertAuthToApiStruct(dst, src);
}

HWTEST_F(EsimTest, ConvertPreDownloadParaFromApiStru_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    PrepareDownloadResp dst;
    EsimProfile src;
    esimFile->ConvertPreDownloadParaFromApiStru(dst, src);
}

HWTEST_F(EsimTest, ProcessRequestRulesAuthTable_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable =
        iccFile->BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    esimFile->currentChannelId_ = 1;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
}

HWTEST_F(EsimTest, RequestRulesAuthTableParseTagCtxComp0_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData = "BF434B"
                             "A0233021"
                             "8002AABB"
                             "A118"
                             "B70A800312F3458103AABBCC"
                             "B70A800312F3458203AABBCC"
                             "8201AA"
                             "A02430AA"
                             "8002AABB"
                             "A118"
                             "B70A800312E345810301AABB"
                             "B70A8003EEEE45820304AABB"
                             "8202AABB"
                             "9000";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_TRUE(esimFile->RequestRulesAuthTableParseTagCtxComp0(root));
    byteLen = 0;
    EXPECT_TRUE(esimFile->RequestRulesAuthTableParseTagCtxComp0(root));
}

HWTEST_F(EsimTest, ProcessRequestRulesAuthTableDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable =
        iccFile->BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF434B"
                                  "A0233021"
                                  "8002AABB"
                                  "A118"
                                  "B70A800312F3458103AABBCC"
                                  "B70A800312F3458203AABBCC"
                                  "8201AA"
                                  "A02430AA"
                                  "8002AABB"
                                  "A118"
                                  "B70A800312E345810301AABB"
                                  "B70A8003EEEE45820304AABB"
                                  "8202AABB"
                                  "9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTableDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRequestRulesAuthTableDone(event1), true);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessRequestRulesAuthTableDone(event1), true);
}

HWTEST_F(EsimTest, ProcessSendApduData_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSendApduData = iccFile->BuildCallerInfo(MSG_ESIM_SEND_APUD_DATA);
    esimFile->currentChannelId_ = 1;
    EXPECT_FALSE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
}

HWTEST_F(EsimTest, ProcessSendApduDataDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessSendApduDataDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessSendApduDataDone(event1), false);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessSendApduDataDone(event1), false);
}

HWTEST_F(EsimTest, ProcessRetrieveNotificationList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRetrieveListNotif =
        iccFile->BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_LIST);
    Event events = Event::EVENT_ENABLE;
    esimFile->currentChannelId_ = 1;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
}

HWTEST_F(EsimTest, ProcessRetrieveNotificationListDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData =
        "BF2B2FA02D3014BF2F118001010C08736D64702E636F6D810204103015BF2F128001020C09736D647032AABBCCDD8102AABB9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRetrieveNotificationListDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRetrieveNotificationListDone(event1), false);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessRetrieveNotificationListDone(event1), false);
}

HWTEST_F(EsimTest, RetrieveNotificationParseCompTag_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData =
        "BF2B2FA02D3014BF2F118001010C08736D64702E636F6D810204103015BF2F128001020C09736D647032AABBCCDD8102AABB9000";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(rcvMsg->fileData.resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_TRUE(esimFile->RetrieveNotificationParseCompTag(root));
}

HWTEST_F(EsimTest, ProcessIfNeedMoreResponse_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    int32_t slotId = 0;
    IccFileData &iccFileData = rcvMsg->fileData;
    EXPECT_FALSE(esimFile->ProcessIfNeedMoreResponse(iccFileData, MSG_ESIM_AUTHENTICATE_SERVER));
    iccFileData.sw1 = 0x61;
    EXPECT_FALSE(esimFile->ProcessIfNeedMoreResponse(iccFileData, MSG_ESIM_AUTHENTICATE_SERVER));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessIfNeedMoreResponse(iccFileData, MSG_ESIM_AUTHENTICATE_SERVER));
}

HWTEST_F(EsimTest, Asn1ParseResponse_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string response;
    int32_t respLength = 0;
    esimFile->Asn1ParseResponse(response, respLength);
}

HWTEST_F(EsimTest, createNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData = "BF2F118001010C08736D6470AABBCCDD8102AABB";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
}

HWTEST_F(EsimTest, BuildProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccProfileInfo euiccProfileInfo;
    memset_s(&euiccProfileInfo, sizeof(EuiccProfileInfo), 0, sizeof(EuiccProfileInfo));
    std::string resultData = "BF2D8184A08181E37F"
                             "5A0A89670000000000AABBCC"
                             "9004AABBCCDD"
                             "9103AABBCC"
                             "9202AABB"
                             "B70F800312F34581030102038203112233"
                             "9F7001AA"
                             "9501DD"
                             "9902AABB"
                             "BF7645E243E135C114ABCD92CBB156B280FA4E1429A6ECEEB6E5AABBCC"
                             "CA1D636F6D2E676F6F676C652E616E64726F69642E617070732E6D79AABBCC"
                             "E30ADB0800000000000000AA"
                             "9000";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, responseByte.length());
    std::shared_ptr<Asn1Node> profileInfo =
        profileNode->Asn1GetChildChild(2, TAG_ESIM_CTX_COMP_0, TAG_ESIM_PROFILE_INFO);
    esimFile->BuildProfile(&euiccProfileInfo, profileInfo);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6D81020410BF2F128001020C09736D647032AABBCCDD8102AABB9000";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    bool isFileHandleResponse = false;
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode, isFileHandleResponse), false);
}

HWTEST_F(EsimTest, ProcessLoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventGetProfile = iccFile->BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackage(slotId));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackage(slotId));
    esimFile->esimProfile_.boundProfilePackage = Str8ToStr16(boundProfilePackage);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessLoadBoundProfilePackage(slotId));
}

HWTEST_F(EsimTest, DecodeBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    std::string boundProfilePackageStr = "some_decode_data";
    EXPECT_FALSE(esimFile->DecodeBoundProfilePackage(boundProfilePackageStr, bppNode));
}

HWTEST_F(EsimTest, BuildApduForInitSecureChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> initSecureChannelReq = bppNode->Asn1GetChild(TAG_ESIM_INITIALISE_SECURE_CHANNEL);
    esimFile->BuildApduForInitSecureChannel(codec, bppNode, initSecureChannelReq);
}

HWTEST_F(EsimTest, BuildApduForFirstSequenceOf87_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> firstSequenceOf87 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    esimFile->BuildApduForFirstSequenceOf87(codec, firstSequenceOf87);
}

HWTEST_F(EsimTest, BuildApduForSequenceOf88_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> sequenceOf88 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    esimFile->BuildApduForSequenceOf88(codec, sequenceOf88);
}

HWTEST_F(EsimTest, BuildApduForSequenceOf86_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> sequenceOf86 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_3);
    esimFile->BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
}

HWTEST_F(EsimTest, MergeRecvLongDataComplete_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    IccFileData fileData;
    fileData.resultData = "";
    EXPECT_FALSE(esimFile->MergeRecvLongDataComplete(fileData));
}
} // namespace Telephony
} // namespace OHOS
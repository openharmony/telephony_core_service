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
#include "sim_file_manager.h"
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

static const std::string bppCombineHexStr = "BF3781ADBF27678008D14FE1DE62C340D7BF2F3480024C66810207800C1E31302E313" +
    "02E31322E3136342F64702D706C75732D696E746572666163655A0A98680010203040506080060388370AA21FA01D4F10A000000559101" +
    "0FFFFFFFF890000120004093007A00530038001005F3740B354AE39D08ACD7EDD7D2D01C73378621F623B832DFA3243489C5B42C90F220" +
    "14E6C928130D78EE561982EF412AC3D94C04B56F37657DA84FD7BB24DD4153E88";

static const std::string boundProfilePackage = static const std::string boundProfilePackage = "vzaCFPW/I4GjggEBgAiX" +
    "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";

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

HWTEST_F(EsimTest, ProcessPrepareDownload_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessPrepareDownload(slotId));

    esimFile->currentChannelId_ = 2;
    EXPECT_TRUE(esimFile->ProcessPrepareDownload(slotId));

    std::u16string str = u"hashCctest";
    esimFile->esimProfile_.hashCc = str;
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
    rcvMsg->fileData.resultData =
        "BF218196A08193304E8008D14FE1DE62C340D75F494104B067E0DF2D080C747D76DF98198DB8766625CB216E62A2796003287E41"
        "E8DAD1D28229C14B9F5D7901D03D224D6AEC6EF031BA9176D50298ECB42F56739014365F37400A3F852229A3A0606F5E90FF9D2F"
        "2DEDE548C5FF87473D6A49A7EED53672D2DF5A4555E9F314F65668AEE8F1C5B3229E629CD27CF9DC6A5768A93B0165E0F54D";
    rcvMsg->fileData.sw1 = 0x90;
    rcvMsg->fileData.sw2 = 0x00;
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(event));

    rcvMsg->fileData.sw1 = 0x61;
    auto eventRecevMore = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(eventRecevMore));

    rcvMsg->fileData.resultData = "";
    rcvMsg->fileData.sw1 = 0x90;
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(eventRecevMore));

    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(event1));

    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessPrepareDownloadDone(event1));
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

HWTEST_F(EsimTest, ProcessLoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
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

HWTEST_F(EsimTest, ProcessLoadBoundProfilePackageDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3781ADBF27678008D14FE1DE62C340D7BF2F3480024C66810207800C1E31302E31302E31322E" +
        "3136342F64702D706C75732D696E746572666163655A0A98680010203040506080060388370AA21FA01D4F10A0000005591010FFF" +
        "FFFFF890000120004093007A00530038001005F3740B354AE39D08ACD7EDD7D2D01C73378621F623B832DFA3243489C5B42C90F22" +
        "014E6C928130D78EE561982EF412AC3D94C04B56F37657DA84FD7BB24DD4153E88";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessLoadBoundProfilePackageDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackageDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackageDone(event1));
}

HWTEST_F(EsimTest, LoadBoundProfilePackageParseNotificationMetadata_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string responseByte = Asn1Utils::HexStrToBytes(bppCombineHexStr);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    std::shared_ptr<Asn1Node> nodeNotificationMetadata =
        esimFile->LoadBoundProfilePackageParseProfileInstallResult(root);
    EXPECT_TRUE(esimFile->LoadBoundProfilePackageParseNotificationMetadata(nodeNotificationMetadata));
}

HWTEST_F(EsimTest, RealProcessLoadBoundProfilePackageDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EXPECT_TRUE(esimFile->RealProcessLoadBoundProfilePackageDone(bppCombineHexStr));
}

HWTEST_F(EsimTest, ProcessListNotifications_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager)
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventListNotif = iccFile->BuildCallerInfo(MSG_ESIM_LIST_NOTIFICATION);
    esimFile->currentChannelId_ =0 ;
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
    esimFile->currentChannelId_ =2 ;
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
        "BF282BA029BF2F118001010C08736D64702E636F6081020410BF2F128001020C09736D6470322E636F60810204209000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessListNotificationsDone(event));

    rcvMsg->fileData.resultData = "";
    auto eventMsgEmpty = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessListNotificationsDone(eventMsgEmpty));

    auto eventListNotif = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessListNotificationsDone(eventListNotif), false);

    eventListNotif = nullptr;
    EXPECT_EQ(esimFile->ProcessListNotificationsDone(eventListNotif), false);
}

HWTEST_F(EsimTest, createNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData = "BF2F118001010C08736D64702E636F6D81020410";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
}

HWTEST_F(EsimTest, createNotification_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData = "BF282BA029BF2F118001010C00736D64702E636F6D8100";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
}

HWTEST_F(EsimTest, createNotification_003, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData = "BF2F118001010C08736D64702E636F6D81020410";
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6D81020410BF2F128001020C09736D6470322E636F6D810204209000";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    bool isFileHandleResponse = false;
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode, isFileHandleResponse), false);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData =
        "BF2803810101";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    bool isFileHandleResponse = false;
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode, isFileHandleResponse), false);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_003, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData =
        "BF2803A00101";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    bool isFileHandleResponse = false;
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode, isFileHandleResponse), false);
}
} // namespace Telephony
} // namespace OHOS
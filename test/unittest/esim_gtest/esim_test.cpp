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
#include "icc_file.h"
#include "sim_file_manager.h
#include "sim_file_manager.h"
#include "sim_constant.h"
#include "telephony_tag_def.h"
#include "tel_ril_manager.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

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
    int slotId = 0;
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

HWTEST_F(EsimTest, ProcessRetrieveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
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

HWTEST_F(EsimTest, ProcessRetrieveNotificationList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
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
        "BF2B2FA02D3014BF2F118001010C08736D64702E636F6D810204103015BF2F128001020C09736D6470322E636F6D810205109000";
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
        "BF2B2FA02D3014BF2F118001010C08736D64702E636F6D810204103015BF2F128001020C09736D6470322E636F6D810205109000";
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(rcvMsg->fileData.resultData);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_TRUE(esimFile->RetrieveNotificationParseCompTag(root));
}
} // namespace Telephony
} // namespace OHOS
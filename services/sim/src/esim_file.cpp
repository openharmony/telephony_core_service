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

#include "esim_file.h"

#include <unistd.h>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_manager_inner.h"
#include "parameters.h"
#include "radio_event.h"
#include "sim_number_decode.h"
#include "str_convert.h"
#include "telephony_common_utils.h"
#include "telephony_ext_wrapper.h"
#include "telephony_state_registry_client.h"
#include "telephony_tag_def.h"
#include "vcard_utils.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {

EuiccNotificationList EsimFile::RetrieveNotificationList(int32_t portIndex, Event events)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.events = events;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRetrieveListNotif = BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_LIST);
    if (!ProcessRetrieveNotificationList(slotId_, Event::EVENT_ENABLE, eventRetrieveListNotif)) {
        TELEPHONY_LOGE("ProcessRetrieveNotificationList encode failed");
        return EuiccNotificationList();
    }
    std::unique_lock<std::mutex> lock(retrieveNotificationListMutex_);
    if (!retrieveNotificationListCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isRetrieveNotificationListReady_; })) {
        SyncCloseChannel();
        return EuiccNotificationList();
    }
    SyncCloseChannel();
    return retrieveNotificationList_;
}

EuiccNotification EsimFile::ObtainRetrieveNotification(int32_t portIndex, int32_t seqNumber)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.seqNumber = seqNumber;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRetrieveNotification = BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_DONE);
    if (!ProcessRetrieveNotification(slotId_, eventRetrieveNotification)) {
        TELEPHONY_LOGE("ProcessRetrieveNotification encode failed");
        return EuiccNotification();
    }
    std::unique_lock<std::mutex> lock(retrieveNotificationMutex_);
    if (!retrieveNotificationCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isRetrieveNotificationReady_; })) {
        SyncCloseChannel();
        return EuiccNotification();
    }
    SyncCloseChannel();
    return notification_;
}

ResultState EsimFile::RemoveNotificationFromList(int32_t portIndex, int32_t seqNumber)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.seqNumber = seqNumber;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRemoveNotif = BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    if (!ProcessRemoveNotification(slotId_, eventRemoveNotif)) {
        TELEPHONY_LOGE("ProcessRemoveNotification encode failed");
        return ResultState();
    }
    std::unique_lock<std::mutex> lock(removeNotificationMutex_);
    if (!removeNotificationCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isRemoveNotificationReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return removeNotifResult_;
}

bool EsimFile::ProcessRetrieveNotificationList(
    int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_RETRIEVE_NOTIFICATIONS_LIST);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr!");
            return false;
        }
        std::shared_ptr<Asn1Builder> compBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
        if (compBuilder == nullptr) {
            TELEPHONY_LOGE("compBuilder is nullptr!");
            return false;
        }
        compBuilder->Asn1AddChildAsBits(TAG_ESIM_CTX_1, static_cast<int32_t>(events));
        std::shared_ptr<Asn1Node> compNode = compBuilder->Asn1Build();
        builder->Asn1AddChild(compNode);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager_ is nullptr");
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessRetrieveNotificationListDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    if (result == false) {
        return false;
    }
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    uint32_t byteLen = responseByte.length();
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero");
        return false;
    }
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }

    if (!RetrieveNotificationParseCompTag(root)) {
        TELEPHONY_LOGE("RetrieveNotificationParseCompTag error");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(retrieveNotificationListMutex_);
        isRetrieveNotificationListReady_ = true;
    }
    retrieveNotificationListCv_.notify_one();
    return true;
}

bool EsimFile::RetrieveNotificationParseCompTag(std::shared_ptr<Asn1Node> &root)
{
    std::list<std::shared_ptr<Asn1Node>> ls;
    std::shared_ptr<Asn1Node> compTag = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (compTag == nullptr) {
        TELEPHONY_LOGE("compTag is nullptr");
        return false;
    }

    int metaDataRes = compTag->Asn1GetChildren(TAG_ESIM_SEQUENCE, ls);
    if (metaDataRes != 0) {
        TELEPHONY_LOGE("metaDataTag is zero");
        return false;
    }
    std::shared_ptr<Asn1Node> curNode = nullptr;
    EuiccNotificationList euiccList;
    for (auto it = ls.begin(); it != ls.end(); ++it) {
        curNode = *it;
        EuiccNotification euicc;
        createNotification(curNode, euicc);
        euiccList.euiccNotification.push_back(euicc);
    }
    eUiccNotificationList_ = euiccList;
    return true;
}

bool EsimFile::ProcessRetrieveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_RETRIEVE_NOTIFICATIONS_LIST);
        std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
        if (builder == nullptr || subBuilder == nullptr) {
            TELEPHONY_LOGE("get builder failed");
            return false;
        }
        subBuilder->Asn1AddChildAsSignedInteger(TAG_ESIM_CTX_0, profile->seqNumber);
        std::shared_ptr<Asn1Node> subNode = subBuilder->Asn1Build();
        builder->Asn1AddChild(subNode);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager_ is nullptr");
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessRetrieveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    if (result == false) {
        return false;
    }
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    uint32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    if (!RetrieveNotificatioParseTagCtxComp0(root)) {
        TELEPHONY_LOGE("RetrieveNotificatioParseTagCtxComp0 error");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(retrieveNotificationMutex_);
        isRetrieveNotificationReady_ = true;
    }
    retrieveNotificationCv_.notify_one();
    return true;
}

bool EsimFile::RetrieveNotificatioParseTagCtxComp0(std::shared_ptr<Asn1Node> &root)
{
    std::list<std::shared_ptr<Asn1Node>> nodes;
    std::shared_ptr<Asn1Node> compNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (nullptr == compNode) {
        TELEPHONY_LOGE("compNode is nullptr");
        return false;
    }

    if (compNode->Asn1GetChildren(TAG_ESIM_SEQUENCE, nodes) != 0) {
        return false;
    }
    EuiccNotification notification;
    std::shared_ptr<Asn1Node> firstNode = nodes.front();
    createNotification(firstNode, notification);
    return true;
}

bool EsimFile::ProcessRemoveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        if (profile == nullptr) {
            TELEPHONY_LOGE("ProcessRemoveNotification profile is nullptr");
            return false;
        }
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_REMOVE_NOTIFICATION_FROM_LIST);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        builder->Asn1AddChildAsSignedInteger(TAG_ESIM_CTX_0, profile->seqNumber);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager_ is nullptr");
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessRemoveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    if (result == false) {
        return false;
    }
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    uint32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    removeNotifResult_ = (ResultState)pAsn1Node->Asn1AsInteger();

    {
        std::lock_guard<std::mutex> lock(removeNotificationMutex_);
        isRemoveNotificationReady_ = true;
    }
    removeNotificationCv_.notify_one();
    return true;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_REMOVE_NOTIFICATION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRemoveNotificationDone(event); };
    memberFuncMap_[MSG_ESIM_RETRIEVE_NOTIFICATION_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRetrieveNotificationDone(event); };
    memberFuncMap_[MSG_ESIM_RETRIEVE_NOTIFICATION_LIST] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRetrieveNotificationListDone(event); };
}

void EsimFile::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        return;
    }
    auto id = event->GetInnerEventId();
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            bool isFileProcessResponse = memberFunc(event);
            ProcessFileLoaded(isFileProcessResponse);
        }
    } else {
        IccFile::ProcessEvent(event);
    }
}
}
}
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
ResponseEsimResult EsimFile::ObtainPrepareDownload(const DownLoadConfigInfo &downLoadConfigInfo)
{
    esimProfile_.portIndex = downLoadConfigInfo.portIndex;
    esimProfile_.hashCc = downLoadConfigInfo.hashCc;
    esimProfile_.smdpSigned2 = downLoadConfigInfo.smdpSigned2;
    esimProfile_.smdpSignature2 = downLoadConfigInfo.smdpSignature2;
    esimProfile_.smdpCertificate = downLoadConfigInfo.smdpCertificate;
    SyncOpenChannel();
    if (!ProcessPrepareDownload(slotId_)) {
        TELEPHONY_LOGE("ProcessPrepareDownload encode failed");
        return ResponseEsimResult();
    }
    isPrepareDownloadReady_ = false;
    std::unique_lock<std::mutex> lock(prepareDownloadMutex_);
    if (!prepareDownloadCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isPrepareDownloadReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return preDownloadResult_;
}

ResponseEsimBppResult EsimFile::ObtainLoadBoundProfilePackage(int32_t portIndex,
    const std::u16string boundProfilePackage)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.boundProfilePackage = boundProfilePackage;
    SyncOpenChannel();
    isLoadBppReady_ = false;
    if (!ProcessLoadBoundProfilePackage(slotId_)) {
        TELEPHONY_LOGE("ProcessLoadBoundProfilePackage encode failed");
        return ResponseEsimBppResult();
    }
    std::unique_lock<std::mutex> lock(loadBppMutex_);
    if (!loadBppCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isLoadBppReady_; })) {
        SyncCloseChannel();
        return ResponseEsimBppResult();
    }
    SyncCloseChannel();
    return loadBPPResult_;
}

EuiccNotificationList EsimFile::ListNotifications(int32_t portIndex, Event events)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.events = events;
    AppExecFwk::InnerEvent::Pointer eventListNotif = BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    SyncOpenChannel();
    if (!ProcessListNotifications(slotId_, Event::EVENT_ENABLE, eventListNotif)) {
        TELEPHONY_LOGE("ProcessListNotifications encode failed");
        return EuiccNotificationList();
    }
    isListNotificationsReady_ = false;
    std::unique_lock<std::mutex> lock(listNotificationsMutex_);
    if (!listNotificationsCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isListNotificationsReady_; })) {
        SyncCloseChannel();
        return EuiccNotificationList();
    }
    SyncCloseChannel();
    return eUiccNotificationList_;
}

void EsimFile::ConvertPreDownloadParaFromApiStru(PrepareDownloadResp& dst, EsimProfile& src)
{
    dst.smdpSigned2 = OHOS::Telephony::ToUtf8(src.smdpSigned2);
    dst.smdpSignature2 = OHOS::Telephony::ToUtf8(src.smdpSignature2);
    dst.smdpCertificate = OHOS::Telephony::ToUtf8(src.smdpCertificate);
    dst.hashCc = OHOS::Telephony::ToUtf8(src.hashCc);
}

void EsimFile::Asn1AddChildAsBase64(std::shared_ptr<Asn1Builder> &builder, std::string &base64Src)
{
    std::string destString = VCardUtils::DecodeBase64(base64Src);
    std::vector<uint8_t> dest = Asn1Utils::StringToBytes(destString);
    std::shared_ptr<Asn1Decoder> decoder = std::make_shared<Asn1Decoder>(dest, 0, destString.length());
    if (decoder == nullptr) {
        TELEPHONY_LOGE("create decoder failed");
        return;
    }
    std::shared_ptr<Asn1Node> node = decoder->Asn1NextNode();
    if (builder == nullptr) {
        TELEPHONY_LOGE("build is nullptr");
        return;
    }
    builder->Asn1AddChild(node);
}

bool EsimFile::ProcessPrepareDownload(int32_t slotId)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    PrepareDownloadResp dst;
    ConvertPreDownloadParaFromApiStru(dst, esimProfile_);
    EsimProfile *profile = &esimProfile_;
    if (profile == nullptr) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_PREPARE_DOWNLOAD);
    if (builder == nullptr) {
        return false;
    }
    Asn1AddChildAsBase64(builder, dst.smdpSigned2);
    Asn1AddChildAsBase64(builder, dst.smdpSignature2);
    if (dst.hashCc.size() != 0) {
        std::vector<uint8_t> bytes = Asn1Utils::StringToBytes(VCardUtils::DecodeBase64(dst.hashCc));
        builder->Asn1AddChildAsBytes(TAG_ESIM_OCTET_STRING_TYPE, bytes, bytes.size());
    }
    Asn1AddChildAsBase64(builder, dst.smdpCertificate);
    std::string hexStr;
    uint32_t hexStrLen = builder->Asn1BuilderToHexStr(hexStr);
    if (hexStrLen == 0) {
        return false;
    }
    SplitSendLongData(slotId, hexStr);
    return true;
}

void EsimFile::SplitSendLongData(int32_t slotId, std::string hexStr)
{
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> apduCommandList = codec.GetCommands();
    for (const auto &cmd : apduCommandList) {
        ApduSimIORequestInfo reqInfo;
        CopyApdCmdToReqInfo(&reqInfo, cmd.get());
        AppExecFwk::InnerEvent::Pointer tmpResponseEvent = BuildCallerInfo(MSG_ESIM_PREPARE_DOWNLOAD_DONE);
        if (telRilManager_ == nullptr) {
            return;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, tmpResponseEvent);
    }
}

bool EsimFile::CombineResponseDataFinish(IccFileData &fileData)
{
    if(fileData.resultData.length() == 0) {
        return false;
    }
    recvCombineStr_ = recvCombineStr_ + fileData.resultData;
    return (fileData.sw1 == SW1_VALUE_90 && fileData.sw2 == SW2_VALUE_00);
}

bool EsimFile::ProcessIfNeedMoreResponse(IccFileData &fileData, int eventId)
{
    if (fileData.sw1 == SW1_MORE_RESPONSE) {
        ApduSimIORequestInfo reqInfo;
        RequestApduBuild codec(currentChannelId_);
        codec.BuildStoreData("");
        std::list<std::unique_ptr<ApduCommand>> lst = codec.GetCommands();
        std::unique_ptr<ApduCommand> apdCmd = std::move(lst.front());
        if (apdCmd == nullptr) {
            return false;
        }
        apdCmd->data.cla = 0;
        apdCmd->data.ins = INS_GET_MORE_RESPONSE;
        apdCmd->data.p1 = 0;
        apdCmd->data.p2 = 0;
        apdCmd->data.p3 = (int)fileData.sw2;
        CopyApdCmdToReqInfo(&reqInfo, apdCmd.get());
        AppExecFwk::InnerEvent::Pointer responseEvent = BuildCallerInfo(eventId);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId_, reqInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::MergeRecvLongDataComplete(IccFileData &fileData)
{
    if(!CombineResponseDataFinish(fileData))
    {
        if(!ProcessIfNeedMoreResponse(fileData, MSG_ESIM_AUTHENTICATE_SERVER))
        {
            TELEPHONY_LOGE("try to ProcessIfNeedMoreResponse NOT done. sw1=%{public}02X", fileData.sw1);
            return false;
        }
    }
    return true;
}

bool EsimFile::ProcessPrepareDownloadDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    IccFileData &iccFileData = rcvMsg->fileData;
    if (!MergeRecvLongDataComplete(iccFileData)) {
        return true;
    }
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    std::shared_ptr<Asn1Node> childNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    if (childNode != nullptr) {
        std::shared_ptr<Asn1Node> errCodeNode = childNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
        if (errCodeNode != nullptr) {
            int32_t protocolErr = errCodeNode->Asn1AsInteger();
            if (protocolErr != TELEPHONY_ERR_ARGUMENT_INVALID) {
                TELEPHONY_LOGE("Prepare download error, es10x errcode: %{public}d", protocolErr);
                return false;
            }
        }
    }
    preDownloadResult_.resultCode = ResultState::RESULT_OK;
    std::string responseByteStr = Asn1Utils::BytesToString(responseByte);
    std::string destString = VCardUtils::EncodeBase64(responseByteStr);
    preDownloadResult_.response = OHOS::Telephony::ToUtf16(destString);
    {
        std::lock_guard<std::mutex> lock(prepareDownloadMutex_);
        isPrepareDownloadReady_ = true;
    }
    prepareDownloadCv_.notify_one();
    return true;
}

bool EsimFile::DecodeBoundProfilePackage(const std::string &boundProfilePackageStr, std::shared_ptr<Asn1Node> &bppNode)
{
    std::string destString = VCardUtils::DecodeBase64(boundProfilePackageStr);
    uint32_t byteLen = destString.length();
    std::vector<uint8_t> dest = Asn1Utils::StringToBytes(destString);
    std::shared_ptr<Asn1Decoder> decoder = std::make_shared<Asn1Decoder>(dest, 0, byteLen);
    if (decoder == nullptr) {
        TELEPHONY_LOGE("decoder is nullptr");
        return false;
    }
    bppNode = decoder->Asn1NextNode();
    if (bppNode == nullptr) {
        TELEPHONY_LOGE("bppNode is nullptr");
        return false;
    }
    return true;
}

void EsimFile::BuildApduForInitSecureChannel(
    RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &initSecureChannelReq)
{
    std::string hexStr;
    std::string destStr;
    uint32_t cursorLen = bppNode->Asn1GetHeadAsHexStr(hexStr);
    cursorLen += initSecureChannelReq->Asn1NodeToHexStr(destStr);
    hexStr += destStr;
    codec.BuildStoreData(hexStr);
}

void EsimFile::BuildApduForFirstSequenceOf87(RequestApduBuild &codec, std::shared_ptr<Asn1Node> &firstSequenceOf87)
{
    std::string hexStr;
    uint32_t cursorLen = firstSequenceOf87->Asn1NodeToHexStr(hexStr);
    codec.BuildStoreData(hexStr);
}

void EsimFile::BuildApduForSequenceOf88(RequestApduBuild &codec, std::shared_ptr<Asn1Node> &sequenceOf88)
{
    std::list<std::shared_ptr<Asn1Node>> metaDataSeqs;
    int32_t metaDataRes = sequenceOf88->Asn1GetChildren(TAG_ESIM_CTX_8, metaDataSeqs);
    if (metaDataRes != 0) {
        return;
    }
    std::string hexStr;
    uint32_t cursorLen = sequenceOf88->Asn1GetHeadAsHexStr(hexStr);
    codec.BuildStoreData(hexStr);
    std::shared_ptr<Asn1Node> curNode = nullptr;
    for (auto it = metaDataSeqs.begin(); it != metaDataSeqs.end(); ++it) {
        curNode = *it;
        if (curNode == nullptr) {
            break;
        }
        curNode->Asn1NodeToHexStr(hexStr);
        codec.BuildStoreData(hexStr);
    }
}

void EsimFile::BuildApduForSequenceOf86(RequestApduBuild &codec, std::shared_ptr<Asn1Node> &bppNode,
    std::shared_ptr<Asn1Node> &sequenceOf86)
{
    std::string hexStr;
    std::list<std::shared_ptr<Asn1Node>> elementSeqs;
    int32_t elementRes = sequenceOf86->Asn1GetChildren(TAG_ESIM_CTX_6, elementSeqs);
    if (elementRes != 0) {
        TELEPHONY_LOGE("sequenceOf86 encode error");
        return;
    }
    if (bppNode->Asn1HasChild(TAG_ESIM_CTX_COMP_2)) {
        std::shared_ptr<Asn1Node> pGetChild = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_2);
        if (pGetChild == nullptr) {
            TELEPHONY_LOGE("pGetChild is nullptr");
            return;
        }
        pGetChild->Asn1NodeToHexStr(hexStr);
        codec.BuildStoreData(hexStr);
    }
    uint32_t cursorLen = sequenceOf86->Asn1GetHeadAsHexStr(hexStr);
    codec.BuildStoreData(hexStr);
    std::shared_ptr<Asn1Node> curNode = nullptr;
    for (auto it = elementSeqs.begin(); it != elementSeqs.end(); ++it) {
        curNode = *it;
        if (curNode == nullptr) {
            break;
        }
        curNode->Asn1NodeToHexStr(hexStr);
        codec.BuildStoreData(hexStr);
    }
}

bool EsimFile::ProcessLoadBoundProfilePackage(int32_t slotId)
{
    if (!IsLogicChannelOpen()) {
        TELEPHONY_LOGE("open channel is failed");
        return false;
    }
    std::string boundProfilePackage = OHOS::Telephony::ToUtf8(esimProfile_.boundProfilePackage);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    if (!DecodeBoundProfilePackage(boundProfilePackage, bppNode)) {
        TELEPHONY_LOGE("DecodeBoundProfilePackage failed");
        return false;
    }
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> initSecureChannelReq = bppNode->Asn1GetChild(TAG_ESIM_INITIALISE_SECURE_CHANNEL);
    if (initSecureChannelReq != nullptr) {
        BuildApduForInitSecureChannel(codec, bppNode, initSecureChannelReq);
    }
    std::shared_ptr<Asn1Node> firstSequenceOf87 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (firstSequenceOf87 != nullptr) {
        BuildApduForFirstSequenceOf87(codec, firstSequenceOf87);
    }
    std::shared_ptr<Asn1Node> sequenceOf88 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    if (sequenceOf88 != nullptr) {
        BuildApduForSequenceOf88(codec, sequenceOf88);
    }
    std::shared_ptr<Asn1Node> sequenceOf86 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_3);
    if (sequenceOf86 != nullptr) {
        BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
    }
    std::list<std::unique_ptr<ApduCommand>> apduCommandList = codec.GetCommands();
    for (const auto &cmd : apduCommandList) {
        ApduSimIORequestInfo reqInfo;
        CopyApdCmdToReqInfo(&reqInfo, cmd.get());
        AppExecFwk::InnerEvent::Pointer responseEvent = BuildCallerInfo(MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
    }
    return true;
}

bool EsimFile::ProcessLoadBoundProfilePackageDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    IccFileData &iccFileData = rcvMsg->fileData;
    if (!MergeRecvLongDataComplete(iccFileData)) {
        return true;
    }
    return RealProcessLoadBoundProfilePackageDone(recvCombineStr_);
}

bool EsimFile::RealProcessLoadBoundProfilePackageDone(std::string combineHexStr)
{
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(combineHexStr);
    uint32_t byteLen = responseByte.size();
    loadBPPResult_.response = OHOS::Telephony::ToUtf16(combineHexStr);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    std::shared_ptr<Asn1Node> nodeNotificationMetadata = LoadBoundProfilePackageParseProfileInstallResult(root);
    if (nodeNotificationMetadata == nullptr) {
        {
            std::lock_guard<std::mutex> lock(loadBppMutex_);
            isLoadBppReady_ = true;
        }
        loadBppCv_.notify_one();
        return false;
    }
    if (!LoadBoundProfilePackageParseNotificationMetadata(nodeNotificationMetadata)) {
        {
            std::lock_guard<std::mutex> lock(loadBppMutex_);
            isLoadBppReady_ = true;
        }
        loadBppCv_.notify_one();
        return false;
    }
    loadBPPResult_.resultCode = 0;
    {
        std::lock_guard<std::mutex> lock(loadBppMutex_);
        isLoadBppReady_ = true;
    }
    loadBppCv_.notify_one();
    return true;
}

bool EsimFile::LoadBoundProfilePackageParseNotificationMetadata(std::shared_ptr<Asn1Node> &notificationMetadata)
{
    if (notificationMetadata == nullptr) {
        TELEPHONY_LOGE("notification metadata is empty");
        return false;
    }
    std::shared_ptr<Asn1Node> sequenceNumberAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_CTX_0);
    if (sequenceNumberAsn != nullptr) {
        loadBPPResult_.seqNumber = sequenceNumberAsn->Asn1AsInteger();
    } else {
        TELEPHONY_LOGE("sequenceNumber tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> profileManagementOpAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_CTX_1);
    if (profileManagementOpAsn != nullptr) {
        loadBPPResult_.profileManagementOperation = EVENT_INSTALL;
    } else {
        TELEPHONY_LOGE("profileManagementOperation tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> addressAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_TARGET_ADDR);
    if (addressAsn != nullptr) {
        std::string hexString;
        addressAsn->Asn1AsString(hexString);
        std::string address = Asn1Utils::HexStrToString(hexString);
        loadBPPResult_.notificationAddress = OHOS::Telephony::ToUtf16(address);
    } else {
        TELEPHONY_LOGE("notificationAddress tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> iccidAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_EID);
    if (iccidAsn == nullptr) {
        TELEPHONY_LOGE("iccidAsn is nullptr");
        return false;
    }
    std::vector<uint8_t> iccid;
    std::string iccString;
    uint32_t iccidLen = iccidAsn->Asn1AsBytes(iccid);
    Asn1Utils::BchToString(iccid, iccString);
    loadBPPResult_.iccId = OHOS::Telephony::ToUtf16(iccString);
    return true;
}

std::shared_ptr<Asn1Node> EsimFile::LoadBoundProfilePackageParseProfileInstallResult(std::shared_ptr<Asn1Node> &root)
{
    if (root == nullptr) {
        TELEPHONY_LOGE("failed to parse load BPP file response");
        return nullptr;
    }
    std::shared_ptr<Asn1Node> resultData = root->Asn1GetChild(TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA);
    if (resultData == nullptr) {
        TELEPHONY_LOGE("failed to find ProfileInstallationResult tag");
        return nullptr;
    }
    std::shared_ptr<Asn1Node> errNode = resultData->Asn1GetGreatGrandson(TAG_ESIM_CTX_COMP_2,
        TAG_ESIM_CTX_COMP_1, TAG_ESIM_CTX_1);
    if (errNode != nullptr) {
        loadBPPResult_.resultCode = errNode->Asn1AsInteger();
        return nullptr;
    }
    std::shared_ptr<Asn1Node> notificationMetadataAsn = resultData->Asn1GetChild(TAG_ESIM_NOTIFICATION_METADATA);
    if (notificationMetadataAsn == nullptr) {
        TELEPHONY_LOGE("extProfileInstallRsp: failed to find finalResult tag");
        return nullptr;
    }
    return notificationMetadataAsn;
}

bool EsimFile::ProcessListNotifications(
    int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_LIST_NOTIFICATION);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    builder->Asn1AddChildAsBits(TAG_ESIM_CTX_1, static_cast<int32_t>(events));
    ApduSimIORequestInfo reqInfo;
    CommBuildOneApduReqInfo(reqInfo, builder);
    if (telRilManager_ == nullptr) {
        return false;
    }
    int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
    if (apduResult == TELEPHONY_ERR_FAIL) {
        return false;
    }
    return true;
}

void EsimFile::createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification &euicc)
{
    if (node == nullptr) {
        TELEPHONY_LOGE("createNotification node is nullptr");
        return;
    }
    std::shared_ptr<Asn1Node> metadataNode;
    if (node->GetNodeTag() == TAG_ESIM_NOTIFICATION_METADATA) {
        metadataNode = node;
    } else if (node->GetNodeTag() == TAG_ESIM_PROFILE_INSTALLATION_RESULT) {
        std::shared_ptr<Asn1Node> findNode =
            node->Asn1GetGrandson(TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA,
            TAG_ESIM_NOTIFICATION_METADATA);
        metadataNode = findNode;
    } else {
        // Other signed notification
        std::shared_ptr<Asn1Node> findNode = node->Asn1GetChild(TAG_ESIM_NOTIFICATION_METADATA);
        metadataNode = findNode;
    }
    if (metadataNode == nullptr) {
        TELEPHONY_LOGE("metadataNode is nullptr");
        return;
    }
    std::shared_ptr<Asn1Node> nodeSeq = metadataNode->Asn1GetChild(TAG_ESIM_SEQ);
    if (nodeSeq == nullptr) {
        TELEPHONY_LOGE("nodeSeq is nullptr");
        return;
    }
    euicc.seq = nodeSeq->Asn1AsInteger();

    std::shared_ptr<Asn1Node> nodeTargetAddr = metadataNode->Asn1GetChild(TAG_ESIM_TARGET_ADDR);
    if (nodeTargetAddr == nullptr) {
        TELEPHONY_LOGE("nodeTargetAddr is nullptr");
        return;
    }
    std::vector<uint8_t> resultStr;
    nodeTargetAddr->Asn1AsBytes(resultStr);
    euicc.targetAddr = OHOS::Telephony::ToUtf16(Asn1Utils::BytesToString(resultStr));

    std::shared_ptr<Asn1Node> nodeEvent = metadataNode->Asn1GetChild(TAG_ESIM_EVENT);
    if (nodeEvent == nullptr) {
        TELEPHONY_LOGE("nodeEvent is nullptr");
        return;
    }
    euicc.event = nodeEvent->Asn1AsBits();

    std::string strmData;
    node->Asn1NodeToHexStr(strmData);
    euicc.data = node->GetNodeTag() == TAG_ESIM_NOTIFICATION_METADATA ? u"" : OHOS::Telephony::ToUtf16(strmData);
}

bool EsimFile::ProcessListNotificationsAsn1Response(std::shared_ptr<Asn1Node> &root)
{
    if (root->Asn1HasChild(TAG_ESIM_CTX_1)) {
        TELEPHONY_LOGE("child is nullptr");
        return false;
    }
    std::list<std::shared_ptr<Asn1Node>> ls;
    std::shared_ptr<Asn1Node> compTag = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (compTag == nullptr) {
        TELEPHONY_LOGE("compTag is nullptr");
        return false;
    }
    int32_t metaDataRes = compTag->Asn1GetChildren(TAG_ESIM_NOTIFICATION_METADATA, ls);
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
    {
        std::lock_guard<std::mutex> lock(listNotificationsMutex_);
        isListNotificationsReady_ = true;
    }
    listNotificationsCv_.notify_one();
    return true;
}

bool EsimFile::ProcessListNotificationsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    if (!ProcessListNotificationsAsn1Response(root)) {
        return false;
    }
    return true;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_LIST_NOTIFICATION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessListNotificationsDone(event); };
    memberFuncMap_[MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessLoadBoundProfilePackageDone(event); };
    memberFuncMap_[MSG_ESIM_PREPARE_DOWNLOAD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessPrepareDownloadDone(event); };
}
} // namespace Telephony
} // namespace OHOS

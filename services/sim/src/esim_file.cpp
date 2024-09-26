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
constexpr int32_t NUMBER_THREE = 3;
EsimFile::EsimFile(std::shared_ptr<SimStateManager> simStateManager) : IccFile("EsimFile", simStateManager)
{
    currentChannelId_ = 0;
    InitMemberFunc();
}

void EsimFile::StartLoad() {}

void EsimFile::SyncOpenChannel()
{
    uint32_t tryCnt = 0;
    while (!IsLogicChannelOpen()) {
        ProcessEsimOpenChannel();
        std::unique_lock<std::mutex> lck(openChannelMutex_);
        if (openChannelCv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM), 
            [this]() { return IsLogicChannelOpen(); })) {
            break;
        }
        tryCnt++;
        if (tryCnt >= NUMBER_THREE) {
            TELEPHONY_LOGE("failed to open the channel");
            break;
        }
    }
}

void EsimFile::SyncOpenChannel(const std::u16string &aid)
{
    uint32_t tryCnt = 0;
    while (!IsLogicChannelOpen()) {
        ProcessEsimOpenChannel(aid);
        std::unique_lock<std::mutex> lck(openChannelMutex_);
        if (openChannelCv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
            [this]() { return IsLogicChannelOpen(); })) {
            break;
        }
        tryCnt++;
        if (tryCnt >= NUMBER_THREE) {
            TELEPHONY_LOGE("failed to open the channel");
            break;
        }
    }
}

void EsimFile::SyncCloseChannel()
{
    uint32_t tryCnt = 0;
    while (IsLogicChannelOpen()) {
        ProcessEsimCloseChannel();
        std::unique_lock<std::mutex> lck(closeChannelMutex_);
        if (closeChannelCv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM), 
            [this]() { return !IsLogicChannelOpen(); })) {
            break;
        }
        tryCnt++;
        if (tryCnt >= NUMBER_THREE) {
            currentChannelId_ = 0;
            TELEPHONY_LOGE("failed to close the channel");
            break;
        }
    }
}

std::string EsimFile::ObtainEid()
{
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventGetEid = BuildCallerInfo(MSG_ESIM_OBTAIN_EID_DONE);
    if (!ProcessObtainEid(0, eventGetEid)) {
        TELEPHONY_LOGE("ProcessObtainEid encode failed");
        return "";
    }
    // wait profileInfo is ready
    getEidReady_ = false;
    std::unique_lock<std::mutex> lock(getEidMutex_);
    if (!getEidCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return getEidReady_; })) {
        SyncCloseChannel();
        return "";
    }
    SyncCloseChannel();
    return eid_;
}

GetEuiccProfileInfoListResult EsimFile::GetEuiccProfileInfoList()
{
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRequestAllProfiles = BuildCallerInfo(MSG_ESIM_REQUEST_ALL_PROFILES);
    if (!ProcessRequestAllProfiles(slotId_, eventRequestAllProfiles)) {
        TELEPHONY_LOGE("ProcessRequestAllProfiles encode failed");
        return GetEuiccProfileInfoListResult();
    }
    areAllProfileInfoReady_ = false;
    std::unique_lock<std::mutex> lock(allProfileInfoMutex_);
    if (!allProfileInfoCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areAllProfileInfoReady_; })) {
        SyncCloseChannel();
        return GetEuiccProfileInfoListResult();
    }
    SyncCloseChannel();
    return euiccProfileInfoList_;
}

EuiccInfo EsimFile::GetEuiccInfo()
{
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo1 = BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE);
    if (!ProcessObtainEuiccInfo1(slotId_, eventEUICCInfo1)) {
        TELEPHONY_LOGE("ProcessObtainEuiccInfo1 encode failed");
        return EuiccInfo();
    }
    areEuiccInfo1Ready_ = false;
    std::unique_lock<std::mutex> lock(euiccInfo1Mutex_);
    if (!euiccInfo1Cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areEuiccInfo1Ready_; })) {
        SyncCloseChannel();
        return EuiccInfo();
    }
    SyncCloseChannel();
    return eUiccInfo_;
}

void EsimFile::CopyApdCmdToReqInfo(ApduSimIORequestInfo *requestInfo, ApduCommand *apduCommand)
{
    if (apduCommand == nullptr || requestInfo == nullptr) {
        TELEPHONY_LOGE("CopyApdCmdToReqInfo failed");
        return;
    }
    static uint32_t cnt = 0;
    requestInfo->serial = cnt;
    cnt++;
    requestInfo->channelId = apduCommand->channel;
    requestInfo->type = apduCommand->data.cla;
    requestInfo->instruction = apduCommand->data.ins;
    requestInfo->p1 = apduCommand->data.p1;
    requestInfo->p2 = apduCommand->data.p2;
    requestInfo->p3 = apduCommand->data.p3;
    requestInfo->data = apduCommand->data.cmdHex;
}

void EsimFile::CommBuildOneApduReqInfo(ApduSimIORequestInfo& requestInfo, std::shared_ptr<Asn1Builder> &builder)
{
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return;
    }
    std::string hexStr;
    int hexStrLen = builder->Asn1BuilderToHexStr(hexStr);
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> lst = codec.getCommands();
    std::unique_ptr<ApduCommand> apduCommand = std::move(lst.front());
    CopyApdCmdToReqInfo(&requestInfo, apduCommand.get());
    requestInfo.p2 = 0;
}

bool EsimFile::ProcessObtainEid(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EID);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        std::string eidTags;
        eidTags += static_cast<unsigned char>(TAG_ESIM_EID);
        builder->Asn1AddChildAsBytes(TAG_ESIM_TAG_LIST, eidTags, eidTags.length());
        ApduSimIORequestInfo requestInfo;
        CommBuildOneApduReqInfo(requestInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, requestInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::ProcessObtainEuiccInfo1(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EUICC_INFO_1);
        ApduSimIORequestInfo requestInfo;
        CommBuildOneApduReqInfo(requestInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, requestInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::ProcessRequestAllProfiles(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_PROFILES);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        unsigned char EUICC_PROFILE_TAGS[] = {
            (unsigned char) TAG_ESIM_ICCID,
            (unsigned char) TAG_ESIM_NICKNAME,
            (unsigned char) TAG_ESIM_OBTAIN_OPERATOR_NAME,
            (unsigned char) TAG_ESIM_PROFILE_NAME,
            (unsigned char) TAG_ESIM_OPERATOR_ID,
            (unsigned char) (TAG_ESIM_PROFILE_STATE / 256),
            (unsigned char) (TAG_ESIM_PROFILE_STATE % 256),
            (unsigned char) TAG_ESIM_PROFILE_CLASS,
            (unsigned char) TAG_ESIM_PROFILE_POLICY_RULE,
            (unsigned char) (TAG_ESIM_CARRIER_PRIVILEGE_RULES / 256),
            (unsigned char) (TAG_ESIM_CARRIER_PRIVILEGE_RULES % 256),
        };
        std::string euiccProfileTags;
        for (unsigned char tag : EUICC_PROFILE_TAGS) {
            euiccProfileTags += tag;
        }
        builder->Asn1AddChildAsBytes(TAG_ESIM_TAG_LIST, euiccProfileTags, euiccProfileTags.length());
        ApduSimIORequestInfo requestInfo;
        CommBuildOneApduReqInfo(requestInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, requestInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::IsLogicChannelOpen()
{
    if (currentChannelId_ > 0) {
        return true;
    }
    return false;
}

void EsimFile::ProcessEsimOpenChannel()
{
    int32_t p2 = -1;
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_ESIM_OPEN_CHANNEL_DONE);
    if (telRilManager_ == nullptr) {
        return;
    }
    telRilManager_->SimOpenLogicalChannel(0, isdr_aid, p2, response);
    return;
}

void EsimFile::ProcessEsimOpenChannel(const std::u16string &aid)
{
    std::string appId = OHOS::Telephony::ToUtf8(aid);
    int32_t p2 =  -1;
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_ESIM_OPEN_CHANNEL_DONE);
    if (telRilManager_ == nullptr) {
        return;
    }
    telRilManager_->SimOpenLogicalChannel(0, appId, p2, response);
    return;
}

bool EsimFile::ProcessEsimOpenChannelDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("open logical channel event is nullptr!");
        return false;
    }
    auto resultPtr = event->GetSharedObject<OpenLogicalChannelResponse>();
    if (resultPtr == nullptr) {
        TELEPHONY_LOGE("open logical channel fd is nullptr!");
        return false;
    }
    if (resultPtr->channelId > 0) {
        currentChannelId_ = resultPtr->channelId;
        openChannelCv_.notify_one(); 
    } else {
        return false;
    }
    return true;
}

void EsimFile::ProcessEsimCloseChannel()
{
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_ESIM_CLOSE_CHANNEL_DONE);
    if (telRilManager_ == nullptr) {
        return;
    }
    telRilManager_->SimCloseLogicalChannel(0, currentChannelId_, response);
    return;
}

bool EsimFile::ProcessEsimCloseChannelDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    {
        std::lock_guard<std::mutex> lock(closeChannelMutex_); 
        currentChannelId_ = 0;
        TELEPHONY_LOGI("Logical channel closed successfully. Notifying waiting thread.");
    }
    closeChannelCv_.notify_one();
    return true;
}

bool EsimFile::ProcessObtainEidDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
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
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, responseByte.length());
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_EID);
    std::string outPutBytes;
    int32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero!");
        return false;
    }
    std::string strResult = Asn1Utils::BytesToHexStr(outPutBytes);
    {
        std::lock_guard<std::mutex> lock(getEidMutex_);
        eid_ = strResult;
        getEidReady_ = true;
    }
    getEidCv_.notify_one();
    return isFileHandleResponse;
}

std::shared_ptr<Asn1Node> EsimFile::Asn1ParseResponse(std::string response, int32_t respLength)
{
    if (response.empty() || respLength == 0) {
        TELEPHONY_LOGE("response null, respLen = %{public}d", respLength);
        return nullptr;
    }
    Asn1Decoder decoder(response, 0, respLength);
    if (!decoder.Asn1HasNextNode()) {
        TELEPHONY_LOGE("Empty response");
        return nullptr;
    }
    std::shared_ptr<Asn1Node> node = decoder.Asn1NextNode();
    return node;
}

bool EsimFile::ProcessObtainEuiccInfo1Done(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, responseByte.length());
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    if (!ObtainEuiccInfo1ParseTagCtx2(root)) {
        TELEPHONY_LOGE("ObtainEuiccInfo1ParseTagCtx2 error!");
        return false;
    }
    eUiccInfo_.response = Str8ToStr16(result->resultData);
    {
        std::lock_guard<std::mutex> lock(euiccInfo1Mutex_);
        areEuiccInfo1Ready_ = true;
    }
    euiccInfo1Cv_.notify_one();
    return true;
}

bool EsimFile::ObtainEuiccInfo1ParseTagCtx2(std::shared_ptr<Asn1Node> &root)
{
    bool isFileHandleResponse = true;
    EuiccInfo1 euiccInfo1;
    std::shared_ptr<Asn1Node> svnNode = root->Asn1GetChild(TAG_ESIM_CTX_2);
    if (svnNode == nullptr) {
        TELEPHONY_LOGE("svnNode is nullptr");
        return false;
    }
    std::string svnRaw;
    int svnRawlen = svnNode->Asn1AsBytes(svnRaw);
    if (svnRawlen < SVN_RAW_LENGTH_MIN) {
        TELEPHONY_LOGE("invalid SVN data");
        return false;
    }
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned char>(svnRaw[VERSION_HIGH])
        << "." << std::setw(2) << std::setfill('0') << static_cast<unsigned char>(svnRaw[VERSION_MIDDLE])
        << "." << std::setw(2) << std::setfill('0') << static_cast<unsigned char>(svnRaw[VERSION_LOW]);
  
    std::string formattedVersion = oss.str();
    euiccInfo1.svn = formattedVersion;

    eUiccInfo_.osVersion = Str8ToStr16(euiccInfo1.svn);
    return isFileHandleResponse;
}

bool EsimFile::ProcessRequestAllProfilesDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
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
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, responseByte.length());
    if(root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return isFileHandleResponse;
    }

    if (!RequestAllProfilesParseProfileInfo(root)) {
        TELEPHONY_LOGE("RequestAllProfilesParseProfileInfo error!");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(allProfileInfoMutex_);
        areAllProfileInfoReady_ = true;
    }
    allProfileInfoCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::RequestAllProfilesParseProfileInfo(std::shared_ptr<Asn1Node> &root)
{
    bool isFileHandleResponse = true;
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr");
        return isFileHandleResponse;
    }

    std::list<std::shared_ptr<Asn1Node>> profileNodes;
    profileRoot->Asn1GetChildren(TAG_ESIM_PROFILE_INFO, profileNodes);
    std::shared_ptr<Asn1Node> curNode = NULL;
    EuiccProfileInfo euiccProfileInfo = {{0}};
    for(auto it = profileNodes.begin(); it != profileNodes.end(); ++it) {
        curNode = *it;
        if (!curNode->Asn1HasChild(TAG_ESIM_ICCID)) {
            TELEPHONY_LOGE("Profile must have an ICCID.");
            continue;
        }
        BuildProfile(&euiccProfileInfo, curNode);
        EuiccProfile euiccProfile;
        ConvertProfileInfoToApiStruct(euiccProfile, euiccProfileInfo);
        euiccProfileInfoList_.profiles.push_back(euiccProfile);
    }
    euiccProfileInfoList_.result = ResultState::RESULT_OK;

    return isFileHandleResponse;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_OPEN_CHANNEL_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEsimOpenChannelDone(event); };
    memberFuncMap_[MSG_ESIM_CLOSE_CHANNEL_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEsimCloseChannelDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_EID_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEidDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEuiccInfo1Done(event); };
    memberFuncMap_[MSG_ESIM_REQUEST_ALL_PROFILES] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRequestAllProfilesDone(event); };
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

int EsimFile::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
{
    return 0;
}

bool EsimFile::ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    return false;
}

bool EsimFile::UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber)
{
    return false;
}

bool EsimFile::SetVoiceMailCount(int32_t voiceMailCount)
{
    return false;
}

bool EsimFile::SetVoiceCallForwarding(bool enable, const std::string &number)
{
    return false;
}

std::string EsimFile::GetVoiceMailNumber()
{
    return "";
}

void EsimFile::SetVoiceMailNumber(const std::string mailNumber)
{
    return;
}

void EsimFile::ProcessIccRefresh(int msgId)
{
    return;
}

void EsimFile::ProcessFileLoaded(bool response)
{
    return;
}

void EsimFile::OnAllFilesFetched()
{
    return;
}
} // namespace Telephony
} // namespace OHOS
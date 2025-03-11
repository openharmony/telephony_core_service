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
EsimFile::EsimFile(std::shared_ptr<SimStateManager> simStateManager) : IccFile("EsimFile", simStateManager)
{
    currentChannelId_ = 0;
    InitMemberFunc();
    InitChanneMemberFunc();
}

void EsimFile::StartLoad() {}

ResultInnerCode EsimFile::ObtainChannelSuccessExclusive()
{
    std::u16string aid = OHOS::Telephony::ToUtf16(ISDR_AID);
    std::lock_guard<std::mutex> occupyLck(occupyChannelMutex_);
    // The channel is in use.
    if (IsLogicChannelOpen()) {
        TELEPHONY_LOGE("The channel is in use");
        return ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_IN_USE;
    }

    ProcessEsimOpenChannel(aid);
    std::unique_lock<std::mutex> lck(openChannelMutex_);
    if (!openChannelCv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SHORT_SECOND_FOR_ESIM),
        [this]() { return IsLogicChannelOpen(); })) {
        TELEPHONY_LOGE("wait cv failed!");
    }

    bool isOpenChannelSuccess = IsLogicChannelOpen();
    if (isOpenChannelSuccess) {
        aidStr_ = aid;
        return ResultInnerCode::RESULT_EUICC_CARD_OK;
    }

    TELEPHONY_LOGE("failed to open the channel");
    return ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_OPEN_FAILED;
}

/**
 * @brief Channels that support the same aid are not disabled when sending data.
 */
ResultInnerCode EsimFile::ObtainChannelSuccessAlllowSameAidReuse(const std::u16string &aid)
{
    std::lock_guard<std::mutex> lck(occupyChannelMutex_);
    if (!IsValidAidForAllowSameAidReuseChannel(aid)) {
        TELEPHONY_LOGE("Aid invalid");
        return ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_OTHER_AID;
    }

    if (!IsLogicChannelOpen()) {
        ProcessEsimOpenChannel(aid);
        std::unique_lock<std::mutex> lck(openChannelMutex_);
        if (!openChannelCv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SHORT_SECOND_FOR_ESIM),
            [this]() { return IsLogicChannelOpen(); })) {
            TELEPHONY_LOGE("wait cv failed!");
        }
    }

    bool isOpenChannelSuccess = IsLogicChannelOpen();
    if (isOpenChannelSuccess) {
        aidStr_ = aid;
        return ResultInnerCode::RESULT_EUICC_CARD_OK;
    }
    TELEPHONY_LOGE("failed to open the channel");
    return ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_OPEN_FAILED;
}

void EsimFile::SyncCloseChannel()
{
    uint32_t tryCnt = 0;
    std::lock_guard<std::mutex> lck(occupyChannelMutex_);
    while (IsLogicChannelOpen()) {
        ProcessEsimCloseChannel();
        std::unique_lock<std::mutex> lck(closeChannelMutex_);
        if (closeChannelCv_.wait_for(lck, std::chrono::seconds(WAIT_TIME_SHORT_SECOND_FOR_ESIM),
            [this]() { return !IsLogicChannelOpen(); })) {
            break;
        }
        tryCnt++;
        if (tryCnt >= NUMBER_TWO) {
            TELEPHONY_LOGE("failed to close the channel");
            break;
        }
        TELEPHONY_LOGW("wait cv failed, retry close channel at %{public}u", tryCnt);
    }
    currentChannelId_ = 0;
    aidStr_ = u"";
}

std::string EsimFile::ObtainEid()
{
    if (!eid_.empty()) {
        return eid_;
    }
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return "";
    }
    AppExecFwk::InnerEvent::Pointer eventGetEid = BuildCallerInfo(MSG_ESIM_OBTAIN_EID_DONE);
    if (!ProcessObtainEid(slotId_, eventGetEid)) {
        TELEPHONY_LOGE("ProcessObtainEid encode failed");
        SyncCloseChannel();
        return "";
    }
    // wait profileInfo is ready
    isEidReady_ = false;
    std::unique_lock<std::mutex> lock(getEidMutex_);
    if (!getEidCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isEidReady_; })) {
        SyncCloseChannel();
        return "";
    }
    SyncCloseChannel();
    return eid_;
}

GetEuiccProfileInfoListInnerResult EsimFile::GetEuiccProfileInfoList()
{
    euiccProfileInfoList_ = GetEuiccProfileInfoListInnerResult();
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        euiccProfileInfoList_.result_ = static_cast<int32_t>(resultFlag);
        return euiccProfileInfoList_;
    }
    recvCombineStr_ = "";
    AppExecFwk::InnerEvent::Pointer eventRequestAllProfiles = BuildCallerInfo(MSG_ESIM_REQUEST_ALL_PROFILES);
    if (!ProcessRequestAllProfiles(slotId_, eventRequestAllProfiles)) {
        TELEPHONY_LOGE("ProcessRequestAllProfiles encode failed");
        SyncCloseChannel();
        euiccProfileInfoList_.result_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return euiccProfileInfoList_;
    }
    isAllProfileInfoReady_ = false;
    std::unique_lock<std::mutex> lock(allProfileInfoMutex_);
    if (!allProfileInfoCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isAllProfileInfoReady_; })) {
        SyncCloseChannel();
        euiccProfileInfoList_.result_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_WAIT_TIMEOUT);
        return euiccProfileInfoList_;
    }
    SyncCloseChannel();
    return euiccProfileInfoList_;
}

EuiccInfo EsimFile::GetEuiccInfo()
{
    eUiccInfo_ = EuiccInfo();
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return EuiccInfo();
    }
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo1 = BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE);
    if (!ProcessObtainEuiccInfo1(slotId_, eventEUICCInfo1)) {
        TELEPHONY_LOGE("ProcessObtainEuiccInfo1 encode failed");
        SyncCloseChannel();
        return EuiccInfo();
    }
    isEuiccInfo1Ready_ = false;
    std::unique_lock<std::mutex> lock(euiccInfo1Mutex_);
    if (!euiccInfo1Cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isEuiccInfo1Ready_; })) {
        TELEPHONY_LOGE("close channal due to timeout");
        SyncCloseChannel();
        return eUiccInfo_;
    }
    SyncCloseChannel();
    return eUiccInfo_;
}

void EsimFile::CopyApdCmdToReqInfo(ApduSimIORequestInfo &requestInfo, ApduCommand *apduCommand)
{
    if (apduCommand == nullptr) {
        TELEPHONY_LOGE("CopyApdCmdToReqInfo failed");
        return;
    }
    requestInfo.serial = nextSerialId_;
    nextSerialId_++;
    if (nextSerialId_ >= INT32_MAX) {
        nextSerialId_ = 0;
    }
    requestInfo.channelId = static_cast<int32_t>(apduCommand->channel);
    requestInfo.type = static_cast<int32_t>(apduCommand->data.cla);
    requestInfo.instruction = static_cast<int32_t>(apduCommand->data.ins);
    requestInfo.p1 = static_cast<int32_t>(apduCommand->data.p1);
    requestInfo.p2 = static_cast<int32_t>(apduCommand->data.p2);
    requestInfo.p3 = static_cast<int32_t>(apduCommand->data.p3);
    requestInfo.data = apduCommand->data.cmdHex;
    TELEPHONY_LOGI("SEND_DATA reqInfo.serial=%{public}d, \
        reqInfo.channelId=%{public}d, reqInfo.type=%{public}d, reqInfo.instruction=%{public}d, \
        reqInfo.p1=%{public}02X, reqInfo.p2=%{public}02X, reqInfo.p3=%{public}02X, reqInfo.data.length=%{public}zu",
        requestInfo.serial, requestInfo.channelId, requestInfo.type, requestInfo.instruction, requestInfo.p1,
        requestInfo.p2, requestInfo.p3, requestInfo.data.length());
}

void EsimFile::CommBuildOneApduReqInfo(ApduSimIORequestInfo &requestInfo, std::shared_ptr<Asn1Builder> &builder)
{
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return;
    }
    std::string hexStr;
    uint32_t hexStrLen = builder->Asn1BuilderToHexStr(hexStr);
    if (hexStrLen == 0) {
        TELEPHONY_LOGE("hexStrLen is zero");
        return;
    }
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> list = codec.GetCommands();
    if (list.empty()) {
        TELEPHONY_LOGE("node is empty");
        return;
    }
    std::unique_ptr<ApduCommand> apduCommand = std::move(list.front());
    CopyApdCmdToReqInfo(requestInfo, apduCommand.get());
}

bool EsimFile::ProcessObtainEid(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EID);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::vector<uint8_t> eidTags;
    eidTags.push_back(static_cast<unsigned char>(TAG_ESIM_EID));
    builder->Asn1AddChildAsBytes(TAG_ESIM_TAG_LIST, eidTags, eidTags.size());
    ApduSimIORequestInfo requestInfo;
    CommBuildOneApduReqInfo(requestInfo, builder);
    if (telRilManager_ == nullptr) {
        return false;
    }
    telRilManager_->SimTransmitApduLogicalChannel(slotId, requestInfo, responseEvent);
    return true;
}

bool EsimFile::ProcessObtainEuiccInfo1(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EUICC_INFO_1);
    ApduSimIORequestInfo requestInfo;
    CommBuildOneApduReqInfo(requestInfo, builder);
    if (telRilManager_ == nullptr) {
        return false;
    }
    telRilManager_->SimTransmitApduLogicalChannel(slotId, requestInfo, responseEvent);
    return true;
}

bool EsimFile::ProcessRequestAllProfiles(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_PROFILES);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    unsigned char EUICC_PROFILE_TAGS[] = {
        static_cast<unsigned char>(TAG_ESIM_ICCID),
        static_cast<unsigned char>(TAG_ESIM_NICKNAME),
        static_cast<unsigned char>(TAG_ESIM_OBTAIN_OPERATOR_NAME),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_NAME),
        static_cast<unsigned char>(TAG_ESIM_OPERATOR_ID),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_STATE / PROFILE_DEFAULT_NUMBER),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_STATE % PROFILE_DEFAULT_NUMBER),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_CLASS),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_POLICY_RULE),
        static_cast<unsigned char>(TAG_ESIM_CARRIER_PRIVILEGE_RULES / PROFILE_DEFAULT_NUMBER),
        static_cast<unsigned char>(TAG_ESIM_CARRIER_PRIVILEGE_RULES % PROFILE_DEFAULT_NUMBER),
    };
    std::vector<uint8_t> euiccProfileTags;
    for (const unsigned char tag : EUICC_PROFILE_TAGS) {
        euiccProfileTags.push_back(tag);
    }
    builder->Asn1AddChildAsBytes(TAG_ESIM_TAG_LIST, euiccProfileTags, euiccProfileTags.size());
    ApduSimIORequestInfo requestInfo;
    CommBuildOneApduReqInfo(requestInfo, builder);
    if (telRilManager_ == nullptr) {
        return false;
    }
    telRilManager_->SimTransmitApduLogicalChannel(slotId, requestInfo, responseEvent);
    return true;
}

bool EsimFile::IsLogicChannelOpen()
{
    if (currentChannelId_ > 0) {
        TELEPHONY_LOGI("opened channel id:%{public}d", currentChannelId_.load());
        return true;
    }
    return false;
}

void EsimFile::ProcessEsimOpenChannel(const std::u16string &aid)
{
    std::string appId = OHOS::Telephony::ToUtf8(aid);
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_ESIM_OPEN_CHANNEL_DONE);
    if (telRilManager_ == nullptr) {
        return;
    }
    TELEPHONY_LOGI("set req to open channel:%{public}d", currentChannelId_.load());
    telRilManager_->SimOpenLogicalChannel(slotId_, appId, PARAMETER_TWO, response);
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
    if (resultPtr->channelId <= 0) {
        TELEPHONY_LOGE("channelId is invalid!");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(openChannelMutex_);
        TELEPHONY_LOGI("Logical channel %{public}d->%{public}d open successfully. Notifying waiting thread.",
            currentChannelId_.load(), resultPtr->channelId);
        currentChannelId_ = resultPtr->channelId;
    }

    if (occupyChannelMutex_.try_lock()) {
        // caller exits waiting, thus lock is obtained and the channel needs released
        ProcessEsimCloseSpareChannel();
        occupyChannelMutex_.unlock();
        return false;
    }

    openChannelCv_.notify_all();
    return true;
}

void EsimFile::ProcessEsimCloseChannel()
{
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_ESIM_CLOSE_CHANNEL_DONE);
    if (telRilManager_ == nullptr) {
        return;
    }
    TELEPHONY_LOGI("set req to close channel:%{public}d", currentChannelId_.load());
    telRilManager_->SimCloseLogicalChannel(slotId_, currentChannelId_, response);
    return;
}

bool EsimFile::ProcessEsimCloseChannelDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::lock_guard<std::mutex> lock(closeChannelMutex_);
    currentChannelId_ = 0;
    aidStr_ = u"";
    TELEPHONY_LOGI("Logical channel closed successfully. Notifying waiting thread.");
    closeChannelCv_.notify_all();
    return true;
}

void EsimFile::ProcessEsimCloseSpareChannel()
{
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_ESIM_CLOSE_SPARE_CHANNEL_DONE);
    if (telRilManager_ == nullptr) {
        return;
    }

    TELEPHONY_LOGI("set req to close spare channel:%{public}d", currentChannelId_.load());
    telRilManager_->SimCloseLogicalChannel(slotId_, currentChannelId_, response);
}

bool EsimFile::ProcessEsimCloseSpareChannelDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::lock_guard<std::mutex> lock(closeChannelMutex_);
    TELEPHONY_LOGI("Spare channel %{public}d closed successfully.", currentChannelId_.load());
    aidStr_ = u"";
    currentChannelId_ = 0;
    return true;
}

std::string EsimFile::MakeVersionString(std::vector<uint8_t> &versionRaw)
{
    if (versionRaw.size() < NUMBER_THREE) {
        TELEPHONY_LOGE("versionRaw.size(%{public}zu) error!", versionRaw.size());
        return "";
    }
    std::ostringstream oss;
    oss << std::hex << std::uppercase << (versionRaw[VERSION_HIGH] & MAX_UINT8) << "." <<
        (versionRaw[VERSION_MIDDLE] & MAX_UINT8) << "." <<
        (versionRaw[VERSION_LOW] & MAX_UINT8);
    return oss.str();
}

bool EsimFile::ProcessObtainEidDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(getEidMutex_, isEidReady_, getEidCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_EID);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr!");
        NotifyReady(getEidMutex_, isEidReady_, getEidCv_);
        return false;
    }
    std::vector<uint8_t> outPutBytes;
    uint32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero!");
        NotifyReady(getEidMutex_, isEidReady_, getEidCv_);
        return false;
    }
    std::string strResult = Asn1Utils::BytesToHexStr(outPutBytes);

    eid_ = strResult;
    NotifyReady(getEidMutex_, isEidReady_, getEidCv_);
    return true;
}

std::shared_ptr<Asn1Node> EsimFile::Asn1ParseResponse(const std::vector<uint8_t> &response, uint32_t respLength)
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
    IccFileData rawData;
    if (!GetRawDataFromEvent(event, rawData)) {
        TELEPHONY_LOGE("rawData is nullptr within rcvMsg");
        NotifyReady(euiccInfo1Mutex_, isEuiccInfo1Ready_, euiccInfo1Cv_);
        return false;
    }
    TELEPHONY_LOGI("input raw data:sw1=%{public}02X, sw2=%{public}02X, length=%{public}zu",
        rawData.sw1, rawData.sw2, rawData.resultData.length());
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(rawData.resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse error!");
        NotifyReady(euiccInfo1Mutex_, isEuiccInfo1Ready_, euiccInfo1Cv_);
        return false;
    }
    if (!ObtainEuiccInfo1ParseTagCtx2(root)) {
        TELEPHONY_LOGE("ObtainEuiccInfo1ParseTagCtx2 error!");
        NotifyReady(euiccInfo1Mutex_, isEuiccInfo1Ready_, euiccInfo1Cv_);
        return false;
    }
    std::string responseHexStr = rawData.resultData;
    eUiccInfo_.response_ = Str8ToStr16(responseHexStr);
    TELEPHONY_LOGI("obtain eUiccInfo_ len:%{public}lu", eUiccInfo_.response_.length());
    NotifyReady(euiccInfo1Mutex_, isEuiccInfo1Ready_, euiccInfo1Cv_);
    return true;
}

bool EsimFile::ObtainEuiccInfo1ParseTagCtx2(std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> svnNode = root->Asn1GetChild(TAG_ESIM_CTX_2);
    if (svnNode == nullptr) {
        TELEPHONY_LOGE("svnNode is nullptr");
        return false;
    }
    std::vector<uint8_t> svnRaw;
    uint32_t svnRawlen = svnNode->Asn1AsBytes(svnRaw);
    if (svnRawlen < SVN_RAW_LENGTH_MIN) {
        TELEPHONY_LOGE("invalid SVN data");
        return false;
    }
    eUiccInfo_.osVersion_ = OHOS::Telephony::ToUtf16(MakeVersionString(svnRaw));
    return true;
}

bool EsimFile::ProcessRequestAllProfilesDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(allProfileInfoMutex_, isAllProfileInfoReady_, allProfileInfoCv_);
        return false;
    }

    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(allProfileInfoMutex_, isAllProfileInfoReady_, allProfileInfoCv_);
        return false;
    }

    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(allProfileInfoMutex_, isAllProfileInfoReady_, allProfileInfoCv_,
        MSG_ESIM_REQUEST_ALL_PROFILES, isHandleFinish);
    if (isHandleFinish) {
        TELEPHONY_LOGI("waits for continuing data...");
        return retValue;
    }

    return RealProcessRequestAllProfilesDone();
}

bool EsimFile::RealProcessRequestAllProfilesDone()
{
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(allProfileInfoMutex_, isAllProfileInfoReady_, allProfileInfoCv_);
        return false;
    }

    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr");
        NotifyReady(allProfileInfoMutex_, isAllProfileInfoReady_, allProfileInfoCv_);
        return false;
    }

    std::list<std::shared_ptr<Asn1Node>> profileNodes;
    profileRoot->Asn1GetChildren(TAG_ESIM_PROFILE_INFO, profileNodes);
    std::shared_ptr<Asn1Node> curNode = nullptr;
    EuiccProfileInfo euiccProfileInfo = {{0}};
    euiccProfileInfoList_.profiles_.clear();
    for (auto it = profileNodes.begin(); it != profileNodes.end(); ++it) {
        curNode = *it;
        if (!curNode->Asn1HasChild(TAG_ESIM_ICCID)) {
            TELEPHONY_LOGE("Profile must have an ICCID.");
            continue;
        }
        BuildBasicProfileInfo(&euiccProfileInfo, curNode);
        EuiccProfile euiccProfile;
        ConvertProfileInfoToApiStruct(euiccProfile, euiccProfileInfo);
        euiccProfileInfoList_.profiles_.push_back(euiccProfile);
    }

    euiccProfileInfoList_.result_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_OK);
    NotifyReady(allProfileInfoMutex_, isAllProfileInfoReady_, allProfileInfoCv_);
    TELEPHONY_LOGI("asn decode success");
    return true;
}

bool EsimFile::SplitMccAndMnc(const std::string mccMnc, std::string &mcc, std::string &mnc)
{
    std::string mMcc(NUMBER_THREE, '\0');
    mMcc[NUMBER_ZERO] = mccMnc[NUMBER_ONE];
    mMcc[NUMBER_ONE] = mccMnc[NUMBER_ZERO];
    mMcc[NUMBER_TWO] = mccMnc[NUMBER_THREE];

    std::string mMnc(NUMBER_THREE, '\0');
    if (mccMnc[NUMBER_TWO] == 'F') {
        mMnc[NUMBER_ZERO] = mccMnc[NUMBER_FIVE];
        mMnc[NUMBER_ONE] = mccMnc[NUMBER_FOUR];
    } else {
        mMnc[NUMBER_ZERO] = mccMnc[NUMBER_FIVE];
        mMnc[NUMBER_ONE] = mccMnc[NUMBER_FOUR];
        mMnc[NUMBER_TWO] = mccMnc[NUMBER_TWO];
    }
    mcc = mMcc.c_str();
    mnc = mMnc.c_str();
    return true;
}

void EsimFile::ConvertProfileInfoToApiStruct(EuiccProfile &dst, EuiccProfileInfo &src)
{
    dst.iccId_ = OHOS::Telephony::ToUtf16(src.iccid);
    dst.nickName_ = OHOS::Telephony::ToUtf16(src.nickname);
    dst.serviceProviderName_ = OHOS::Telephony::ToUtf16(src.serviceProviderName);
    dst.profileName_ = OHOS::Telephony::ToUtf16(src.profileName);
    dst.state_ = static_cast<ProfileState>(src.profileState);
    dst.profileClass_ = static_cast<ProfileClass>(src.profileClass);
    dst.policyRules_ = static_cast<PolicyRules>(src.policyRules);

    // split mccMnc to mcc and mnc
    std::string mcc = "";
    std::string mnc = "";
    SplitMccAndMnc(src.operatorId.mccMnc, mcc, mnc);
    dst.carrierId_.mcc_ = OHOS::Telephony::ToUtf16(mcc);
    dst.carrierId_.mnc_ = OHOS::Telephony::ToUtf16(mnc);
    dst.carrierId_.gid1_ = OHOS::Telephony::ToUtf16(src.operatorId.gid1);
    dst.carrierId_.gid2_ = OHOS::Telephony::ToUtf16(src.operatorId.gid2);
    dst.accessRules_.clear();
}

void EsimFile::BuildBasicProfileInfo(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &profileNode)
{
    if (eProfileInfo == nullptr || profileNode == nullptr) {
        TELEPHONY_LOGE("BuildBasicProfileInfo failed");
        return;
    }
    std::shared_ptr<Asn1Node> iccIdNode = profileNode->Asn1GetChild(TAG_ESIM_ICCID);
    if (iccIdNode == nullptr) {
        TELEPHONY_LOGE("iccIdNode is nullptr");
        return;
    }
    std::vector<uint8_t> iccidBytes;
    uint32_t iccidBytesLen = iccIdNode->Asn1AsBytes(iccidBytes);
    Asn1Utils::BchToString(iccidBytes, eProfileInfo->iccid);
    if (profileNode->Asn1HasChild(TAG_ESIM_NICKNAME)) {
        std::shared_ptr<Asn1Node> nickNameNode = profileNode->Asn1GetChild(TAG_ESIM_NICKNAME);
        if (nickNameNode == nullptr) {
            TELEPHONY_LOGE("nickNameNode is nullptr");
            return;
        }
        std::vector<uint8_t> nickNameBytes;
        nickNameNode->Asn1AsBytes(nickNameBytes);
        eProfileInfo->nickname = Asn1Utils::BytesToString(nickNameBytes);
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_OBTAIN_OPERATOR_NAME)) {
        std::shared_ptr<Asn1Node> serviceProviderNameNode = profileNode->Asn1GetChild(TAG_ESIM_OBTAIN_OPERATOR_NAME);
        if (serviceProviderNameNode == nullptr) {
            TELEPHONY_LOGE("serviceProviderNameNode is nullptr");
            return;
        }
        std::vector<uint8_t> serviceProviderNameBytes;
        serviceProviderNameNode->Asn1AsBytes(serviceProviderNameBytes);
        eProfileInfo->serviceProviderName = Asn1Utils::BytesToString(serviceProviderNameBytes);
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_PROFILE_NAME)) {
        std::shared_ptr<Asn1Node> profileNameNode = profileNode->Asn1GetChild(TAG_ESIM_PROFILE_NAME);
        if (profileNameNode == nullptr) {
            TELEPHONY_LOGE("profileNameNode is nullptr");
            return;
        }
        std::vector<uint8_t> profileNameBytes;
        profileNameNode->Asn1AsBytes(profileNameBytes);
        eProfileInfo->profileName = Asn1Utils::BytesToString(profileNameBytes);
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_OPERATOR_ID)) {
        std::shared_ptr<Asn1Node> pOperatorId = profileNode->Asn1GetChild(TAG_ESIM_OPERATOR_ID);
        BuildOperatorId(eProfileInfo, pOperatorId);
    }

    BuildAdvancedProfileInfo(eProfileInfo, profileNode);
}

void EsimFile::BuildAdvancedProfileInfo(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &profileNode)
{
    if (eProfileInfo == nullptr || profileNode == nullptr) {
        TELEPHONY_LOGE("BuildAdvancedProfileInfo failed");
        return;
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_PROFILE_STATE)) {
        std::shared_ptr<Asn1Node> profileStateNode = profileNode->Asn1GetChild(TAG_ESIM_PROFILE_STATE);
        if (profileStateNode == nullptr) {
            TELEPHONY_LOGE("profileStateNode is nullptr");
            return;
        }
        int32_t ret = profileStateNode->Asn1AsInteger();
        eProfileInfo->profileState = ((ret == TELEPHONY_ERR_ARGUMENT_INVALID) ? ESIM_PROFILE_STATE_DISABLED : ret);
    } else {
        eProfileInfo->profileState = ESIM_PROFILE_STATE_DISABLED;
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_PROFILE_CLASS)) {
        std::shared_ptr<Asn1Node> profileClassNode = profileNode->Asn1GetChild(TAG_ESIM_PROFILE_CLASS);
        if (profileClassNode == nullptr) {
            TELEPHONY_LOGE("profileClassNode is nullptr");
            return;
        }
        eProfileInfo->profileClass = profileClassNode->Asn1AsInteger();
    } else {
        eProfileInfo->profileClass = PROFILE_CLASS_OPERATIONAL;
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_PROFILE_POLICY_RULE)) {
        std::shared_ptr<Asn1Node> profilePolicyRuleNode = profileNode->Asn1GetChild(TAG_ESIM_PROFILE_POLICY_RULE);
        if (profilePolicyRuleNode == nullptr) {
            TELEPHONY_LOGE("profilePolicyRuleNode is nullptr");
            return;
        }
        eProfileInfo->policyRules = profilePolicyRuleNode->Asn1AsBits();
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_CARRIER_PRIVILEGE_RULES)) {
        std::list<std::shared_ptr<Asn1Node>> refArDoNodes;
        std::shared_ptr<Asn1Node> carrierPrivilegeRulesNode =
            profileNode->Asn1GetChild(TAG_ESIM_CARRIER_PRIVILEGE_RULES);
        if (carrierPrivilegeRulesNode == nullptr) {
            TELEPHONY_LOGE("carrierPrivilegeRulesNode is nullptr");
            return;
        }
        carrierPrivilegeRulesNode->Asn1GetChildren(TAG_ESIM_REF_AR_DO, refArDoNodes);
    }
}

void EsimFile::BuildOperatorId(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &operatorIdNode)
{
    if (eProfileInfo == nullptr || operatorIdNode == nullptr) {
        TELEPHONY_LOGE("BuildOperatorId failed");
        return;
    }
    if (operatorIdNode->Asn1HasChild(TAG_ESIM_CTX_0)) {
        std::shared_ptr<Asn1Node> nodeCtx0 = operatorIdNode->Asn1GetChild(TAG_ESIM_CTX_0);
        if (nodeCtx0 == nullptr) {
            TELEPHONY_LOGE("nodeCtx0 is nullptr");
            return;
        }
        nodeCtx0->Asn1AsString(eProfileInfo->operatorId.mccMnc);
    }
    if (operatorIdNode->Asn1HasChild(TAG_ESIM_CTX_1)) {
        std::shared_ptr<Asn1Node> nodeCtx1 = operatorIdNode->Asn1GetChild(TAG_ESIM_CTX_1);
        if (nodeCtx1 == nullptr) {
            TELEPHONY_LOGE("nodeCtx1 is nullptr");
            return;
        }
        nodeCtx1->Asn1AsString(eProfileInfo->operatorId.gid1);
    }
    if (operatorIdNode->Asn1HasChild(TAG_ESIM_CTX_2)) {
        std::shared_ptr<Asn1Node> nodeCtx2 = operatorIdNode->Asn1GetChild(TAG_ESIM_CTX_2);
        if (nodeCtx2 == nullptr) {
            TELEPHONY_LOGE("nodeCtx2 is nullptr");
            return;
        }
        nodeCtx2->Asn1AsString(eProfileInfo->operatorId.gid2);
    }
    return;
}

int32_t EsimFile::DisableProfile(int32_t portIndex, const std::u16string &iccId)
{
    disableProfileResult_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        disableProfileResult_ = static_cast<int32_t>(resultFlag);
        return disableProfileResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventDisableProfile = BuildCallerInfo(MSG_ESIM_DISABLE_PROFILE);
    if (!ProcessDisableProfile(slotId_, eventDisableProfile)) {
        TELEPHONY_LOGE("ProcessDisableProfile encode failed");
        SyncCloseChannel();
        return disableProfileResult_;
    }
    isDisableProfileReady_ = false;
    std::unique_lock<std::mutex> lock(disableProfileMutex_);
    if (!disableProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isDisableProfileReady_; })) {
        SyncCloseChannel();
        return disableProfileResult_;
    }
    SyncCloseChannel();
    return disableProfileResult_;
}

std::string EsimFile::ObtainSmdsAddress(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return "";
    }
    AppExecFwk::InnerEvent::Pointer eventObtainSmdsAddress = BuildCallerInfo(MSG_ESIM_OBTAIN_SMDS_ADDRESS);
    if (!ProcessObtainSmdsAddress(slotId_, eventObtainSmdsAddress)) {
        TELEPHONY_LOGE("ProcessObtainSmdsAddress encode failed");
        SyncCloseChannel();
        return "";
    }
    isSmdsAddressReady_ = false;
    std::unique_lock<std::mutex> lock(smdsAddressMutex_);
    if (!smdsAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSmdsAddressReady_; })) {
        SyncCloseChannel();
        return "";
    }
    SyncCloseChannel();
    return smdsAddress_;
}

EuiccRulesAuthTable EsimFile::ObtainRulesAuthTable(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return EuiccRulesAuthTable();
    }
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable = BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    if (!ProcessRequestRulesAuthTable(slotId_, eventRequestRulesAuthTable)) {
        TELEPHONY_LOGE("ProcessRequestRulesAuthTable encode failed");
        SyncCloseChannel();
        return EuiccRulesAuthTable();
    }
    isRulesAuthTableReady_ = false;
    std::unique_lock<std::mutex> lock(rulesAuthTableMutex_);
    if (!rulesAuthTableCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isRulesAuthTableReady_; })) {
        SyncCloseChannel();
        return EuiccRulesAuthTable();
    }
    SyncCloseChannel();
    return eUiccRulesAuthTable_;
}

ResponseEsimInnerResult EsimFile::ObtainEuiccChallenge(int32_t portIndex)
{
    responseChallengeResult_ = ResponseEsimInnerResult();
    esimProfile_.portIndex = portIndex;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        responseChallengeResult_.resultCode_ = static_cast<int32_t>(resultFlag);
        return responseChallengeResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventEUICCChanllenge = BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE);
    if (!ProcessObtainEuiccChallenge(slotId_, eventEUICCChanllenge)) {
        TELEPHONY_LOGE("ProcessObtainEuiccChallenge encode failed");
        SyncCloseChannel();
        responseChallengeResult_.resultCode_ =
            static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return responseChallengeResult_;
    }
    isEuiccChallengeReady_ = false;
    std::unique_lock<std::mutex> lock(euiccChallengeMutex_);
    if (!euiccChallengeCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isEuiccChallengeReady_; })) {
        SyncCloseChannel();
        responseChallengeResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_WAIT_TIMEOUT);
        return responseChallengeResult_;
    }
    SyncCloseChannel();
    return responseChallengeResult_;
}

bool EsimFile::ProcessDisableProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    if (builder == nullptr || subBuilder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string str = OHOS::Telephony::ToUtf8(esimProfile_.iccId);
    Asn1Utils::BcdToBytes(str, iccidBytes);
    subBuilder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.size());
    std::shared_ptr<Asn1Node> subNode = subBuilder->Asn1Build();
    if (subNode == nullptr) {
        return false;
    }
    builder->Asn1AddChild(subNode);
    builder->Asn1AddChildAsBoolean(TAG_ESIM_CTX_1, true);
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

bool EsimFile::ProcessObtainSmdsAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_CONFIGURED_ADDRESSES);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
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

bool EsimFile::ProcessRequestRulesAuthTable(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_RAT);
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

bool EsimFile::ProcessObtainEuiccChallenge(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EUICC_CHALLENGE);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
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

bool EsimFile::ProcessDisableProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(disableProfileMutex_, isDisableProfileReady_, disableProfileCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        NotifyReady(disableProfileMutex_, isDisableProfileReady_, disableProfileCv_);
        return false;
    }
    disableProfileResult_ = pAsn1Node->Asn1AsInteger();
    NotifyReady(disableProfileMutex_, isDisableProfileReady_, disableProfileCv_);
    return true;
}

bool EsimFile::ProcessObtainSmdsAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(smdsAddressMutex_, isSmdsAddressReady_, smdsAddressCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_1);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr!");
        NotifyReady(smdsAddressMutex_, isSmdsAddressReady_, smdsAddressCv_);
        return false;
    }
    std::vector<uint8_t> outPutBytes;
    profileRoot->Asn1AsBytes(outPutBytes);
    smdsAddress_ = Asn1Utils::BytesToString(outPutBytes);
    NotifyReady(smdsAddressMutex_, isSmdsAddressReady_, smdsAddressCv_);
    return true;
}

struct CarrierIdentifier CarrierIdentifiers(const std::vector<uint8_t> &mccMncData, int mccMncLen,
    const std::u16string &gid1, const std::u16string &gid2)
{
    std::string strResult = Asn1Utils::BytesToHexStr(mccMncData);
    std::string mMcc(NUMBER_THREE, '\0');
    mMcc[NUMBER_ZERO] = strResult[NUMBER_ONE];
    mMcc[NUMBER_ONE] = strResult[NUMBER_ZERO];
    mMcc[NUMBER_TWO] = strResult[NUMBER_THREE];
    std::string mMnc(NUMBER_THREE, '\0');
    mMnc[NUMBER_ZERO] = strResult[NUMBER_FIVE];
    mMnc[NUMBER_ONE] = strResult[NUMBER_FOUR];
    if (strResult[NUMBER_TWO] != 'F') {
        mMnc[NUMBER_TWO] = strResult[NUMBER_TWO];
    }
    CarrierIdentifier carrierId;
    carrierId.mcc_ = OHOS::Telephony::ToUtf16(std::string(mMcc.c_str()));
    carrierId.mnc_ = OHOS::Telephony::ToUtf16(std::string(mMnc.c_str()));
    carrierId.gid1_ = gid1;
    carrierId.gid2_ = gid2;
    return carrierId;
}

struct CarrierIdentifier buildCarrierIdentifiers(std::shared_ptr<Asn1Node> &root)
{
    std::u16string gid1;
    std::u16string gid2;
    std::vector<uint8_t> gid1Byte;
    std::vector<uint8_t> gid2Byte;
    std::string strResult;
    CarrierIdentifier defaultCarrier = CarrierIdentifiers({}, 0, u"", u"");
    if (root->Asn1HasChild(TAG_ESIM_CTX_1)) {
        std::shared_ptr<Asn1Node> node = root->Asn1GetChild(TAG_ESIM_CTX_1);
        if (node == nullptr) {
            return defaultCarrier;
        }
        node->Asn1AsBytes(gid1Byte);
        strResult = Asn1Utils::BytesToHexStr(gid1Byte);
        gid1 = OHOS::Telephony::ToUtf16(strResult);
    }
    if (root->Asn1HasChild(TAG_ESIM_CTX_2)) {
        std::shared_ptr<Asn1Node> node = root->Asn1GetChild(TAG_ESIM_CTX_2);
        if (node == nullptr) {
            return defaultCarrier;
        }
        node->Asn1AsBytes(gid2Byte);
        strResult = Asn1Utils::BytesToHexStr(gid2Byte);
        gid2 = OHOS::Telephony::ToUtf16(strResult);
    }

    std::vector<uint8_t> mccMnc;
    std::shared_ptr<Asn1Node> ctx0Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (ctx0Node == nullptr) {
        return defaultCarrier;
    }
    uint32_t mccMncLen = ctx0Node->Asn1AsBytes(mccMnc);
    CarrierIdentifier myCarrier = CarrierIdentifiers(mccMnc, mccMncLen, gid1, gid2);
    return myCarrier;
}

bool EsimFile::RequestRulesAuthTableParseTagCtxComp0(std::shared_ptr<Asn1Node> &root)
{
    std::list<std::shared_ptr<Asn1Node>> Nodes;
    std::list<std::shared_ptr<Asn1Node>> opIdNodes;
    root->Asn1GetChildren(TAG_ESIM_CTX_COMP_0, Nodes);
    for (auto it = Nodes.begin(); it != Nodes.end(); ++it) {
        std::shared_ptr<Asn1Node> node = *it;
        if (node == nullptr) {
            return false;
        }
        std::shared_ptr<Asn1Node> grandson = node->Asn1GetGrandson(TAG_ESIM_SEQUENCE, TAG_ESIM_CTX_COMP_1);
        if (grandson == nullptr) {
            return false;
        }
        int32_t opIdNodesRes = grandson->Asn1GetChildren(TAG_ESIM_SEQUENCE, opIdNodes);
        if (opIdNodesRes != 0) {
            return false;
        }
        for (auto iter = opIdNodes.begin(); iter != opIdNodes.end(); ++iter) {
            std::shared_ptr<Asn1Node> curNode = nullptr;
            curNode = *iter;
            if (curNode == nullptr) {
                return false;
            }
            eUiccRulesAuthTable_.carrierIds_.push_back(buildCarrierIdentifiers(curNode));
        }
        grandson = node->Asn1GetGrandson(TAG_ESIM_SEQUENCE, TAG_ESIM_CTX_0);
        if (grandson == nullptr) {
            return false;
        }
        int32_t policyRules = grandson->Asn1AsInteger();
        grandson = node->Asn1GetGrandson(TAG_ESIM_SEQUENCE, TAG_ESIM_CTX_2);
        if (grandson == nullptr) {
            return false;
        }
        int32_t policyRuleFlags = grandson->Asn1AsInteger();
        eUiccRulesAuthTable_.policyRules_.push_back(policyRules);
        eUiccRulesAuthTable_.policyRuleFlags_.push_back(policyRuleFlags);
    }
    return true;
}

bool EsimFile::ProcessRequestRulesAuthTableDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(rulesAuthTableMutex_, isRulesAuthTableReady_, rulesAuthTableCv_);
        return false;
    }
    if (!RequestRulesAuthTableParseTagCtxComp0(root)) {
        TELEPHONY_LOGE("RequestRulesAuthTableParseTagCtxComp0 error");
        NotifyReady(rulesAuthTableMutex_, isRulesAuthTableReady_, rulesAuthTableCv_);
        return false;
    }
    NotifyReady(rulesAuthTableMutex_, isRulesAuthTableReady_, rulesAuthTableCv_);
    return true;
}

bool EsimFile::ProcessObtainEuiccChallengeDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(euiccChallengeMutex_, isEuiccChallengeReady_, euiccChallengeCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("Asn1GetChild failed");
        NotifyReady(euiccChallengeMutex_, isEuiccChallengeReady_, euiccChallengeCv_);
        return false;
    }
    std::vector<uint8_t> profileResponseByte;
    uint32_t byteLen = profileRoot->Asn1AsBytes(profileResponseByte);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero");
        NotifyReady(euiccChallengeMutex_, isEuiccChallengeReady_, euiccChallengeCv_);
        return false;
    }
    std::string resultStr = Asn1Utils::BytesToHexStr(profileResponseByte);
    responseChallengeResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_OK);
    responseChallengeResult_.response_ = OHOS::Telephony::ToUtf16(resultStr);
    NotifyReady(euiccChallengeMutex_, isEuiccChallengeReady_, euiccChallengeCv_);
    return true;
}

std::string EsimFile::ObtainDefaultSmdpAddress()
{
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return "";
    }
    AppExecFwk::InnerEvent::Pointer eventSmdpAddress = BuildCallerInfo(MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE);
    if (!ProcessObtainDefaultSmdpAddress(slotId_, eventSmdpAddress)) {
        TELEPHONY_LOGE("ProcessObtainDefaultSmdpAddress encode failed");
        SyncCloseChannel();
        return "";
    }
    isObtainDefaultSmdpAddressReady_ = false;
    std::unique_lock<std::mutex> lock(obtainDefaultSmdpAddressMutex_);
    if (!obtainDefaultSmdpAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isObtainDefaultSmdpAddressReady_; })) {
        SyncCloseChannel();
        return "";
    }
    SyncCloseChannel();
    return defaultDpAddress_;
}

ResponseEsimInnerResult EsimFile::CancelSession(const std::u16string &transactionId, CancelReason cancelReason)
{
    cancelSessionResult_ = ResponseEsimInnerResult();
    esimProfile_.transactionId = transactionId;
    esimProfile_.cancelReason = cancelReason;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        cancelSessionResult_.resultCode_ = static_cast<int32_t>(resultFlag);
        return cancelSessionResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventCancelSession = BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    if (!ProcessCancelSession(slotId_, eventCancelSession)) {
        TELEPHONY_LOGE("ProcessCancelSession encode failed");
        SyncCloseChannel();
        cancelSessionResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return cancelSessionResult_;
    }
    isCancelSessionReady_ = false;
    std::unique_lock<std::mutex> lock(cancelSessionMutex_);
    if (!cancelSessionCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isCancelSessionReady_; })) {
        SyncCloseChannel();
        cancelSessionResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_WAIT_TIMEOUT);
        return cancelSessionResult_;
    }
    SyncCloseChannel();
    return cancelSessionResult_;
}

EuiccProfile EsimFile::ObtainProfile(int32_t portIndex, const std::u16string &iccId)
{
    eUiccProfile_ = EuiccProfile();
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return eUiccProfile_;
    }
    AppExecFwk::InnerEvent::Pointer eventGetProfile = BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    if (!ProcessGetProfile(slotId_, eventGetProfile)) {
        TELEPHONY_LOGE("ProcessGetProfile encode failed");
        SyncCloseChannel();
        return eUiccProfile_;
    }
    isObtainProfileReady_ = false;
    std::unique_lock<std::mutex> lock(obtainProfileMutex_);
    if (!obtainProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isObtainProfileReady_; })) {
        SyncCloseChannel();
        return eUiccProfile_;
    }
    SyncCloseChannel();
    return eUiccProfile_;
}

bool EsimFile::ProcessObtainDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_CONFIGURED_ADDRESSES);
    if (builder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
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

bool EsimFile::ProcessGetProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_PROFILES);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    if (builder == nullptr || subBuilder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string iccid = OHOS::Telephony::ToUtf8(esimProfile_.iccId);
    Asn1Utils::BcdToBytes(iccid, iccidBytes);
    subBuilder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.size());
    std::shared_ptr<Asn1Node> subNode = subBuilder->Asn1Build();
    builder->Asn1AddChild(subNode);
    std::vector<uint8_t> getProfileTags = GetProfileTagList();
    builder->Asn1AddChildAsBytes(TAG_ESIM_TAG_LIST, getProfileTags, getProfileTags.size());
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

std::vector<uint8_t> EsimFile::GetProfileTagList()
{
    unsigned char EUICC_PROFILE_TAGS[] = {
        static_cast<unsigned char>(TAG_ESIM_ICCID),
        static_cast<unsigned char>(TAG_ESIM_NICKNAME),
        static_cast<unsigned char>(TAG_ESIM_OBTAIN_OPERATOR_NAME),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_NAME),
        static_cast<unsigned char>(TAG_ESIM_OPERATOR_ID),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_STATE / PROFILE_DEFAULT_NUMBER),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_STATE % PROFILE_DEFAULT_NUMBER),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_CLASS),
        static_cast<unsigned char>(TAG_ESIM_PROFILE_POLICY_RULE),
        static_cast<unsigned char>(TAG_ESIM_CARRIER_PRIVILEGE_RULES / PROFILE_DEFAULT_NUMBER),
        static_cast<unsigned char>(TAG_ESIM_CARRIER_PRIVILEGE_RULES % PROFILE_DEFAULT_NUMBER),
    };
    std::vector<uint8_t> getProfileTags;
    for (const unsigned char tag : EUICC_PROFILE_TAGS) {
        getProfileTags.push_back(tag);
    }
    return getProfileTags;
}

bool EsimFile::ProcessCancelSession(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_CANCEL_SESSION);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::string transactionIdStr = Str16ToStr8(esimProfile_.transactionId);
    std::vector<uint8_t> transactionIdByte = Asn1Utils::HexStrToBytes(transactionIdStr);
    builder->Asn1AddChildAsBytes(TAG_ESIM_CTX_0, transactionIdByte, transactionIdByte.size());
    builder->Asn1AddChildAsInteger(TAG_ESIM_CTX_1, static_cast<uint32_t>(esimProfile_.cancelReason));
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

bool EsimFile::ProcessObtainDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(obtainDefaultSmdpAddressMutex_, isObtainDefaultSmdpAddressReady_, obtainDefaultSmdpAddressCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(obtainDefaultSmdpAddressMutex_, isObtainDefaultSmdpAddressReady_, obtainDefaultSmdpAddressCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr");
        NotifyReady(obtainDefaultSmdpAddressMutex_, isObtainDefaultSmdpAddressReady_, obtainDefaultSmdpAddressCv_);
        return false;
    }
    std::vector<uint8_t> outPutBytes;
    uint32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero");
        NotifyReady(obtainDefaultSmdpAddressMutex_, isObtainDefaultSmdpAddressReady_, obtainDefaultSmdpAddressCv_);
        return false;
    }
    defaultDpAddress_ = Asn1Utils::BytesToHexStr(outPutBytes);
    NotifyReady(obtainDefaultSmdpAddressMutex_, isObtainDefaultSmdpAddressReady_, obtainDefaultSmdpAddressCv_);
    return true;
}

bool EsimFile::ProcessCancelSessionDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        NotifyReady(cancelSessionMutex_, isCancelSessionReady_, cancelSessionCv_);
        return false;
    }
    IccFileData rawData;
    if (!GetRawDataFromEvent(event, rawData)) {
        TELEPHONY_LOGE("rawData is nullptr within rcvMsg");
        NotifyReady(cancelSessionMutex_, isCancelSessionReady_, cancelSessionCv_);
        return false;
    }
    cancelSessionResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_OK);
    cancelSessionResult_.response_ = OHOS::Telephony::ToUtf16(rawData.resultData);
    NotifyReady(cancelSessionMutex_, isCancelSessionReady_, cancelSessionCv_);
    return true;
}

bool EsimFile::GetProfileDoneParseProfileInfo(std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> profileInfo = root->Asn1GetGrandson(TAG_ESIM_CTX_COMP_0, TAG_ESIM_PROFILE_INFO);
    if (profileInfo == nullptr) {
        TELEPHONY_LOGE("get profile list failed");
        return false;
    }
    std::shared_ptr<Asn1Node> iccNode = profileInfo->Asn1GetChild(TAG_ESIM_ICCID);
    if (iccNode == nullptr) {
        TELEPHONY_LOGE("nodeIcc is nullptr");
        return false;
    }
    EuiccProfileInfo euiccProfileInfo = {{0}};
    BuildBasicProfileInfo(&euiccProfileInfo, profileInfo);
    ConvertProfileInfoToApiStruct(eUiccProfile_, euiccProfileInfo);
    return true;
}

bool EsimFile::ProcessGetProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        NotifyReady(obtainProfileMutex_, isObtainProfileReady_, obtainProfileCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(obtainProfileMutex_, isObtainProfileReady_, obtainProfileCv_);
        return false;
    }
    if (!GetProfileDoneParseProfileInfo(root)) {
        TELEPHONY_LOGE("GetProfileDoneParseProfileInfo error!");
        NotifyReady(obtainProfileMutex_, isObtainProfileReady_, obtainProfileCv_);
        return false;
    }
    NotifyReady(obtainProfileMutex_, isObtainProfileReady_, obtainProfileCv_);
    return true;
}

int32_t EsimFile::ResetMemory(ResetOption resetOption)
{
    resetResult_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.option = resetOption;

    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        resetResult_ = static_cast<int32_t>(resultFlag);
        return resetResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventResetMemory = BuildCallerInfo(MSG_ESIM_RESET_MEMORY);
    if (!ProcessResetMemory(slotId_, eventResetMemory)) {
        TELEPHONY_LOGE("ProcessResetMemory encode failed");
        SyncCloseChannel();
        return resetResult_;
    }
    isResetMemoryReady_ = false;
    std::unique_lock<std::mutex> lock(resetMemoryMutex_);
    if (!resetMemoryCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isResetMemoryReady_; })) {
        SyncCloseChannel();
        return resetResult_;
    }
    SyncCloseChannel();
    return resetResult_;
}

int32_t EsimFile::SetDefaultSmdpAddress(const std::u16string &defaultSmdpAddress)
{
    setDpAddressResult_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.defaultSmdpAddress = defaultSmdpAddress;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        setDpAddressResult_ = static_cast<int32_t>(resultFlag);
        return setDpAddressResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventSetSmdpAddress = BuildCallerInfo(MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE);
    if (!ProcessEstablishDefaultSmdpAddress(slotId_, eventSetSmdpAddress)) {
        TELEPHONY_LOGE("ProcessEstablishDefaultSmdpAddress encode failed!!");
        SyncCloseChannel();
        return setDpAddressResult_;
    }
    isSetDefaultSmdpAddressReady_ = false;
    std::unique_lock<std::mutex> lock(setDefaultSmdpAddressMutex_);
    if (!setDefaultSmdpAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSetDefaultSmdpAddressReady_; })) {
        SyncCloseChannel();
        return setDpAddressResult_;
    }
    SyncCloseChannel();
    return setDpAddressResult_;
}

bool EsimFile::ProcessEstablishDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }

    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_SET_DEFAULT_SMDP_ADDRESS);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::string address = OHOS::Telephony::ToUtf8(esimProfile_.defaultSmdpAddress);
    builder->Asn1AddChildAsString(TAG_ESIM_TARGET_ADDR, address);
    ApduSimIORequestInfo reqInfo;
    CommBuildOneApduReqInfo(reqInfo, builder);
    if (telRilManager_ == nullptr) {
        return false;
    }
    telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
    return true;
}

bool EsimFile::ProcessEstablishDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(setDefaultSmdpAddressMutex_, isSetDefaultSmdpAddressReady_, setDefaultSmdpAddressCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        NotifyReady(setDefaultSmdpAddressMutex_, isSetDefaultSmdpAddressReady_, setDefaultSmdpAddressCv_);
        return false;
    }
    setDpAddressResult_ = pAsn1Node->Asn1AsInteger();
    NotifyReady(setDefaultSmdpAddressMutex_, isSetDefaultSmdpAddressReady_, setDefaultSmdpAddressCv_);
    return true;
}

bool EsimFile::IsSupported()
{
    char buf[ATR_LENGTH + 1] = {0};
    if (isSupported_) {
        return isSupported_;
    }
    GetParameter(TEL_ESIM_SUPPORT, "", buf, ATR_LENGTH);
    ResetResponse resetResponse;
    std::string atr(buf);
    if (atr.empty()) {
        if (!ObtainEid().empty()) {
            isSupported_ = true;
        }
        return isSupported_;
    }
    resetResponse.AnalysisAtrData(atr);
    isSupported_ = resetResponse.IsEuiccAvailable();
    return isSupported_;
}

ResponseEsimInnerResult EsimFile::SendApduData(const std::u16string &aid, const EsimApduData &apduData)
{
    transApduDataResponse_ = ResponseEsimInnerResult();
    if (aid.empty()) {
        TELEPHONY_LOGE("Aid is empty");
        transApduDataResponse_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_AID_EMPTY);
        return transApduDataResponse_;
    }
    if (apduData.closeChannelFlag_) {
        if (IsSameAid(aid)) {
            SyncCloseChannel();
            return ResponseEsimInnerResult();
        }

        TELEPHONY_LOGE("SendApduData Close Channel failed");
        transApduDataResponse_.resultCode_ =
            static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_CLOSE_FAILED);
        return transApduDataResponse_;
    }

    esimProfile_.apduData = apduData;
    AppExecFwk::InnerEvent::Pointer eventSendApduData = BuildCallerInfo(MSG_ESIM_SEND_APUD_DATA);
    ResultInnerCode resultFlag = ObtainChannelSuccessAlllowSameAidReuse(aid);
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessAlllowSameAidReuse failed ,%{public}d", resultFlag);
        transApduDataResponse_.resultCode_ = static_cast<int32_t>(resultFlag);
        return transApduDataResponse_;
    }
    if (!ProcessSendApduData(slotId_, eventSendApduData)) {
        TELEPHONY_LOGE("ProcessSendApduData encode failed");
        SyncCloseChannel();
        transApduDataResponse_.resultCode_ =
            static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return transApduDataResponse_;
    }
    isSendApduDataReady_ = false;
    std::unique_lock<std::mutex> lock(sendApduDataMutex_);
    if (!sendApduDataCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSendApduDataReady_; })) {
        SyncCloseChannel();
        transApduDataResponse_.resultCode_ =
            static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_WAIT_TIMEOUT);
        return transApduDataResponse_;
    }
    return transApduDataResponse_;
}

bool EsimFile::ProcessResetMemory(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_EUICC_MEMORY_RESET);
    if (builder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    std::vector<uint8_t> resetMemoryTags;
    resetMemoryTags.push_back(static_cast<uint8_t>(EUICC_MEMORY_RESET_BIT_STR_FILL_LEN));
    resetMemoryTags.push_back(static_cast<uint8_t>(EUICC_MEMORY_RESET_BIT_STR_VALUE));
    builder->Asn1AddChildAsBytes(TAG_ESIM_CTX_2, resetMemoryTags, resetMemoryTags.size());
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

bool EsimFile::ProcessResetMemoryDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(resetMemoryMutex_, isResetMemoryReady_, resetMemoryCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> asn1NodeData = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (asn1NodeData == nullptr) {
        TELEPHONY_LOGE("asn1NodeData is nullptr");
        NotifyReady(resetMemoryMutex_, isResetMemoryReady_, resetMemoryCv_);
        return false;
    }
    resetResult_ = asn1NodeData->Asn1AsInteger();
    NotifyReady(resetMemoryMutex_, isResetMemoryReady_, resetMemoryCv_);
    return true;
}

bool EsimFile::ProcessSendApduData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::string hexStr = OHOS::Telephony::ToUtf8(esimProfile_.apduData.data_);
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> list = codec.GetCommands();
    if (list.empty()) {
        TELEPHONY_LOGE("node is empty");
        return false;
    }
    std::unique_ptr<ApduCommand> apdCmd = std::move(list.front());
    if (apdCmd == nullptr) {
        return false;
    }
    ApduSimIORequestInfo reqInfo;
    CopyApdCmdToReqInfo(reqInfo, apdCmd.get());
    if (esimProfile_.apduData.unusedDefaultReqHeadFlag_) {
        reqInfo.type = esimProfile_.apduData.instructionType_;
        reqInfo.instruction = esimProfile_.apduData.instruction_;
        reqInfo.p1 = esimProfile_.apduData.p1_;
        reqInfo.p2 = esimProfile_.apduData.p2_;
        reqInfo.p3 = esimProfile_.apduData.p3_;
    }
    if (telRilManager_ == nullptr) {
        return false;
    }
    int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
    if (apduResult == TELEPHONY_ERR_FAIL) {
        return false;
    }
    return true;
}

bool EsimFile::ProcessSendApduDataDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(sendApduDataMutex_, isSendApduDataReady_, sendApduDataCv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(sendApduDataMutex_, isSendApduDataReady_, sendApduDataCv_);
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    if (result == nullptr) {
        TELEPHONY_LOGE("result is nullptr");
        NotifyReady(sendApduDataMutex_, isSendApduDataReady_, sendApduDataCv_);
        return false;
    }
    transApduDataResponse_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_OK);
    transApduDataResponse_.response_ = OHOS::Telephony::ToUtf16(result->resultData);
    transApduDataResponse_.sw1_ = result->sw1;
    transApduDataResponse_.sw2_ = result->sw2;
    NotifyReady(sendApduDataMutex_, isSendApduDataReady_, sendApduDataCv_);
    return true;
}

ResponseEsimInnerResult EsimFile::ObtainPrepareDownload(const DownLoadConfigInfo &downLoadConfigInfo)
{
    preDownloadResult_ = ResponseEsimInnerResult();
    esimProfile_.portIndex = downLoadConfigInfo.portIndex_;
    esimProfile_.hashCc = downLoadConfigInfo.hashCc_;
    esimProfile_.smdpSigned2 = downLoadConfigInfo.smdpSigned2_;
    esimProfile_.smdpSignature2 = downLoadConfigInfo.smdpSignature2_;
    esimProfile_.smdpCertificate = downLoadConfigInfo.smdpCertificate_;

    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        preDownloadResult_.resultCode_ = static_cast<int32_t>(resultFlag);
        return preDownloadResult_;
    }
    recvCombineStr_ = "";
    if (!ProcessPrepareDownload(slotId_)) {
        TELEPHONY_LOGE("ProcessPrepareDownload encode failed");
        SyncCloseChannel();
        preDownloadResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return preDownloadResult_;
    }
    SyncCloseChannel();
    return preDownloadResult_;
}

ResponseEsimBppResult EsimFile::ObtainLoadBoundProfilePackage(int32_t portIndex,
    const std::u16string boundProfilePackage)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.boundProfilePackage = boundProfilePackage;

    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        loadBPPResult_.resultCode_ = static_cast<int32_t>(resultFlag);
        return loadBPPResult_;
    }
    recvCombineStr_ = "";
    if (!ProcessLoadBoundProfilePackage(slotId_)) {
        TELEPHONY_LOGE("ProcessLoadBoundProfilePackage encode failed");
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
    AppExecFwk::InnerEvent::Pointer eventListNotif = BuildCallerInfo(MSG_ESIM_LIST_NOTIFICATION);
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return EuiccNotificationList();
    }
    recvCombineStr_ = "";
    if (!ProcessListNotifications(slotId_, events, eventListNotif)) {
        TELEPHONY_LOGE("ProcessListNotifications encode failed");
        SyncCloseChannel();
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
    std::string destString = VCardUtils::DecodeBase64NoWrap(base64Src);
    std::vector<uint8_t> dest = Asn1Utils::StringToBytes(destString);
    std::shared_ptr<Asn1Decoder> decoder = std::make_shared<Asn1Decoder>(dest, 0, dest.size());
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
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_PREPARE_DOWNLOAD);
    if (builder == nullptr) {
        return false;
    }
    Asn1AddChildAsBase64(builder, dst.smdpSigned2);
    Asn1AddChildAsBase64(builder, dst.smdpSignature2);
    if (dst.hashCc.size() != 0) {
        std::vector<uint8_t> bytes = Asn1Utils::StringToBytes(VCardUtils::DecodeBase64NoWrap(dst.hashCc));
        builder->Asn1AddChildAsBytes(TAG_ESIM_OCTET_STRING_TYPE, bytes, bytes.size());
    }
    Asn1AddChildAsBase64(builder, dst.smdpCertificate);
    std::string hexStr;
    uint32_t hexStrLen = builder->Asn1BuilderToHexStr(hexStr);
    if (hexStrLen == 0) {
        return false;
    }
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    SplitSendLongData(codec, MSG_ESIM_PREPARE_DOWNLOAD_DONE,
        prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_);
    return true;
}

void EsimFile::SplitSendLongData(
    RequestApduBuild &codec, int32_t esimMessageId, std::mutex &mtx, bool &flag, std::condition_variable &cv)
{
    std::list<std::unique_ptr<ApduCommand>> apduCommandList = codec.GetCommands();
    for (const auto &cmd : apduCommandList) {
        if (!cmd) {
            return;
        }
        ApduSimIORequestInfo reqInfo;
        CopyApdCmdToReqInfo(reqInfo, cmd.get());
        AppExecFwk::InnerEvent::Pointer tmpResponseEvent = BuildCallerInfo(esimMessageId);
        if (telRilManager_ == nullptr) {
            return;
        }
        std::unique_lock<std::mutex> lock(mtx);
        flag = false;
        telRilManager_->SimTransmitApduLogicalChannel(slotId_, reqInfo, tmpResponseEvent);
        if (!cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
            [&flag]() { return flag; })) {
            return;
        }
    }
}

uint32_t EsimFile::CombineResponseDataFinish(IccFileData &fileData)
{
    if (fileData.sw1 == SW1_MORE_RESPONSE) {
        return RESPONS_DATA_NOT_FINISH;
    } else if (fileData.sw1 == SW1_VALUE_90 && fileData.sw2 == SW2_VALUE_00) {
        return RESPONS_DATA_FINISH;
    } else {
        return RESPONS_DATA_ERROR;
    }
}

void EsimFile::ProcessIfNeedMoreResponse(IccFileData &fileData, int32_t eventId)
{
    if (fileData.sw1 == SW1_MORE_RESPONSE) {
        ApduSimIORequestInfo reqInfo;
        RequestApduBuild codec(currentChannelId_);
        codec.BuildStoreData("");
        std::list<std::unique_ptr<ApduCommand>> list = codec.GetCommands();
        if (list.empty()) {
            TELEPHONY_LOGE("node is empty");
            return;
        }
        std::unique_ptr<ApduCommand> apdCmd = std::move(list.front());
        if (apdCmd == nullptr) {
            return;
        }
        apdCmd->data.cla = 0;
        apdCmd->data.ins = INS_GET_MORE_RESPONSE;
        apdCmd->data.p1 = 0;
        apdCmd->data.p2 = 0;
        apdCmd->data.p3 = static_cast<uint32_t>(fileData.sw2);
        CopyApdCmdToReqInfo(reqInfo, apdCmd.get());
        AppExecFwk::InnerEvent::Pointer responseEvent = BuildCallerInfo(eventId);
        if (telRilManager_ == nullptr) {
            return;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId_, reqInfo, responseEvent);
    }
}

uint32_t EsimFile::MergeRecvLongDataComplete(IccFileData &fileData, int32_t eventId)
{
    TELEPHONY_LOGI("eventId=%{public}d input sw1=%{public}02X, sw2=%{public}02X, data.length=%{public}zu",
        eventId, fileData.sw1, fileData.sw2, fileData.resultData.length());
    uint32_t result = CombineResponseDataFinish(fileData);
    if (result == RESPONS_DATA_ERROR) {
        TELEPHONY_LOGE("RESPONS_DATA_ERROR current_len:%{public}zu", recvCombineStr_.length());
        return result;
    }
    recvCombineStr_ = recvCombineStr_ + fileData.resultData;
    if (result == RESPONS_DATA_NOT_FINISH) {
        ProcessIfNeedMoreResponse(fileData, eventId);
        TELEPHONY_LOGI("RESPONS_DATA_NOT_FINISH current_len:%{public}zu", recvCombineStr_.length());
        return result;
    }
    TELEPHONY_LOGI("RESPONS_DATA_FINISH current_len:%{public}zu", recvCombineStr_.length());
    return result;
}

bool EsimFile::ProcessPrepareDownloadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_);
        return false;
    }
    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_,
        MSG_ESIM_PREPARE_DOWNLOAD_DONE, isHandleFinish);
    if (isHandleFinish) {
        return retValue;
    }
    return RealProcessPrepareDownloadDone();
}

bool EsimFile::RealProcessPrepareDownloadDone()
{
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> childNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    if (childNode != nullptr) {
        std::shared_ptr<Asn1Node> errCodeNode = childNode->Asn1GetChild(TAG_ESIM_UNI_2);
        if (errCodeNode != nullptr) {
            int32_t protocolErr = errCodeNode->Asn1AsInteger();
            if (protocolErr != TELEPHONY_ERR_ARGUMENT_INVALID) {
                TELEPHONY_LOGE("Prepare download error, es10x errcode: %{public}d", protocolErr);
                preDownloadResult_.resultCode_ = protocolErr;
                preDownloadResult_.response_ = u"";
                NotifyReady(prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_);
                return false;
            }
        }
    }
    preDownloadResult_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_OK);
    std::string responseByteStr = Asn1Utils::BytesToString(responseByte);
    std::string destString = VCardUtils::EncodeBase64(responseByteStr);
    preDownloadResult_.response_ = OHOS::Telephony::ToUtf16(destString);
    NotifyReady(prepareDownloadMutex_, isPrepareDownloadReady_, prepareDownloadCv_);
    return true;
}

bool EsimFile::DecodeBoundProfilePackage(const std::string &boundProfilePackageStr, std::shared_ptr<Asn1Node> &bppNode)
{
    std::string destString = VCardUtils::DecodeBase64NoWrap(boundProfilePackageStr);
    std::vector<uint8_t> dest = Asn1Utils::StringToBytes(destString);
    std::shared_ptr<Asn1Decoder> decoder = std::make_shared<Asn1Decoder>(dest, 0, dest.size());
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
    // 1. The BPP came with extraneous tags other than what the spec
    // mandates. We keep track of the total length of the BPP and compare it
    // to the length of the segments we care about. If they're different,
    // we'll throw an exception to indicate this.
    std::shared_ptr<Asn1Node> unknownBppSegment = bppNode->Asn1GetChild(TAG_ESIM_UNKNOWN_BPP_SEGMENT);
    if (unknownBppSegment != nullptr) {
        TELEPHONY_LOGE("recv GET_BPP_LOAD_ERROR_UNKNOWN_TAG");
        return false;
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
    if (sequenceOf86 == nullptr) {
        // 2. The BPP is missing a required tag. Upon calling bppNode.getChild,
        // an exception will occur if the expected tag is missing, though we
        // should make sure that the sequences are non-empty when appropriate as
        // well. A profile with no profile elements is invalid.
        TELEPHONY_LOGE("recv GET_BPP_LOAD_ERROR");
        return false;
    }
    BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
    SplitSendLongData(codec, MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE, loadBppMutex_, isLoadBppReady_, loadBppCv_);
    return true;
}

bool EsimFile::ProcessLoadBoundProfilePackageDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(loadBppMutex_, isLoadBppReady_, loadBppCv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(loadBppMutex_, isLoadBppReady_, loadBppCv_);
        return false;
    }
    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(loadBppMutex_, isLoadBppReady_, loadBppCv_,
        MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE, isHandleFinish);
    if (isHandleFinish) {
        return retValue;
    }
    return RealProcessLoadBoundProfilePackageDone();
}
bool EsimFile::RealProcessLoadBoundProfilePackageDone()
{
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    loadBPPResult_.response_ = OHOS::Telephony::ToUtf16(recvCombineStr_);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(loadBppMutex_, isLoadBppReady_, loadBppCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> nodeNotificationMetadata = LoadBoundProfilePackageParseProfileInstallResult(root);
    if (nodeNotificationMetadata == nullptr) {
        TELEPHONY_LOGE("nodeNotificationMetadata is nullptr");
        NotifyReady(loadBppMutex_, isLoadBppReady_, loadBppCv_);
        return false;
    }
    if (!LoadBoundProfilePackageParseNotificationMetadata(nodeNotificationMetadata)) {
        TELEPHONY_LOGE("LoadBoundProfilePackageParseNotificationMetadata error");
        NotifyReady(loadBppMutex_, isLoadBppReady_, loadBppCv_);
        return false;
    }
    loadBPPResult_.resultCode_ = 0;
    NotifyReady(loadBppMutex_, isLoadBppReady_, loadBppCv_);
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
        loadBPPResult_.seqNumber_ = sequenceNumberAsn->Asn1AsInteger();
    } else {
        TELEPHONY_LOGE("sequenceNumber tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> profileManagementOpAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_CTX_1);
    if (profileManagementOpAsn != nullptr) {
        loadBPPResult_.profileManagementOperation_ = EVENT_INSTALL;
    } else {
        TELEPHONY_LOGE("profileManagementOperation tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> addressAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_TARGET_ADDR);
    if (addressAsn != nullptr) {
        std::string hexString;
        addressAsn->Asn1AsString(hexString);
        std::string address = Asn1Utils::HexStrToString(hexString);
        loadBPPResult_.notificationAddress_ = OHOS::Telephony::ToUtf16(address);
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
    loadBPPResult_.iccId_ = OHOS::Telephony::ToUtf16(iccString);
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
        loadBPPResult_.resultCode_ = errNode->Asn1AsInteger();
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
    euicc.seq_ = nodeSeq->Asn1AsInteger();

    std::shared_ptr<Asn1Node> nodeTargetAddr = metadataNode->Asn1GetChild(TAG_ESIM_TARGET_ADDR);
    if (nodeTargetAddr == nullptr) {
        TELEPHONY_LOGE("nodeTargetAddr is nullptr");
        return;
    }
    std::vector<uint8_t> resultStr;
    nodeTargetAddr->Asn1AsBytes(resultStr);
    euicc.targetAddr_ = OHOS::Telephony::ToUtf16(Asn1Utils::BytesToString(resultStr));

    std::shared_ptr<Asn1Node> nodeEvent = metadataNode->Asn1GetChild(TAG_ESIM_EVENT);
    if (nodeEvent == nullptr) {
        TELEPHONY_LOGE("nodeEvent is nullptr");
        return;
    }
    euicc.event_ = nodeEvent->Asn1AsBits();

    std::string strmData;
    node->Asn1NodeToHexStr(strmData);
    euicc.data_ = Str8ToStr16(strmData);
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
        euiccList.euiccNotification_.push_back(euicc);
    }
    eUiccNotificationList_ = euiccList;
    return true;
}

bool EsimFile::ProcessListNotificationsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        NotifyReady(listNotificationsMutex_, isListNotificationsReady_, listNotificationsCv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(listNotificationsMutex_, isListNotificationsReady_, listNotificationsCv_);
        return false;
    }
    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(listNotificationsMutex_, isListNotificationsReady_, listNotificationsCv_,
        MSG_ESIM_LIST_NOTIFICATION, isHandleFinish);
    if (isHandleFinish) {
        return retValue;
    }
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(listNotificationsMutex_, isListNotificationsReady_, listNotificationsCv_);
        return false;
    }
    if (!ProcessListNotificationsAsn1Response(root)) {
        TELEPHONY_LOGE("ProcessListNotificationsAsn1Response error");
        NotifyReady(listNotificationsMutex_, isListNotificationsReady_, listNotificationsCv_);
        return false;
    }
    NotifyReady(listNotificationsMutex_, isListNotificationsReady_, listNotificationsCv_);
    return true;
}

EuiccNotificationList EsimFile::RetrieveNotificationList(int32_t portIndex, Event events)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.events = events;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return EuiccNotificationList();
    }
    recvCombineStr_ = "";
    AppExecFwk::InnerEvent::Pointer eventRetrieveListNotif = BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_LIST);
    if (!ProcessRetrieveNotificationList(slotId_, events, eventRetrieveListNotif)) {
        TELEPHONY_LOGE("ProcessRetrieveNotificationList encode failed");
        SyncCloseChannel();
        return EuiccNotificationList();
    }
    isRetrieveNotificationListReady_ = false;
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
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        return EuiccNotification();
    }
    recvCombineStr_ = "";
    AppExecFwk::InnerEvent::Pointer eventRetrieveNotification = BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_DONE);
    if (!ProcessRetrieveNotification(slotId_, eventRetrieveNotification)) {
        TELEPHONY_LOGE("ProcessRetrieveNotification encode failed");
        SyncCloseChannel();
        return EuiccNotification();
    }
    isRetrieveNotificationReady_ = false;
    std::unique_lock<std::mutex> lock(retrieveNotificationMutex_);
    if (!retrieveNotificationCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isRetrieveNotificationReady_; })) {
        SyncCloseChannel();
        return EuiccNotification();
    }
    SyncCloseChannel();
    return notification_;
}

int32_t EsimFile::RemoveNotificationFromList(int32_t portIndex, int32_t seqNumber)
{
    removeNotifResult_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.portIndex = portIndex;
    esimProfile_.seqNumber = seqNumber;

    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        removeNotifResult_ = static_cast<int32_t>(resultFlag);
        return removeNotifResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventRemoveNotif = BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    if (!ProcessRemoveNotification(slotId_, eventRemoveNotif)) {
        TELEPHONY_LOGE("ProcessRemoveNotification encode failed");
        SyncCloseChannel();
        return removeNotifResult_;
    }
    isRemoveNotificationReady_ = false;
    std::unique_lock<std::mutex> lock(removeNotificationMutex_);
    if (!removeNotificationCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isRemoveNotificationReady_; })) {
        SyncCloseChannel();
        return removeNotifResult_;
    }
    SyncCloseChannel();
    return removeNotifResult_;
}

bool EsimFile::ProcessRetrieveNotificationList(
    int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
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

bool EsimFile::ProcessRetrieveNotificationListDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(retrieveNotificationListMutex_, isRetrieveNotificationListReady_, retrieveNotificationListCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(retrieveNotificationListMutex_, isRetrieveNotificationListReady_, retrieveNotificationListCv_);
        return false;
    }
    if (!RetrieveNotificationParseCompTag(root)) {
        TELEPHONY_LOGE("RetrieveNotificationParseCompTag error");
        NotifyReady(retrieveNotificationListMutex_, isRetrieveNotificationListReady_, retrieveNotificationListCv_);
        return false;
    }
    NotifyReady(retrieveNotificationListMutex_, isRetrieveNotificationListReady_, retrieveNotificationListCv_);
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
    int32_t metaDataRes = compTag->Asn1GetChildren(TAG_ESIM_SEQUENCE, ls);
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
        euiccList.euiccNotification_.push_back(euicc);
    }
    eUiccNotificationList_ = euiccList;
    return true;
}

bool EsimFile::ProcessRetrieveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_RETRIEVE_NOTIFICATIONS_LIST);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    if (builder == nullptr || subBuilder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    subBuilder->Asn1AddChildAsSignedInteger(TAG_ESIM_CTX_0, esimProfile_.seqNumber);
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

bool EsimFile::ProcessRetrieveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    ResetEuiccNotification();
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        NotifyReady(retrieveNotificationMutex_, isRetrieveNotificationReady_, retrieveNotificationCv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(retrieveNotificationMutex_, isRetrieveNotificationReady_, retrieveNotificationCv_);
        return false;
    }
    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(retrieveNotificationMutex_, isRetrieveNotificationReady_,
        retrieveNotificationCv_, MSG_ESIM_RETRIEVE_NOTIFICATION_DONE, isHandleFinish);
    if (isHandleFinish) {
        return retValue;
    }
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        NotifyReady(retrieveNotificationMutex_, isRetrieveNotificationReady_, retrieveNotificationCv_);
        return false;
    }
    if (!RetrieveNotificatioParseTagCtxComp0(root)) {
        TELEPHONY_LOGE("RetrieveNotificatioParseTagCtxComp0 error");
        NotifyReady(retrieveNotificationMutex_, isRetrieveNotificationReady_, retrieveNotificationCv_);
        return false;
    }
    NotifyReady(retrieveNotificationMutex_, isRetrieveNotificationReady_, retrieveNotificationCv_);
    return true;
}

bool EsimFile::RetrieveNotificatioParseTagCtxComp0(std::shared_ptr<Asn1Node> &root)
{
    std::list<std::shared_ptr<Asn1Node>> nodes;
    std::shared_ptr<Asn1Node> compNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (compNode == nullptr) {
        TELEPHONY_LOGE("compNode is nullptr");
        return false;
    }

    int32_t ret = compNode->Asn1GetChildren(TAG_ESIM_SEQUENCE, nodes);
    if ((ret != TELEPHONY_ERR_SUCCESS) || nodes.empty()) {
        ret = compNode->Asn1GetChildren(TAG_ESIM_PROFILE_INSTALLATION_RESULT, nodes);
        if ((ret != TELEPHONY_ERR_SUCCESS) || nodes.empty()) {
            TELEPHONY_LOGE("Asn1GetChildren error");
            return false;
        }
    }

    EuiccNotification notification;
    std::shared_ptr<Asn1Node> firstNode = nodes.front();
    createNotification(firstNode, notification);
    notification_.seq_ = notification.seq_;
    notification_.targetAddr_ = notification.targetAddr_;
    notification_.event_ = notification.event_;
    notification_.data_ = notification.data_;
    return true;
}

bool EsimFile::ProcessRemoveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_REMOVE_NOTIFICATION_FROM_LIST);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    builder->Asn1AddChildAsSignedInteger(TAG_ESIM_CTX_0, esimProfile_.seqNumber);
    ApduSimIORequestInfo reqInfo;
    CommBuildOneApduReqInfo(reqInfo, builder);
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr");
        return false;
    }
    int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
    if (apduResult == TELEPHONY_ERR_FAIL) {
        return false;
    }
    return true;
}

bool EsimFile::ProcessRemoveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        NotifyReady(removeNotificationMutex_, isRemoveNotificationReady_, removeNotificationCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(removeNotificationMutex_, isRemoveNotificationReady_, removeNotificationCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (node == nullptr) {
        TELEPHONY_LOGE("node is nullptr");
        NotifyReady(removeNotificationMutex_, isRemoveNotificationReady_, removeNotificationCv_);
        return false;
    }
    removeNotifResult_ = node->Asn1AsInteger();
    NotifyReady(removeNotificationMutex_, isRemoveNotificationReady_, removeNotificationCv_);
    return true;
}

int32_t EsimFile::DeleteProfile(const std::u16string &iccId)
{
    delProfile_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.iccId = iccId;

    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        delProfile_ = static_cast<int32_t>(resultFlag);
        return delProfile_;
    }
    AppExecFwk::InnerEvent::Pointer eventDeleteProfile = BuildCallerInfo(MSG_ESIM_DELETE_PROFILE);
    if (!ProcessDeleteProfile(slotId_, eventDeleteProfile)) {
        TELEPHONY_LOGE("ProcessDeleteProfile encode failed");
        SyncCloseChannel();
        return delProfile_;
    }
    isDeleteProfileReady_ = false;
    std::unique_lock<std::mutex> lock(deleteProfileMutex_);
    if (!deleteProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isDeleteProfileReady_; })) {
        SyncCloseChannel();
        return delProfile_;
    }
    SyncCloseChannel();
    return delProfile_;
}

int32_t EsimFile::SwitchToProfile(int32_t portIndex, const std::u16string &iccId, bool forceDisableProfile)
{
    switchResult_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    esimProfile_.forceDisableProfile = forceDisableProfile;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        switchResult_ = static_cast<int32_t>(resultFlag);
        return switchResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventSwitchToProfile = BuildCallerInfo(MSG_ESIM_SWITCH_PROFILE);
    if (!ProcessSwitchToProfile(slotId_, eventSwitchToProfile)) {
        TELEPHONY_LOGE("ProcessSwitchToProfile encode failed");
        SyncCloseChannel();
        return switchResult_;
    }
    isSwitchToProfileReady_ = false;
    std::unique_lock<std::mutex> lock(switchToProfileMutex_);
    if (!switchToProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSwitchToProfileReady_; })) {
        SyncCloseChannel();
        return switchResult_;
    }
    SyncCloseChannel();
    return switchResult_;
}

int32_t EsimFile::SetProfileNickname(const std::u16string &iccId, const std::u16string &nickname)
{
    setNicknameResult_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DEFALUT_ERROR);
    esimProfile_.iccId = iccId;
    esimProfile_.nickname = nickname;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        setNicknameResult_ = static_cast<int32_t>(resultFlag);
        return setNicknameResult_;
    }
    AppExecFwk::InnerEvent::Pointer eventSetNickName = BuildCallerInfo(MSG_ESIM_SET_NICK_NAME);
    if (!ProcessSetNickname(slotId_, eventSetNickName)) {
        TELEPHONY_LOGE("ProcessSetNickname encode failed");
        SyncCloseChannel();
        return setNicknameResult_;
    }
    isSetNicknameReady_ = false;
    std::unique_lock<std::mutex> lock(setNicknameMutex_);
    if (!setNicknameCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSetNicknameReady_; })) {
        SyncCloseChannel();
        return setNicknameResult_;
    }
    SyncCloseChannel();
    return setNicknameResult_;
}

bool EsimFile::ProcessDeleteProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_DELETE_PROFILE);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string strIccId = OHOS::Telephony::ToUtf8(esimProfile_.iccId);
    Asn1Utils::BcdToBytes(strIccId, iccidBytes);
    builder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.size());
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

bool EsimFile::ProcessSetNickname(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_SET_NICKNAME);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string strIccId = OHOS::Telephony::ToUtf8(esimProfile_.iccId);
    std::string childStr = OHOS::Telephony::ToUtf8(esimProfile_.nickname);
    Asn1Utils::BcdToBytes(strIccId, iccidBytes);

    builder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.size());
    builder->Asn1AddChildAsString(TAG_ESIM_NICKNAME, childStr);
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

bool EsimFile::ProcessDeleteProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(deleteProfileMutex_, isDeleteProfileReady_, deleteProfileCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> Asn1NodeData = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (Asn1NodeData == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        NotifyReady(deleteProfileMutex_, isDeleteProfileReady_, deleteProfileCv_);
        return false;
    }
    delProfile_ = Asn1NodeData->Asn1AsInteger();
    NotifyReady(deleteProfileMutex_, isDeleteProfileReady_, deleteProfileCv_);
    return true;
}

bool EsimFile::ProcessSwitchToProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_ENABLE_PROFILE);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    if (builder == nullptr || subBuilder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string strIccId = OHOS::Telephony::ToUtf8(esimProfile_.iccId);
    Asn1Utils::BcdToBytes(strIccId, iccidBytes);
    subBuilder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.size());
    std::shared_ptr<Asn1Node> subNode = subBuilder->Asn1Build();
    if (subNode == nullptr) {
        TELEPHONY_LOGE("subNode is nullptr");
        return false;
    }
    builder->Asn1AddChild(subNode);
    builder->Asn1AddChildAsBoolean(TAG_ESIM_CTX_1, true);
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

bool EsimFile::ProcessSwitchToProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(switchToProfileMutex_, isSwitchToProfileReady_, switchToProfileCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> asn1NodeData = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (asn1NodeData == nullptr) {
        TELEPHONY_LOGE("asn1NodeData is nullptr");
        NotifyReady(switchToProfileMutex_, isSwitchToProfileReady_, switchToProfileCv_);
        return false;
    }
    switchResult_ = asn1NodeData->Asn1AsInteger();
    NotifyReady(switchToProfileMutex_, isSwitchToProfileReady_, switchToProfileCv_);
    return true;
}

bool EsimFile::ProcessSetNicknameDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(setNicknameMutex_, isSetNicknameReady_, setNicknameCv_);
        return false;
    }
    std::shared_ptr<Asn1Node> asn1NodeData = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (asn1NodeData == nullptr) {
        TELEPHONY_LOGE("asn1NodeData is nullptr");
        NotifyReady(setNicknameMutex_, isSetNicknameReady_, setNicknameCv_);
        return false;
    }
    setNicknameResult_ = asn1NodeData->Asn1AsInteger();
    NotifyReady(setNicknameMutex_, isSetNicknameReady_, setNicknameCv_);
    return true;
}

EuiccInfo2 EsimFile::ObtainEuiccInfo2(int32_t portIndex)
{
    euiccInfo2Result_ = EuiccInfo2();
    esimProfile_.portIndex = portIndex;

    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        euiccInfo2Result_.resultCode_ = static_cast<int32_t>(resultFlag);
        return euiccInfo2Result_;
    }
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo2 = BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO2_DONE);
    recvCombineStr_ = "";
    if (!ProcessObtainEuiccInfo2(slotId_, eventEUICCInfo2)) {
        TELEPHONY_LOGE("ProcessObtainEuiccInfo2 encode failed");
        SyncCloseChannel();
        euiccInfo2Result_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return euiccInfo2Result_;
    }
    isEuiccInfo2Ready_ = false;
    std::unique_lock<std::mutex> lock(euiccInfo2Mutex_);
    if (!euiccInfo2Cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isEuiccInfo2Ready_; })) {
        SyncCloseChannel();
        euiccInfo2Result_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_WAIT_TIMEOUT);
        return euiccInfo2Result_;
    }
    SyncCloseChannel();
    return euiccInfo2Result_;
}

ResponseEsimInnerResult EsimFile::AuthenticateServer(const AuthenticateConfigInfo &authenticateConfigInfo)
{
    responseAuthenticateResult_ = ResponseEsimInnerResult();
    esimProfile_.portIndex = authenticateConfigInfo.portIndex_;
    esimProfile_.matchingId = authenticateConfigInfo.matchingId_;
    esimProfile_.serverSigned1 = authenticateConfigInfo.serverSigned1_;
    esimProfile_.serverSignature1 = authenticateConfigInfo.serverSignature1_;
    esimProfile_.euiccCiPkIdToBeUsed = authenticateConfigInfo.euiccCiPkIdToBeUsed_;
    esimProfile_.serverCertificate = authenticateConfigInfo.serverCertificate_;

    std::u16string imei = u"";
    CoreManagerInner::GetInstance().GetImei(slotId_, imei);
    esimProfile_.imei = imei;
    ResultInnerCode resultFlag = ObtainChannelSuccessExclusive();
    if (resultFlag != ResultInnerCode::RESULT_EUICC_CARD_OK) {
        TELEPHONY_LOGE("ObtainChannelSuccessExclusive failed ,%{public}d", resultFlag);
        responseAuthenticateResult_.resultCode_ = static_cast<int32_t>(resultFlag);
        return responseAuthenticateResult_;
    }
    recvCombineStr_ = "";
    if (!ProcessAuthenticateServer(slotId_)) {
        TELEPHONY_LOGE("ProcessAuthenticateServer encode failed");
        SyncCloseChannel();
        responseAuthenticateResult_.resultCode_ =
            static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_DATA_PROCESS_ERROR);
        return responseAuthenticateResult_;
    }
    SyncCloseChannel();
    return responseAuthenticateResult_;
}

bool EsimFile::ProcessObtainEuiccInfo2(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EUICC_INFO_2);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::string hexStr;
    uint32_t strLen = builder->Asn1BuilderToHexStr(hexStr);
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

void EsimFile::ResetEuiccNotification()
{
    notification_.seq_ = 0;
    notification_.targetAddr_ = u"";
    notification_.event_ = 0;
    notification_.data_ = u"";
}

void EsimFile::ConvertAuthInputParaFromApiStru(Es9PlusInitAuthResp &dst, EsimProfile &src)
{
    dst.serverSigned1 = OHOS::Telephony::ToUtf8(src.serverSigned1);
    dst.serverSignature1 = OHOS::Telephony::ToUtf8(src.serverSignature1);
    dst.euiccCiPKIdToBeUsed = OHOS::Telephony::ToUtf8(src.euiccCiPkIdToBeUsed);
    dst.serverCertificate = OHOS::Telephony::ToUtf8(src.serverCertificate);
    dst.matchingId = OHOS::Telephony::ToUtf8(src.matchingId);
    dst.imei = OHOS::Telephony::ToUtf8(src.imei);
}

bool EsimFile::ProcessAuthenticateServer(int32_t slotId)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    Es9PlusInitAuthResp authRespData;
    ConvertAuthInputParaFromApiStru(authRespData, esimProfile_);
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_AUTHENTICATE_SERVER);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder create failed");
        return false;
    }
    Asn1AddChildAsBase64(builder, authRespData.serverSigned1);
    Asn1AddChildAsBase64(builder, authRespData.serverSignature1);
    Asn1AddChildAsBase64(builder, authRespData.euiccCiPKIdToBeUsed);
    Asn1AddChildAsBase64(builder, authRespData.serverCertificate);
    std::shared_ptr<Asn1Builder> ctxParams1Builder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    AddCtxParams1(ctxParams1Builder, authRespData);
    if (ctxParams1Builder == nullptr) {
        TELEPHONY_LOGE("AddCtxParams1 failed");
        return false;
    }
    std::shared_ptr<Asn1Node> ctxNode = ctxParams1Builder->Asn1Build();
    if (ctxNode == nullptr) {
        TELEPHONY_LOGE("ctxNode is nullptr");
        return false;
    }
    builder->Asn1AddChild(ctxNode);
    std::string hexStr;
    uint32_t hexStrLen = builder->Asn1BuilderToHexStr(hexStr);
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    SplitSendLongData(codec, MSG_ESIM_AUTHENTICATE_SERVER,
        authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
    return true;
}

void EsimFile::AddDeviceCapability(std::shared_ptr<Asn1Builder> &devCapsBuilder)
{
    std::vector<uint8_t> versionBytes;
    Asn1Utils::UintToBytes(VERSION_NUMBER, versionBytes);
    versionBytes.push_back(0);
    versionBytes.push_back(0);
    devCapsBuilder->Asn1AddChildAsBytes(TAG_ESIM_CTX_0, versionBytes, versionBytes.size());
    devCapsBuilder->Asn1AddChildAsBytes(TAG_ESIM_CTX_1, versionBytes, versionBytes.size());
    devCapsBuilder->Asn1AddChildAsBytes(TAG_ESIM_CTX_5, versionBytes, versionBytes.size());
}

void EsimFile::GetImeiBytes(std::vector<uint8_t> &imeiBytes, const std::string &imei)
{
    size_t imeiLen = imei.length();
    if (imeiLen < AUTH_SERVER_IMEI_LEN * BYTE_TO_HEX_LEN - 1) {
        return;
    }
    if (imeiLen != AUTH_SERVER_IMEI_LEN * BYTE_TO_HEX_LEN) {
        std::string newImei = imei;
        newImei += 'F';
        Asn1Utils::BcdToBytes(newImei, imeiBytes);
        unsigned char last = imeiBytes[LAST_BYTE_OF_IMEI];
        imeiBytes[LAST_BYTE_OF_IMEI] = static_cast<unsigned char>((last & 0xFF) <<
            OFFSET_FOUR_BIT | ((last & 0xFF) >> OFFSET_FOUR_BIT));
    } else {
        Asn1Utils::BcdToBytes(imei, imeiBytes);
    }
}

void EsimFile::AddCtxParams1(std::shared_ptr<Asn1Builder> &ctxParams1Builder, Es9PlusInitAuthResp &authRespData)
{
    if (ctxParams1Builder == nullptr) {
        return;
    }
    ctxParams1Builder->Asn1AddChildAsString(TAG_ESIM_CTX_0, authRespData.matchingId);
    std::shared_ptr<Asn1Node> subNode = nullptr;
    std::vector<uint8_t> tmpBytes;
    std::vector<uint8_t> imeiBytes;
    Asn1Utils::BcdToBytes(authRespData.imei, tmpBytes);
    if (tmpBytes.size() < AUTH_SERVER_TAC_LEN) {
        TELEPHONY_LOGE("tmpBytes.size is small than AUTH_SERVER_TAC_LEN");
        return;
    }
    std::vector<uint8_t> tacBytes(tmpBytes.begin(), tmpBytes.begin() + AUTH_SERVER_TAC_LEN);
    GetImeiBytes(imeiBytes, authRespData.imei);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_1);
    if (subBuilder == nullptr) {
        TELEPHONY_LOGE("AddCtxParams1 subBuilder is nullptr");
        return;
    }
    subBuilder->Asn1AddChildAsBytes(TAG_ESIM_CTX_0, tacBytes, tacBytes.size());
    // add devCap
    std::shared_ptr<Asn1Builder> devCapsBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_1);
    if (devCapsBuilder == nullptr) {
        TELEPHONY_LOGE("AddCtxParams1 devCapsBuilder is nullptr");
        return;
    }
    AddDeviceCapability(devCapsBuilder);
    std::shared_ptr<Asn1Node> devCapNode = devCapsBuilder->Asn1Build();
    if (devCapNode == nullptr) {
        TELEPHONY_LOGE("devCapNode is nullptr");
        return;
    }
    subBuilder->Asn1AddChild(devCapNode);
    subBuilder->Asn1AddChildAsBytes(TAG_ESIM_CTX_2, imeiBytes, imeiBytes.size());
    subNode = subBuilder->Asn1Build();
    ctxParams1Builder->Asn1AddChild(subNode);
}

bool EsimFile::ProcessObtainEuiccInfo2Done(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        NotifyReady(euiccInfo2Mutex_, isEuiccInfo2Ready_, euiccInfo2Cv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(euiccInfo2Mutex_, isEuiccInfo2Ready_, euiccInfo2Cv_);
        return false;
    }
    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(euiccInfo2Mutex_, isEuiccInfo2Ready_, euiccInfo2Cv_,
        MSG_ESIM_OBTAIN_EUICC_INFO2_DONE, isHandleFinish);
    if (isHandleFinish) {
        return retValue;
    }
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(euiccInfo2Mutex_, isEuiccInfo2Ready_, euiccInfo2Cv_);
        return false;
    }
    this->EuiccInfo2ParseProfileVersion(euiccInfo2Result_, root);
    this->EuiccInfo2ParseSvn(euiccInfo2Result_, root);
    this->EuiccInfo2ParseEuiccFirmwareVer(euiccInfo2Result_, root);
    this->EuiccInfo2ParseExtCardResource(euiccInfo2Result_, root);
    this->EuiccInfo2ParseUiccCapability(euiccInfo2Result_, root);
    this->EuiccInfo2ParseTs102241Version(euiccInfo2Result_, root);
    this->EuiccInfo2ParseGlobalPlatformVersion(euiccInfo2Result_, root);
    this->EuiccInfo2ParseRspCapability(euiccInfo2Result_, root);
    this->EuiccInfo2ParseEuiccCiPKIdListForVerification(euiccInfo2Result_, root);
    this->EuiccInfo2ParseEuiccCiPKIdListForSigning(euiccInfo2Result_, root);
    this->EuiccInfo2ParseEuiccCategory(euiccInfo2Result_, root);
    this->EuiccInfo2ParsePpVersion(euiccInfo2Result_, root);
    euiccInfo2Result_.resultCode_ = static_cast<int32_t>(ResultInnerCode::RESULT_EUICC_CARD_OK);
    euiccInfo2Result_.response_ = newRecvData_.resultData;
    NotifyReady(euiccInfo2Mutex_, isEuiccInfo2Ready_, euiccInfo2Cv_);
    return true;
}

void EsimFile::EuiccInfo2ParseProfileVersion(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> profileVerNode = root->Asn1GetChild(TAG_ESIM_CTX_1);
    if (profileVerNode == nullptr) {
        TELEPHONY_LOGE("profileVerNode is nullptr");
        return;
    }
    std::vector<uint8_t> profileVersionRaw = {};
    uint32_t profileVersionRawLen = profileVerNode->Asn1AsBytes(profileVersionRaw);
    if (profileVersionRawLen < EUICC_INFO_VERSION_MIN_LENGTH) {
        TELEPHONY_LOGE("invalid profileVersion data");
        return;
    }
    euiccInfo2.profileVersion_ = MakeVersionString(profileVersionRaw);
}

void EsimFile::EuiccInfo2ParseSvn(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> svnNode = root->Asn1GetChild(TAG_ESIM_CTX_2);
    if (svnNode == nullptr) {
        TELEPHONY_LOGE("svnNode is nullptr");
        return;
    }
    std::vector<uint8_t> svnRaw = {};
    uint32_t svnRawLen = svnNode->Asn1AsBytes(svnRaw);
    if (svnRawLen < EUICC_INFO_VERSION_MIN_LENGTH) {
        TELEPHONY_LOGE("invalid SVN data");
        return;
    }
    euiccInfo2.svn_ = MakeVersionString(svnRaw);
}

void EsimFile::EuiccInfo2ParseEuiccFirmwareVer(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> euiccFirmwareVerNode = root->Asn1GetChild(TAG_ESIM_CTX_3);
    if (euiccFirmwareVerNode == nullptr) {
        TELEPHONY_LOGE("euiccFirmwareVerNode is nullptr");
        return;
    }
    std::vector<uint8_t> euiccFirmwareVerRaw = {};
    uint32_t versionLen = euiccFirmwareVerNode->Asn1AsBytes(euiccFirmwareVerRaw);
    if (versionLen < EUICC_INFO_VERSION_MIN_LENGTH) {
        TELEPHONY_LOGE("invalid firmwareVer data");
        return;
    }
    euiccInfo2.firmwareVer_ = MakeVersionString(euiccFirmwareVerRaw);
}

void EsimFile::EuiccInfo2ParseExtCardResource(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> extCardResourceNode = root->Asn1GetChild(TAG_ESIM_CTX_4);
    if (extCardResourceNode == nullptr) {
        TELEPHONY_LOGE("extCardResourceNode is nullptr");
        return;
    }
    extCardResourceNode->Asn1AsString(euiccInfo2.extCardResource_);
}

void EsimFile::EuiccInfo2ParseUiccCapability(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> uiccCapabilityNode = root->Asn1GetChild(TAG_ESIM_CTX_5);
    if (uiccCapabilityNode == nullptr) {
        TELEPHONY_LOGE("uiccCapabilityNode is nullptr");
        return;
    }
    uiccCapabilityNode->Asn1AsString(euiccInfo2.uiccCapability_);
}

void EsimFile::EuiccInfo2ParseTs102241Version(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> ts102241VersionNode = root->Asn1GetChild(TAG_ESIM_CTX_6);
    if (ts102241VersionNode == nullptr) {
        TELEPHONY_LOGE("ts102241VersionNode is nullptr");
        return;
    }
    std::vector<uint8_t> ts102241VersionRaw = {};
    uint32_t versionLen = ts102241VersionNode->Asn1AsBytes(ts102241VersionRaw);
    if (versionLen < EUICC_INFO_VERSION_MIN_LENGTH) {
        TELEPHONY_LOGE("invalid ts102241VersionNode data");
        return;
    }
    euiccInfo2.ts102241Version_ = MakeVersionString(ts102241VersionRaw);
}

void EsimFile::EuiccInfo2ParseGlobalPlatformVersion(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> globalPlatformVersionNode = root->Asn1GetChild(TAG_ESIM_CTX_7);
    if (globalPlatformVersionNode == nullptr) {
        TELEPHONY_LOGE("globalPlatformVersionNode is nullptr");
        return;
    }
    std::vector<uint8_t> globalPlatformVersionRaw = {};
    uint32_t versionLen = globalPlatformVersionNode->Asn1AsBytes(globalPlatformVersionRaw);
    if (versionLen < EUICC_INFO_VERSION_MIN_LENGTH) {
        TELEPHONY_LOGE("invalid globalplatformVersionRaw data");
        return;
    }
    euiccInfo2.globalPlatformVersion_ = MakeVersionString(globalPlatformVersionRaw);
}

void EsimFile::EuiccInfo2ParseRspCapability(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> rspCapabilityNode = root->Asn1GetChild(TAG_ESIM_CTX_8);
    if (rspCapabilityNode == nullptr) {
        TELEPHONY_LOGE("rspCapabilityNode is nullptr");
        return;
    }
    rspCapabilityNode->Asn1AsString(euiccInfo2.rspCapability_);
}

void EsimFile::EuiccInfo2ParseEuiccCiPKIdListForVerification(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> ciPKIdListForVerificationNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_9);
    if (ciPKIdListForVerificationNode == nullptr) {
        TELEPHONY_LOGE("ciPKIdListForVerificationNode is nullptr");
        return;
    }
    ciPKIdListForVerificationNode->Asn1NodeToHexStr(euiccInfo2.euiccCiPKIdListForVerification_);
}

void EsimFile::EuiccInfo2ParseEuiccCiPKIdListForSigning(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> euiccCiPKIdListForSigningNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_A);
    if (euiccCiPKIdListForSigningNode == nullptr) {
        TELEPHONY_LOGE("euiccCiPKIdListForSigningNode is nullptr");
        return;
    }
    euiccCiPKIdListForSigningNode->Asn1NodeToHexStr(euiccInfo2.euiccCiPKIdListForSigning_);
}

void EsimFile::EuiccInfo2ParseEuiccCategory(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> euiccCategoryNode = root->Asn1GetChild(TAG_ESIM_CTX_B);
    if (euiccCategoryNode == nullptr) {
        TELEPHONY_LOGE("euiccCategoryNode is nullptr");
        return;
    }
    euiccInfo2.euiccCategory_ = euiccCategoryNode->Asn1AsInteger();
}

void EsimFile::EuiccInfo2ParsePpVersion(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> ppVersionNode = root->Asn1GetChild(TAG_ESIM_OCTET_STRING_TYPE);
    if (ppVersionNode == nullptr) {
        TELEPHONY_LOGE("ppVersionNode is nullptr");
        return;
    }
    std::vector<uint8_t> ppVersionNodeRaw = {};
    uint32_t versionLen = ppVersionNode->Asn1AsBytes(ppVersionNodeRaw);
    if (versionLen < EUICC_INFO_VERSION_MIN_LENGTH) {
        TELEPHONY_LOGE("invalid ppVersion data");
        return;
    }
    euiccInfo2.ppVersion_ = MakeVersionString(ppVersionNodeRaw);
}

bool EsimFile::RealProcessAuthenticateServerDone()
{
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    std::shared_ptr<Asn1Node> responseNode = Asn1ParseResponse(responseByte, responseByte.size());
    if (responseNode == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
        return false;
    }
    AuthServerResponse authServerResp = { 0 };
    if (responseNode->Asn1HasChild(TAG_ESIM_CTX_COMP_1)) {
        std::shared_ptr<Asn1Node> authServerRespNode = responseNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
        if (authServerRespNode == nullptr) {
            TELEPHONY_LOGE("authServerRespNode is nullptr");
            NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
            return false;
        }
        if (authServerRespNode->Asn1HasChild(TAG_ESIM_CTX_0) &&
            authServerRespNode->Asn1HasChild(TAG_ESIM_INTEGER_TYPE)) {
            std::shared_ptr<Asn1Node> transactionIdNode = authServerRespNode->Asn1GetChild(TAG_ESIM_CTX_0);
            std::shared_ptr<Asn1Node> errCodeNode = authServerRespNode->Asn1GetChild(TAG_ESIM_INTEGER_TYPE);
            if (transactionIdNode == nullptr || errCodeNode == nullptr) {
                TELEPHONY_LOGE("authServerRespNode failed");
                NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
                return false;
            }
            uint32_t tidByteLen = transactionIdNode->Asn1AsString(authServerResp.transactionId);
            if (tidByteLen == 0) {
                TELEPHONY_LOGE("tidByteLen is zero.");
                NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
                return false;
            }
            authServerResp.errCode = errCodeNode->Asn1AsInteger();
        } else {
            TELEPHONY_LOGE("the auth server response has no right child");
            NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
            return false;
        }
    } else {
        authServerResp.respStr = responseByte;
        authServerResp.respLength = responseByte.size();
    }
    CovertAuthToApiStruct(responseAuthenticateResult_, authServerResp);
    NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
    return true;
}

bool EsimFile::ProcessAuthenticateServerDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        NotifyReady(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_);
        return false;
    }
    newRecvData_ = rcvMsg->fileData;
    bool isHandleFinish = false;
    bool retValue = CommMergeRecvData(authenticateServerMutex_, isAuthenticateServerReady_, authenticateServerCv_,
        MSG_ESIM_AUTHENTICATE_SERVER, isHandleFinish);
    if (isHandleFinish) {
        return retValue;
    }
    return RealProcessAuthenticateServerDone();
}

void EsimFile::CovertAuthToApiStruct(ResponseEsimInnerResult &dst, AuthServerResponse &src)
{
    dst.resultCode_ = src.errCode;
    std::string hexStr = Asn1Utils::BytesToHexStr(src.respStr);
    dst.response_ = OHOS::Telephony::ToUtf16(hexStr);
}

void EsimFile::NotifyReady(std::mutex &mtx, bool &flag, std::condition_variable &cv)
{
    std::lock_guard<std::mutex> lock(mtx);
    flag = true;
    cv.notify_all();
}

bool EsimFile::CommMergeRecvData(
    std::mutex &mtx, bool &flag, std::condition_variable &cv, int32_t eventId, bool &isHandleFinish)
{
    uint32_t mergeResult = MergeRecvLongDataComplete(newRecvData_, eventId);
    if (mergeResult == RESPONS_DATA_ERROR) {
        NotifyReady(mtx, flag, cv);
        isHandleFinish = true;
        return false;
    }
    if ((mergeResult == RESPONS_DATA_FINISH) && (newRecvData_.resultData.length() == 0)) {
        NotifyReady(mtx, flag, cv);
        isHandleFinish = true;
        return true;
    }
    if (mergeResult == RESPONS_DATA_NOT_FINISH) {
        isHandleFinish = true;
        return true;
    }
    isHandleFinish = false;
    return false;
}

void EsimFile::InitChanneMemberFunc()
{
    memberFuncMap_[MSG_ESIM_OPEN_CHANNEL_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEsimOpenChannelDone(event); };
    memberFuncMap_[MSG_ESIM_CLOSE_CHANNEL_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEsimCloseChannelDone(event); };
    memberFuncMap_[MSG_ESIM_SEND_APUD_DATA] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSendApduDataDone(event); };
    memberFuncMap_[MSG_ESIM_CLOSE_SPARE_CHANNEL_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEsimCloseSpareChannelDone(event); };
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_OBTAIN_EID_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEidDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEuiccInfo1Done(event); };
    memberFuncMap_[MSG_ESIM_REQUEST_ALL_PROFILES] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRequestAllProfilesDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEuiccChallengeDone(event); };
    memberFuncMap_[MSG_ESIM_REQUEST_RULES_AUTH_TABLE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRequestRulesAuthTableDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_SMDS_ADDRESS] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainSmdsAddressDone(event); };
    memberFuncMap_[MSG_ESIM_DISABLE_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessDisableProfileDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainDefaultSmdpAddressDone(event); };
    memberFuncMap_[MSG_ESIM_CANCEL_SESSION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessCancelSessionDone(event); };
    memberFuncMap_[MSG_ESIM_GET_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetProfileDone(event); };
    memberFuncMap_[MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEstablishDefaultSmdpAddressDone(event); };
    memberFuncMap_[MSG_ESIM_RESET_MEMORY] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessResetMemoryDone(event); };
    memberFuncMap_[MSG_ESIM_LIST_NOTIFICATION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessListNotificationsDone(event); };
    memberFuncMap_[MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessLoadBoundProfilePackageDone(event); };
    memberFuncMap_[MSG_ESIM_PREPARE_DOWNLOAD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessPrepareDownloadDone(event); };
    memberFuncMap_[MSG_ESIM_REMOVE_NOTIFICATION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRemoveNotificationDone(event); };
    memberFuncMap_[MSG_ESIM_RETRIEVE_NOTIFICATION_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRetrieveNotificationDone(event); };
    memberFuncMap_[MSG_ESIM_RETRIEVE_NOTIFICATION_LIST] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRetrieveNotificationListDone(event); };
    memberFuncMap_[MSG_ESIM_DELETE_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessDeleteProfileDone(event); };
    memberFuncMap_[MSG_ESIM_SWITCH_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSwitchToProfileDone(event); };
    memberFuncMap_[MSG_ESIM_SET_NICK_NAME] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSetNicknameDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_EUICC_INFO2_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEuiccInfo2Done(event); };
    memberFuncMap_[MSG_ESIM_AUTHENTICATE_SERVER] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessAuthenticateServerDone(event); };
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
            return;
        }
    } else {
        IccFile::ProcessEvent(event);
    }
}

bool EsimFile::GetRawDataFromEvent(const AppExecFwk::InnerEvent::Pointer &event, IccFileData &outRawData)
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
    outRawData = rcvMsg->fileData;
    return true;
}

std::shared_ptr<Asn1Node> EsimFile::ParseEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    IccFileData rawData;
    if (!GetRawDataFromEvent(event, rawData)) {
        TELEPHONY_LOGE("rawData is nullptr within rcvMsg");
        return nullptr;
    }
    TELEPHONY_LOGI("input raw data:sw1=%{public}02X, sw2=%{public}02X, length=%{public}zu",
        rawData.sw1, rawData.sw2, rawData.resultData.length());
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(rawData.resultData);
    uint32_t byteLen = responseByte.size();
    return Asn1ParseResponse(responseByte, byteLen);
}

int32_t EsimFile::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
{
    return 0;
}

bool EsimFile::IsSameAid(const std::u16string &aid)
{
    std::lock_guard<std::mutex> lock(occupyChannelMutex_);
    if (aidStr_ == aid) {
        return true;
    } else {
        return false;
    }
}

bool EsimFile::IsValidAidForAllowSameAidReuseChannel(const std::u16string &aid)
{
    if (aidStr_ != aid && !aidStr_.empty()) {
        return false;
    } else {
        return true;
    }
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

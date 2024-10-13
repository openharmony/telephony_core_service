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
}

void EsimFile::StartLoad() {}

void EsimFile::SyncOpenChannel()
{
    uint32_t tryCnt = 0;
    while (!IsLogicChannelOpen()) {
        ProcessEsimOpenChannel(OHOS::Telephony::ToUtf16(ISDR_AID));
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
    if (!ProcessObtainEid(slotId_, eventGetEid)) {
        TELEPHONY_LOGE("ProcessObtainEid encode failed");
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

GetEuiccProfileInfoListResult EsimFile::GetEuiccProfileInfoList()
{
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRequestAllProfiles = BuildCallerInfo(MSG_ESIM_REQUEST_ALL_PROFILES);
    if (!ProcessRequestAllProfiles(slotId_, eventRequestAllProfiles)) {
        TELEPHONY_LOGE("ProcessRequestAllProfiles encode failed");
        return GetEuiccProfileInfoListResult();
    }
    isAllProfileInfoReady_ = false;
    std::unique_lock<std::mutex> lock(allProfileInfoMutex_);
    if (!allProfileInfoCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isAllProfileInfoReady_; })) {
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
    isEuiccInfo1Ready_ = false;
    std::unique_lock<std::mutex> lock(euiccInfo1Mutex_);
    if (!euiccInfo1Cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isEuiccInfo1Ready_; })) {
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
    requestInfo->serial = nextSerialId_;
    nextSerialId_++;
    if (nextSerialId_ >= INT32_MAX) {
        nextSerialId_ = 0;
    }
    requestInfo->channelId = apduCommand->channel;
    requestInfo->type = apduCommand->data.cla;
    requestInfo->instruction = apduCommand->data.ins;
    requestInfo->p1 = apduCommand->data.p1;
    requestInfo->p2 = apduCommand->data.p2;
    requestInfo->p3 = apduCommand->data.p3;
    requestInfo->data = apduCommand->data.cmdHex;
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
        TELEPHONY_LOGE("hexStrLen is zero!");
        return;
    }
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> lst = codec.GetCommands();
    std::unique_ptr<ApduCommand> apduCommand = std::move(lst.front());
    CopyApdCmdToReqInfo(&requestInfo, apduCommand.get());
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
    telRilManager_->SimCloseLogicalChannel(slotId_, currentChannelId_, response);
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

std::string EsimFile::MakeVersionString(std::vector<uint8_t> &versionRaw)
{
    if (versionRaw.size() < BYTE_NUM3) {
        TELEPHONY_LOGE("versionRaw.size error!");
        return "";
    }
    std::ostringstream oss;
    oss << std::hex << static_cast<unsigned char>(versionRaw[VERSION_HIGH]) << "." <<
        static_cast<unsigned char>(versionRaw[VERSION_MIDDLE]) << "." <<
        static_cast<unsigned char>(versionRaw[VERSION_LOW]);
    return oss.str();
}

bool EsimFile::ProcessObtainEidDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_EID);
    if (profileRoot == nullptr) {
        return false;
    }
    std::vector<uint8_t> outPutBytes;
    uint32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero!");
        return false;
    }
    std::string strResult = Asn1Utils::BytesToHexStr(outPutBytes);
    {
        std::lock_guard<std::mutex> lock(getEidMutex_);
        eid_ = strResult;
        isEidReady_ = true;
    }
    getEidCv_.notify_one();
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
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    if (!ObtainEuiccInfo1ParseTagCtx2(root)) {
        TELEPHONY_LOGE("ObtainEuiccInfo1ParseTagCtx2 error!");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    eUiccInfo_.response = Str8ToStr16(result->resultData);
    {
        std::lock_guard<std::mutex> lock(euiccInfo1Mutex_);
        isEuiccInfo1Ready_ = true;
    }
    euiccInfo1Cv_.notify_one();
    return true;
}

bool EsimFile::ObtainEuiccInfo1ParseTagCtx2(std::shared_ptr<Asn1Node> &root)
{
    EuiccInfo1 euiccInfo1;
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
    eUiccInfo_.osVersion = OHOS::Telephony::ToUtf16(MakeVersionString(svnRaw));
    return true;
}

bool EsimFile::ProcessRequestAllProfilesDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }

    if (!RequestAllProfilesParseProfileInfo(root)) {
        TELEPHONY_LOGE("RequestAllProfilesParseProfileInfo error!");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(allProfileInfoMutex_);
        isAllProfileInfoReady_ = true;
    }
    allProfileInfoCv_.notify_one();
    return true;
}

bool EsimFile::RequestAllProfilesParseProfileInfo(std::shared_ptr<Asn1Node> &root)
{
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr");
        return false;
    }
    std::list<std::shared_ptr<Asn1Node>> profileNodes;
    profileRoot->Asn1GetChildren(TAG_ESIM_PROFILE_INFO, profileNodes);
    std::shared_ptr<Asn1Node> curNode = nullptr;
    EuiccProfileInfo euiccProfileInfo = {{0}};
    for (auto it = profileNodes.begin(); it != profileNodes.end(); ++it) {
        curNode = *it;
        if (!curNode->Asn1HasChild(TAG_ESIM_ICCID)) {
            TELEPHONY_LOGE("Profile must have an ICCID.");
            continue;
        }
        BuildBasicProfileInfo(&euiccProfileInfo, curNode);
        EuiccProfile euiccProfile;
        ConvertProfileInfoToApiStruct(euiccProfile, euiccProfileInfo);
        euiccProfileInfoList_.profiles.push_back(euiccProfile);
    }
    euiccProfileInfoList_.result = ResultState::RESULT_OK;
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
    mcc = mMcc;
    mnc = mMnc;
    return true;
}

void EsimFile::ConvertProfileInfoToApiStruct(EuiccProfile &dst, EuiccProfileInfo &src)
{
    dst.iccId = OHOS::Telephony::ToUtf16(src.iccid);
    dst.nickName = OHOS::Telephony::ToUtf16(src.nickname);
    dst.serviceProviderName = OHOS::Telephony::ToUtf16(src.serviceProviderName);
    dst.profileName = OHOS::Telephony::ToUtf16(src.profileName);
    dst.state = static_cast<ProfileState>(src.profileState);
    dst.profileClass = static_cast<ProfileClass>(src.profileClass);
    dst.policyRules = static_cast<PolicyRules>(src.policyRules);

    // split mccMnc to mcc and mnc
    std::string mcc = "";
    std::string mnc = "";
    SplitMccAndMnc(src.operatorId.mccMnc, mcc, mnc);
    dst.carrierId.mcc = OHOS::Telephony::ToUtf16(mcc);
    dst.carrierId.mnc = OHOS::Telephony::ToUtf16(mnc);
    dst.carrierId.gid1 = OHOS::Telephony::ToUtf16(src.operatorId.gid1);
    dst.carrierId.gid2 = OHOS::Telephony::ToUtf16(src.operatorId.gid2);
    dst.accessRules.clear();
}

void EsimFile::BuildBasicProfileInfo(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &profileNode)
{
    if (eProfileInfo == nullptr || profileNode == nullptr) {
        TELEPHONY_LOGE("BuildProfile failed");
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
        nickNameNode->Asn1AsString(eProfileInfo->nickname);
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_OBTAIN_OPERATOR_NAME)) {
        std::shared_ptr<Asn1Node> serviceProviderNameNode = profileNode->Asn1GetChild(TAG_ESIM_OBTAIN_OPERATOR_NAME);
        if (serviceProviderNameNode == nullptr) {
            TELEPHONY_LOGE("serviceProviderNameNode is nullptr");
            return;
        }
        serviceProviderNameNode->Asn1AsString(eProfileInfo->serviceProviderName);
    }
    if (profileNode->Asn1HasChild(TAG_ESIM_PROFILE_NAME)) {
        std::shared_ptr<Asn1Node> profileNameNode = profileNode->Asn1GetChild(TAG_ESIM_PROFILE_NAME);
        if (profileNameNode == nullptr) {
            TELEPHONY_LOGE("profileNameNode is nullptr");
            return;
        }
        profileNameNode->Asn1AsString(eProfileInfo->profileName);
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
        TELEPHONY_LOGE("BuildProfile failed");
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

ResultState EsimFile::DisableProfile(int32_t portIndex, const std::u16string &iccId)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventDisableProfile = BuildCallerInfo(MSG_ESIM_DISABLE_PROFILE);
    if (!ProcessDisableProfile(slotId_, eventDisableProfile)) {
        TELEPHONY_LOGE("ProcessDisableProfile encode failed");
        return ResultState();
    }
    isDisableProfileReady_ = false;
    std::unique_lock<std::mutex> lock(disableProfileMutex_);
    if (!disableProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isDisableProfileReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return disableProfileResult_;
}

std::string EsimFile::ObtainSmdsAddress(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventObtainSmdsAddress = BuildCallerInfo(MSG_ESIM_OBTAIN_SMDS_ADDRESS);
    if (!ProcessObtainSmdsAddress(slotId_, eventObtainSmdsAddress)) {
        TELEPHONY_LOGE("ProcessObtainSmdsAddress encode failed");
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
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable = BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    if (!ProcessRequestRulesAuthTable(slotId_, eventRequestRulesAuthTable)) {
        TELEPHONY_LOGE("ProcessRequestRulesAuthTable encode failed");
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

ResponseEsimResult EsimFile::ObtainEuiccChallenge(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventEUICCChanllenge = BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE);
    if (!ProcessObtainEuiccChallenge(slotId_, eventEUICCChanllenge)) {
        TELEPHONY_LOGE("ProcessObtainEuiccChallenge encode failed");
        return ResponseEsimResult();
    }
    isEuiccChallengeReady_ = false;
    std::unique_lock<std::mutex> lock(euiccChallengeMutex_);
    if (!euiccChallengeCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isEuiccChallengeReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return responseChallengeResult_;
}

bool EsimFile::ProcessDisableProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
    EsimProfile *profile = &esimProfile_;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    if (builder == nullptr || subBuilder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string str = OHOS::Telephony::ToUtf8(profile->iccId);
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
        return false;
    }
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    disableProfileResult_ = static_cast<ResultState>(pAsn1Node->Asn1AsInteger());
    {
        std::lock_guard<std::mutex> lock(disableProfileMutex_);
        isDisableProfileReady_ = true;
    }
    disableProfileCv_.notify_one();
    return true;
}

bool EsimFile::ProcessObtainSmdsAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr!");
        return false;
    }
    std::string outPutBytes;
    uint32_t byteLen = profileRoot->Asn1AsString(outPutBytes);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero!");
        return false;
    }
    smdsAddress_ = outPutBytes;
    {
        std::lock_guard<std::mutex> lock(smdsAddressMutex_);
        isSmdsAddressReady_ = true;
    }
    smdsAddressCv_.notify_one();
    return true;
}

struct CarrierIdentifier CarrierIdentifiers(const std::vector<uint8_t> &mccMncData, int mccMncLen,
    const std::u16string &gid1, const std::u16string &gid2)
{
    std::string strResult = Asn1Utils::BytesToHexStr(mccMncData);
    std::string mMcc(NUMBER_THREE + NUMBER_ONE, '\0');
    std::string mMnc(NUMBER_THREE, '\0');
    mMnc[NUMBER_ZERO] = strResult[NUMBER_FIVE];
    mMnc[NUMBER_ONE] = strResult[NUMBER_FOUR];
    mMcc[NUMBER_TWO] = strResult[NUMBER_THREE];
    if (strResult[NUMBER_TWO] != 'F') {
        mMnc[NUMBER_TWO] = strResult[NUMBER_TWO];
    }
    struct CarrierIdentifier carrierId;
    carrierId.mcc = OHOS::Telephony::ToUtf16(mMcc);
    carrierId.mnc = OHOS::Telephony::ToUtf16(mMnc);
    carrierId.gid1 = gid1;
    carrierId.gid2 = gid2;
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
        int32_t opIdNodesRes = grandson->Asn1GetChildren(TAG_ESIM_OPERATOR_ID, opIdNodes);
        if (opIdNodesRes != 0) {
            return false;
        }
        for (auto iter = opIdNodes.begin(); iter != opIdNodes.end(); ++iter) {
            std::shared_ptr<Asn1Node> curNode = nullptr;
            curNode = *iter;
            if (curNode == nullptr) {
                return false;
            }
            eUiccRulesAuthTable_.carrierIds.push_back(buildCarrierIdentifiers(curNode));
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
        eUiccRulesAuthTable_.policyRules.push_back(policyRules);
        eUiccRulesAuthTable_.policyRuleFlags.push_back(policyRuleFlags);
    }
    return true;
}

bool EsimFile::ProcessRequestRulesAuthTableDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    if (!RequestRulesAuthTableParseTagCtxComp0(root)) {
        TELEPHONY_LOGE("RequestRulesAuthTableParseTagCtxComp0 error");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(rulesAuthTableMutex_);
        isRulesAuthTableReady_ = true;
    }
    rulesAuthTableCv_.notify_one();
    return true;
}

bool EsimFile::ProcessObtainEuiccChallengeDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("Asn1GetChild failed");
        return false;
    }
    std::vector<uint8_t> profileResponseByte;
    uint32_t byteLen = profileRoot->Asn1AsBytes(profileResponseByte);
    if (byteLen == 0) {
        return false;
    }
    std::string resultStr = Asn1Utils::BytesToHexStr(profileResponseByte);
    responseChallengeResult_.resultCode = ResultState::RESULT_OK;
    responseChallengeResult_.response = OHOS::Telephony::ToUtf16(resultStr);
    {
        std::lock_guard<std::mutex> lock(euiccChallengeMutex_);
        isEuiccChallengeReady_ = true;
    }
    euiccChallengeCv_.notify_one();
    return true;
}

std::string EsimFile::ObtainDefaultSmdpAddress()
{
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventSmdpAddress = BuildCallerInfo(MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE);
    if (!ProcessObtainDefaultSmdpAddress(slotId_, eventSmdpAddress)) {
        TELEPHONY_LOGE("ProcessObtainDefaultSmdpAddress encode failed");
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

ResponseEsimResult EsimFile::CancelSession(const std::u16string &transactionId, CancelReason cancelReason)
{
    esimProfile_.transactionId = transactionId;
    esimProfile_.cancelReason = cancelReason;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventCancelSession = BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    if (!ProcessCancelSession(slotId_, eventCancelSession)) {
        TELEPHONY_LOGE("ProcessCancelSession encode failed");
        return ResponseEsimResult();
    }
    isCancelSessionReady_ = false;
    std::unique_lock<std::mutex> lock(cancelSessionMutex_);
    if (!cancelSessionCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isCancelSessionReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return cancelSessionResult_;
}

EuiccProfile EsimFile::ObtainProfile(int32_t portIndex, const std::u16string &iccId)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventGetProfile = BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    if (!ProcessGetProfile(slotId_, eventGetProfile)) {
        TELEPHONY_LOGE("ProcessGetProfile encode failed");
        return EuiccProfile();
    }
    isObtainProfileReady_ = false;
    std::unique_lock<std::mutex> lock(obtainProfileMutex_);
    if (!obtainProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isObtainProfileReady_; })) {
        SyncCloseChannel();
        return EuiccProfile();
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
    builder->Asn1AddChildAsInteger(TAG_ESIM_CTX_1, static_cast<uint32_t>(profile->cancelReason));
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
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (profileRoot == nullptr) {
        return false;
    }
    std::vector<uint8_t> outPutBytes;
    uint32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero");
        return false;
    }
    defaultDpAddress_ = Asn1Utils::BytesToHexStr(outPutBytes);
    return true;
}

bool EsimFile::ProcessCancelSessionDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    std::string responseResult;
    uint32_t byteLen = root->Asn1AsString(responseResult);
    if (byteLen == 0) {
        return false;
    }
    cancelSessionResult_.resultCode = ResultState::RESULT_OK;
    cancelSessionResult_.response = OHOS::Telephony::ToUtf16(responseResult);
    {
        std::lock_guard<std::mutex> lock(cancelSessionMutex_);
        isCancelSessionReady_ = true;
    }
    cancelSessionCv_.notify_one();
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
    BuildProfile(&euiccProfileInfo, profileInfo);
    ConvertProfileInfoToApiStruct(eUiccProfile_, euiccProfileInfo);
    return true;
}

bool EsimFile::ProcessGetProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    if (!GetProfileDoneParseProfileInfo(root)) {
        TELEPHONY_LOGE("GetProfileDoneParseProfileInfo error!");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(obtainProfileMutex_);
        isObtainProfileReady_ = true;
    }
    obtainProfileCv_.notify_one();
    return true;
}

ResultState EsimFile::ResetMemory(ResetOption resetOption)
{
    esimProfile_.option = resetOption;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventResetMemory = BuildCallerInfo(MSG_ESIM_RESET_MEMORY);
    if (!ProcessResetMemory(slotId_, eventResetMemory)) {
        TELEPHONY_LOGE("ProcessResetMemory encode failed");
        return ResultState();
    }
    isResetMemoryReady_ = false;
    std::unique_lock<std::mutex> lock(resetMemoryMutex_);
    if (!resetMemoryCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isResetMemoryReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return resetResult_;
}

ResultState EsimFile::SetDefaultSmdpAddress(const std::u16string &defaultSmdpAddress)
{
    esimProfile_.defaultSmdpAddress = defaultSmdpAddress;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventSetSmdpAddress = BuildCallerInfo(MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE);
    if (!ProcessEstablishDefaultSmdpAddress(slotId_, eventSetSmdpAddress)) {
        TELEPHONY_LOGE("ProcessEstablishDefaultSmdpAddress encode failed!!");
        return ResultState();
    }
    isSetDefaultSmdpAddressReady_ = false;
    std::unique_lock<std::mutex> lock(setDefaultSmdpAddressMutex_);
    if (!setDefaultSmdpAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSetDefaultSmdpAddressReady_; })) {
        SyncCloseChannel();
        return ResultState();
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
    builder->Asn1AddChildAsString(TAG_ESIM_TARGET_ADDR, defaultDpAddress_);
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
        return false;
    }
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    setDpAddressResult_ = static_cast<ResultState>(pAsn1Node->Asn1AsInteger());
    {
        std::lock_guard<std::mutex> lock(setDefaultSmdpAddressMutex_);
        isSetDefaultSmdpAddressReady_ = true;
    }
    setDefaultSmdpAddressCv_.notify_one();
    return true;
}

bool EsimFile::IsEsimSupported()
{
    char buf[ATR_LENGTH + 1] = {0};
    GetParameter(TEL_ESIM_SUPPORT, "", buf, ATR_LENGTH);
    ResetResponse resetResponse;
    std::string atr(buf);
    resetResponse.AnalysisAtrData(atr);
    isSupported_ = resetResponse.IsEuiccAvailable();
    return isSupported_;
}

ResponseEsimResult EsimFile::SendApduData(const std::u16string &aid, const std::u16string &apduData)
{
    if (aid.empty() || apduData.empty()) {
        return ResponseEsimResult();
    }
    esimProfile_.aid = aid;
    esimProfile_.apduData = apduData;
    SyncOpenChannel(aid);
    AppExecFwk::InnerEvent::Pointer eventSendApduData = BuildCallerInfo(MSG_ESIM_SEND_APUD_DATA);
    if (!ProcessSendApduData(slotId_, eventSendApduData)) {
        TELEPHONY_LOGE("ProcessSendApduData encode failed");
        return ResponseEsimResult();
    }
    std::unique_lock<std::mutex> lock(sendApduDataMutex_);
    if (!sendApduDataCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSendApduDataReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
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
        return false;
    }
    std::shared_ptr<Asn1Node> asn1NodeData = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (asn1NodeData == nullptr) {
        TELEPHONY_LOGE("asn1NodeData is nullptr");
        return false;
    }
    resetResult_ = static_cast<ResultState>(asn1NodeData->Asn1AsInteger());
    {
        std::lock_guard<std::mutex> lock(resetMemoryMutex_);
        isResetMemoryReady_ = true;
    }
    resetMemoryCv_.notify_one();
    return true;
}

bool EsimFile::setDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }
      
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_SET_DEFAULT_SMDP_ADDRESS);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    builder->Asn1AddChildAsString(TAG_ESIM_TARGET_ADDR, defaultDpAddress_);
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

bool EsimFile::setDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> asn1NodeData = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (asn1NodeData == nullptr) {
        TELEPHONY_LOGE("asn1NodeData is nullptr");
        return false;
    }
    setDpAddressResult_ = static_cast<ResultState>(asn1NodeData->Asn1AsInteger());
    {
        std::lock_guard<std::mutex> lock(setDefaultSmdpAddressMutex_);
        isSetDefaultSmdpAddressReady_ = true;
    }
    setDefaultSmdpAddressCv_.notify_one();
    return true;
}

bool EsimFile::ProcessSendApduData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (!IsLogicChannelOpen()) {
        return false;
    }

    std::string hexStr = OHOS::Telephony::ToUtf8(esimProfile_.toBeSendApduDataHexStr);
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> list = codec.GetCommands();
    std::unique_ptr<ApduCommand> apdCmd = std::move(list.front());
    if (apdCmd == nullptr) {
        return false;
    }
    ApduSimIORequestInfo reqInfo;
    CopyApdCmdToReqInfo(&reqInfo, apdCmd.get());
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
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    if (result == nullptr) {
        return false;
    }
    transApduDataResponse_.resultCode = ResultState::RESULT_OK;
    transApduDataResponse_.response = OHOS::Telephony::ToUtf16(result->resultData);

    {
        std::lock_guard<std::mutex> lock(sendApduDataMutex_);
        isSendApduDataReady_ = true;
    }
    sendApduDataCv_.notify_one();
    return true;
}

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
    AppExecFwk::InnerEvent::Pointer eventListNotif = BuildCallerInfo(MSG_ESIM_LIST_NOTIFICATION);
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
    if (dst.hashCc.size() == 0) {
        return false;
    }
    std::vector<uint8_t> bytes = Asn1Utils::StringToBytes(VCardUtils::DecodeBase64(dst.hashCc));
    builder->Asn1AddChildAsBytes(TAG_ESIM_OCTET_STRING_TYPE, bytes, bytes.size());
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
    if (fileData.resultData.length() == 0) {
        return false;
    }
    recvCombineStr_ = recvCombineStr_ + fileData.resultData;
    return (fileData.sw1 == SW1_VALUE_90 && fileData.sw2 == SW2_VALUE_00);
}

bool EsimFile::ProcessIfNeedMoreResponse(IccFileData &fileData, int32_t eventId)
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
        apdCmd->data.p3 = static_cast<uint32_t>(fileData.sw2);
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
    if (!CombineResponseDataFinish(fileData)) {
        if (!ProcessIfNeedMoreResponse(fileData, MSG_ESIM_AUTHENTICATE_SERVER)) {
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
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
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

void EsimFile::createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification& euicc)
{
    if (node == nullptr) {
        TELEPHONY_LOGE("createNotification node is nullptr");
        return;
    }
    std::shared_ptr<Asn1Node> metadataNode;
    if (node->GetNodeTag() == TAG_ESIM_NOTIFICATION_METADATA) {
        metadataNode = node;
    } else if (node->GetNodeTag() == TAG_ESIM_PROFILE_INSTALLATION_RESULT) {
        std::shared_ptr<Asn1Node> findNode = node->Asn1GetGrandson(TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA,
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
    std::string strResult;
    nodeTargetAddr->Asn1AsString(strResult);
    euicc.targetAddr = OHOS::Telephony::ToUtf16(strResult);

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
        euiccList.euiccNotification.push_back(euicc);
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
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
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
    if (compNode == nullptr) {
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
        TELEPHONY_LOGE("telRilManager_ is nullptr");
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
        return false;
    }
    std::shared_ptr<Asn1Node> root = ParseEvent(event);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (node == nullptr) {
        TELEPHONY_LOGE("node is nullptr");
        return false;
    }
    removeNotifResult_ = static_cast<ResultState>(node->Asn1AsInteger());
    {
        std::lock_guard<std::mutex> lock(removeNotificationMutex_);
        isRemoveNotificationReady_ = true;
    }
    removeNotificationCv_.notify_one();
    return true;
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
    memberFuncMap_[MSG_ESIM_SEND_APUD_DATA] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSendApduDataDone(event); };
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

std::shared_ptr<Asn1Node> EsimFile::ParseEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return nullptr;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return nullptr;
    }
    IccFileData *resultDataPtr = &(rcvMsg->fileData);
    if (resultDataPtr == nullptr) {
        TELEPHONY_LOGE("resultDataPtr is nullptr within rcvMsg");
        return nullptr;
    }
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultDataPtr->resultData);
    uint32_t byteLen = responseByte.size();
    return Asn1ParseResponse(responseByte, byteLen);
}

int32_t EsimFile::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
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

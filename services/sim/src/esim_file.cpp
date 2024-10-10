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
    oss << std::hex << static_cast<unsigned char>(versionRaw[VERSION_HIGH])
        << "." << static_cast<unsigned char>(versionRaw[VERSION_MIDDLE])
        << "." << static_cast<unsigned char>(versionRaw[VERSION_LOW]);
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
        BuildProfile(&euiccProfileInfo, curNode);
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

void EsimFile::BuildProfile(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &profileNode)
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
}

ResultState EsimFile::DisableProfile(int32_t portIndex, std::u16string &iccId)
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
    std::string iccidBytes;
    std::string str = OHOS::Telephony::ToUtf8(profile->iccId);
    Asn1Utils::BcdToBytes(str, iccidBytes);
    subBuilder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.length());
    std::shared_ptr<Asn1Node> subNode = subBuilder->Asn1Build();
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
    uint32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
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

struct CarrierIdentifier CarrierIdentifiers(const std::string &mccMncData, int mccMncLen,
    const std::u16string &gid1, const std::u16string &gid2)
{
    std::string strResult = Asn1Utils::BytesToHexStr(mccMncData);
    std::string mMcc(NUMBER_THREE + NUMBER_ONE, '\0');
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
    std::string gid1Byte;
    std::string gid2Byte;
    std::string strResult;
    CarrierIdentifier defaultCarrier = CarrierIdentifiers("", 0, u"", u"");
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

    std::string mccMnc;
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

std::shared_ptr<Asn1Node> ParseEvent(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::shared_ptr<IccFileData> resultDataPtr = nullptr;
    resultDataPtr = &(rcvMsg->fileData);
    if (resultDataPtr == nullptr) {
        TELEPHONY_LOGE("resultData is nullptr within rcvMsg");
        return nullptr;
    }
    std::string responseByte = Asn1Utils::HexStrToBytes(resultDataPtr->resultData);
    uint32_t byteLen = responseByte.length();
    return Asn1ParseResponse(responseByte, byteLen);
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
    std::string profileResponseByte;
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
        TELEPHONY_LOGE("resultData is nullptr within rcvMsg");
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

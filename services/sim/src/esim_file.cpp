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
    EsimProfile *profile = &esimProfile_;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_PROFILES);
    std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
    if (builder == nullptr || subBuilder == nullptr) {
        TELEPHONY_LOGE("get builder failed");
        return false;
    }
    std::vector<uint8_t> iccidBytes;
    std::string iccid= OHOS::Telephony::ToUtf8(profile->iccId);
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
    EsimProfile *profile = &esimProfile_;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_CANCEL_SESSION);
    if (builder == nullptr) {
        TELEPHONY_LOGE("builder is nullptr");
        return false;
    }
    std::string transactionIdStr = Str16ToStr8(profile->transactionId);
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
        TELEPHONY_LOGE("event is nullptr!");
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
        TELEPHONY_LOGE("byteLen is zero!");
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
    if(iccNode == nullptr) {
        TELEPHONY_LOGE("nodeIcc is null");
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

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainDefaultSmdpAddressDone(event); };
    memberFuncMap_[MSG_ESIM_CANCEL_SESSION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessCancelSessionDone(event); };
    memberFuncMap_[MSG_ESIM_GET_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetProfileDone(event); };
}
} // namespace Telephony
} // namespace OHOS
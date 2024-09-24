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

#define NUMBER_ZERO (0)
#define NUMBER_ONE (1)
#define NUMBER_TWO (2)
#define NUMBER_THREE (3)
#define NUMBER_FOUR (4)
#define NUMBER_FIVE (5)
#define NUMBER_ELEVEN (11)

#define SW1_MORE_RESPONSE 0x61
#define INS_GET_MORE_RESPONSE 0xC0
#define SW1_VALUE_90 0x90
#define SW2_VALUE_00 0x00

namespace OHOS {
namespace Telephony {
ResultState EsimFile::DeleteProfile(std::u16string iccId)
{
    esimProfile_.iccId = iccId;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventDeleteProfile = BuildCallerInfo(MSG_ESIM_DELETE_PROFILE);
    if (!ProcessDeleteProfile(slotId_, eventDeleteProfile)) {
        TELEPHONY_LOGE("ProcessDeleteProfile encode failed");
        return ResultState();
    }
    areDeleteProfileReady_ = false;
    std::unique_lock<std::mutex> lock(deleteProfileMutex_);
    if (!deleteProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areDeleteProfileReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return disableProfileResult_;
}

ResultState EsimFile::SwitchToProfile(int32_t portIndex, std::u16string iccId, bool forceDeactivateSim)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    esimProfile_.forceDeactivateSim = forceDeactivateSim;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventSwitchToProfile = BuildCallerInfo(MSG_ESIM_SWITCH_PROFILE);
    if (!ProcessSwitchToProfile(slotId_, eventSwitchToProfile)) {
        TELEPHONY_LOGE("ProcessSwitchToProfile encode failed");
        return ResultState();
    }
    areSwitchToProfileReady_ = false;
    std::unique_lock<std::mutex> lock(switchToProfileMutex_);
    if (!switchToProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areSwitchToProfileReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return switchResult_;
}

ResultState EsimFile::SetProfileNickname(std::u16string iccId, std::u16string nickname)
{
    esimProfile_.iccId = iccId;
    esimProfile_.nickname = nickname;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventSetNickName = BuildCallerInfo(MSG_ESIM_SET_NICK_NAME);
    if (!ProcessSetNickname(slotId_, eventSetNickName)) {
        TELEPHONY_LOGE("ProcessSetNickname encode failed");
        return ResultState();
    }
    areSetNicknameReady_ = false;
    std::unique_lock<std::mutex> lock(setNicknameMutex_);
    if (!setNicknameCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areSetNicknameReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return updateNicknameResult_;
}

bool EsimFile::ProcessDeleteProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::string iccidBytes;
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_DELETE_PROFILE);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        std::string str = OHOS::Telephony::ToUtf8(profile->iccId);
        Asn1Utils::BcdToBytes(str, iccidBytes);
        builder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.length());
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::ProcessSetNickname(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_SET_NICKNAME);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        std::string iccidBytes;
        std::string str = OHOS::Telephony::ToUtf8(profile->iccId);
        std::string childStr = OHOS::Telephony::ToUtf8(profile->nickname);
        Asn1Utils::BcdToBytes(str, iccidBytes);

        builder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.length());
        builder->Asn1AddChildAsString(TAG_ESIM_NICKNAME, childStr);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::ProcessDeleteProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    delProfile_ = (ResultState)pAsn1Node->Asn1AsInteger();
    {
        std::lock_guard<std::mutex> lock(deleteProfileMutex_);
        areDeleteProfileReady_ = true;
    }
    deleteProfileCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessSwitchToProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder =std::make_shared<Asn1Builder>(TAG_ESIM_ENABLE_PROFILE);
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
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::ProcessSwitchToProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    switchResult_ = (ResultState)pAsn1Node->Asn1AsInteger();

    {
        std::lock_guard<std::mutex> lock(switchToProfileMutex_);
        areSwitchToProfileReady_ = true;
    }
    switchToProfileCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessSetNicknameDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    updateNicknameResult_ = (ResultState)pAsn1Node->Asn1AsInteger();
    {
        std::lock_guard<std::mutex> lock(setNicknameMutex_);
        areSetNicknameReady_ = true;
    }
    setNicknameCv_.notify_one();
    return isFileHandleResponse;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_DELETE_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessDeleteProfileDone(event); }; 
    memberFuncMap_[MSG_ESIM_SWITCH_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSwitchToProfileDone(event); }; 
    memberFuncMap_[MSG_ESIM_SET_NICK_NAME] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSetNicknameDone(event); };
}
} // namespace Telephony
} // namespace OHOS

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
    setDpAddressResult_ = (ResultState)pAsn1Node->Asn1AsInteger();
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

    EsimProfile *profile = &esimProfile_;
    std::string hexStr = OHOS::Telephony::ToUtf8(profile->toBeSendApduDataHexStr);
    RequestApduBuild codec(currentChannelId_);
    codec.BuildStoreData(hexStr);
    std::list<std::unique_ptr<ApduCommand>> list = codec.GetCommands();
    std::unique_ptr<ApduCommand> apdCmd = std::move(list.front());
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

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEstablishDefaultSmdpAddressDone(event); };
    memberFuncMap_[MSG_ESIM_RESET_MEMORY] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessResetMemoryDone(event); };
    memberFuncMap_[MSG_ESIM_SEND_APUD_DATA] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSendApduDataDone(event); };
}
}
}
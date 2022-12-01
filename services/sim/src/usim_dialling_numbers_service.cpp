/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "usim_dialling_numbers_service.h"

namespace OHOS {
namespace Telephony {
std::mutex UsimDiallingNumbersService::mtx_;

UsimDiallingNumbersService::UsimDiallingNumbersService(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : AppExecFwk::EventHandler(runner)
{
    InitFuncMap();
}

void UsimDiallingNumbersService::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessEvent event is null");
        return;
    }
    uint32_t id = event->GetInnerEventId();
    TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessEvent Id is %{public}d", id);
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd != nullptr) {
        if (fd->exception != nullptr) {
            TELEPHONY_LOGE("UsimDiallingNumbersService::ProcessEvent: get error result");
            SendLocalBack();
            return;
        }
    }
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(event);
        }
    }
}

void UsimDiallingNumbersService::InitFuncMap()
{
    memberFuncMap_[MSG_USIM_PBR_LOAD_DONE] = &UsimDiallingNumbersService::ProcessPbrLoadDone;
    memberFuncMap_[MSG_USIM_USIM_ADN_LOAD_DONE] = &UsimDiallingNumbersService::ProcessDiallingNumberLoadDone;
}

void UsimDiallingNumbersService::ProcessPbrLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object != nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessPbrLoadDone: %{public}d", object->resultLength);
        if (object->exception == nullptr) {
            std::vector<std::string> &files = object->fileResults;
            GeneratePbrFile(files);
        }
    } else {
        TELEPHONY_LOGE("ProcessPbrLoadDone: get null pointer!!!");
    }
    TELEPHONY_LOGI("ProcessPbrLoadDone start load %{public}zu", pbrFiles_.size());
    if (pbrFiles_.empty()) {
        std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> list =
            std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
        SendBackResult(list);
        TELEPHONY_LOGI("ProcessPbrLoadDone empty pbr");
    } else {
        pbrIndex_ = 0;
        LoadDiallingNumberFiles(pbrIndex_);
    }
}

void UsimDiallingNumbersService::ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<DiallingNumbersHandlerResult> object = event->GetUniqueObject<DiallingNumbersHandlerResult>();

    if (object != nullptr) {
        if (object->exception == nullptr) {
            std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
                std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(object->result);
            FillDiallingNumbersRecords(diallingNumberList);
        } else {
            TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: exception occured");
        }
    }

    if (pbrIndex_ < pbrFiles_.size()) {
        TELEPHONY_LOGI(
            "ProcessDiallingNumberLoadDone to Tap: %{public}d %{public}zu", pbrIndex_, pbrFiles_.size());
        LoadDiallingNumberFiles(++pbrIndex_);
    } else {
        TELEPHONY_LOGI("loadEfFilesFromUsim: finished");
        SendLocalBack();
    }
}

void UsimDiallingNumbersService::FillDiallingNumbersRecords(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list)
{
    if (list != nullptr) {
        for (std::vector<std::shared_ptr<DiallingNumbersInfo>>::iterator it = list->begin(); it != list->end(); ++it) {
            diallingNumbersFiles_.push_back(*it);
        }
        TELEPHONY_LOGI(
            "UsimDiallingNumbersService::FillDiallingNumbersRecords  %{public}zu", diallingNumbersFiles_.size());
    } else {
        TELEPHONY_LOGE("FillDiallingNumbersRecords: get null vectors!!!");
    }
}

void UsimDiallingNumbersService::ObtainUsimElementaryFiles(const AppExecFwk::InnerEvent::Pointer &pointer)
{
    callerPointer_ = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(pointer));
    if (diallingNumbersFiles_.empty()) {
        if (pbrFiles_.empty()) {
            LoadPbrFiles();
        }
    }
}

void UsimDiallingNumbersService::LoadPbrFiles()
{
    std::unique_lock<std::mutex> lock(mtx_);
    AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(MSG_USIM_PBR_LOAD_DONE);
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("LoadPbrFiles fileController_ is nullptr");
        return;
    }
    fileController_->ObtainAllLinearFixedFile(ELEMENTARY_FILE_PBR, event);
}

bool UsimDiallingNumbersService::LoadDiallingNumberFiles(int recId)
{
    if (recId >= static_cast<int>(pbrFiles_.size())) {
        TELEPHONY_LOGI("LoadDiallingNumberFiles finish %{public}d", recId);
        NextStep(MSG_USIM_USIM_ADN_LOAD_DONE);
        return false;
    }

    std::unique_lock<std::mutex> lock(mtx_);
    std::map<int, std::shared_ptr<TagData>> files = pbrFiles_.at(recId)->fileIds_;
    if (files.empty() || !files.size()) {
        TELEPHONY_LOGI("LoadDiallingNumberFiles empty file %{public}d", recId);
        NextStep(MSG_USIM_USIM_ADN_LOAD_DONE);
        return false;
    }

    int extEf = files.at(TAG_SIM_USIM_EXT1) != nullptr ? files.at(TAG_SIM_USIM_EXT1)->fileId : 0;
    if (extEf >= 0 && files.at(TAG_SIM_USIM_ADN) != nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::LoadDiallingNumberFiles start %{public}d", recId);
        int efId = files.at(TAG_SIM_USIM_ADN)->fileId;
        AppExecFwk::InnerEvent::Pointer event = CreateHandlerPointer(MSG_USIM_USIM_ADN_LOAD_DONE, efId, 0, nullptr);
        if (diallingNumbersHandler_ == nullptr) {
            TELEPHONY_LOGE("LoadDiallingNumberFiles diallingNumbersHandler_ is nullptr");
            return false;
        }
        diallingNumbersHandler_->GetAllDiallingNumbers(efId, extEf, event);
        return true;
    } else {
        bool fileNull = files.at(TAG_SIM_USIM_ADN) == nullptr;
        TELEPHONY_LOGE("LoadDiallingNumberFiles error params %{public}d, nullfile %{public}d", extEf, fileNull);
        NextStep(MSG_USIM_USIM_ADN_LOAD_DONE);
        return false;
    }
}

void UsimDiallingNumbersService::GeneratePbrFile(std::vector<std::string> &records)
{
    pbrFileLoaded_ = !records.empty() && pbrFileLoaded_;
    pbrFiles_.clear();
    constexpr size_t FstByteChrLen = 2;
    for (const auto &dataPac : records) {
        TELEPHONY_LOGI("GeneratePbrFile: %{public}s", dataPac.c_str());
        if (dataPac.size() < FstByteChrLen) {
            continue;
        }
        auto subStr = dataPac.substr(0, FstByteChrLen);
        if (subStr == "FF" || subStr == "ff") {
            continue;
        }
        auto pbrFile = BuildNumberFileByRecord(dataPac);
        pbrFiles_.push_back(pbrFile);
        auto fileIt = pbrFile->fileIds_.find(TAG_SIM_USIM_ADN);
        if (fileIt == pbrFile->fileIds_.end()) {
            continue;
        }
        std::shared_ptr<TagData> file = fileIt->second;
        if (file == nullptr) {
            continue;
        }
        if (file->shortFileId == INVALID_SFI) {
            continue;
        }
        efIdOfSfi_.insert(std::pair<int, int>(file->shortFileId, file->fileId));
    }
}

AppExecFwk::InnerEvent::Pointer UsimDiallingNumbersService::BuildCallerInfo(int eventId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer UsimDiallingNumbersService::CreateHandlerPointer(
    int eventid, int efId, int index, std::shared_ptr<void> pobj)
{
    std::unique_ptr<DiallingNumbersHandleHolder> holder = std::make_unique<DiallingNumbersHandleHolder>();
    holder->fileID = efId;
    holder->index = index;
    holder->diallingNumber = pobj;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventid, holder, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

void UsimDiallingNumbersService::SetFileControllerAndDiallingNumberHandler(
    std::shared_ptr<IccFileController> &ctrl, std::shared_ptr<IccDiallingNumbersHandler> handler)
{
    fileController_ = ctrl;
    diallingNumbersHandler_ = handler;
}

std::shared_ptr<UsimDiallingNumberFile> UsimDiallingNumbersService::BuildNumberFileByRecord(
    const std::string &record)
{
    std::shared_ptr<TagService> recTlv = std::make_shared<TagService>(record);
    std::shared_ptr<UsimDiallingNumberFile> file = std::make_shared<UsimDiallingNumberFile>();
    int tag = 0;
    TELEPHONY_LOGI("BuildNumberFileByRecord: start get tag");
    while (recTlv->Next()) {
        tag = recTlv->GetTagCode();
        TELEPHONY_LOGI("front tag type: %{public}d", tag);
        if ((tag != TYPE1_FLAG) && (tag != TYPE2_FLAG) && (tag != TYPE3_FLAG)) {
            TELEPHONY_LOGE("the tag:'%{public}d' need in {%{public}d,%{public}d,%{public}d}", tag, TYPE1_FLAG,
                TYPE2_FLAG, TYPE3_FLAG);
            continue;
        }
        std::vector<uint8_t> datav;
        recTlv->GetValue(datav);
        auto tlvEfSfi = std::make_shared<TagService>(datav);
        StorePbrDetailInfo(file, tlvEfSfi, tag);
    }
    return file;
}

void UsimDiallingNumbersService::StorePbrDetailInfo(
    std::shared_ptr<UsimDiallingNumberFile> file, std::shared_ptr<TagService> tlv, int parentTag)
{
    for (int count = 0; tlv->Next(); ++count) {
        const int tag = tlv->GetTagCode();
        TELEPHONY_LOGI("make file tag type: %{public}d", tag);
        if ((tag < TAG_SIM_USIM_ADN) || (tag > TAG_SIM_USIM_CCP1)) {
            TELEPHONY_LOGE("the tag:'%{public}d' need in range [%{public}d,%{public}d]", tag, TAG_SIM_USIM_ADN,
                TAG_SIM_USIM_CCP1);
            continue;
        }
        // 3GPP TS 31.102, 4.4.2.1 EF_PBR
        std::vector<uint8_t> data;
        tlv->GetValue(data);
        auto dataIt = data.begin();
        if (dataIt == data.end()) {
            TELEPHONY_LOGE("the length of data == 0 ?!");
            continue;
        }
        uint32_t efid = *dataIt;
        ++dataIt;
        if (dataIt == data.end()) {
            TELEPHONY_LOGE("the length of data only one ?!");
            continue;
        }
        efid <<= BIT_OF_BYTE;
        efid |= *dataIt;
        ++dataIt;
        int sfi = (dataIt == data.end()) ? 0 : static_cast<int>((*dataIt));
        std::shared_ptr<TagData> deltaFile = std::make_shared<TagData>(parentTag, efid, sfi, count);
        TELEPHONY_LOGI(
            "MakeFiles result[ parentTag:%{public}d, efid:%{public}d, sfi:%{public}d, count:%{public}d ]",
            parentTag, efid, sfi, count);
        file->fileIds_.insert(std::pair<int, std::shared_ptr<TagData>>(tag, deltaFile));
    }
}

void UsimDiallingNumbersService::SendBackResult(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &diallingnumbers)
{
    auto owner = callerPointer_->GetOwner();
    uint32_t id = callerPointer_->GetInnerEventId();
    std::unique_ptr<UsimFetcher> fd = callerPointer_->GetUniqueObject<UsimFetcher>();
    std::unique_ptr<UsimResult> data = std::make_unique<UsimResult>(fd.get());
    data->result = static_cast<std::shared_ptr<void>>(diallingnumbers);
    owner->SendEvent(id, data);
    TELEPHONY_LOGI("UsimDiallingNumbersService::SendBackResult send end");
}

void UsimDiallingNumbersService::UsimDiallingNumbersService::SendLocalBack()
{
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingnumbers =
        std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(&diallingNumbersFiles_);
    SendBackResult(diallingnumbers);
}

void UsimDiallingNumbersService::NextStep(int msgId)
{
    std::unique_ptr<int> step = std::make_unique<int>(NEXT);
    SendEvent(msgId, step);
}

UsimDiallingNumbersService::~UsimDiallingNumbersService() {}
} // namespace Telephony
} // namespace OHOS

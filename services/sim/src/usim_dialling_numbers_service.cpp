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
constexpr int32_t MIN_ANR_RECORD_LENGTH_BYTES = 15;
constexpr int32_t ANR_ADDITION_NUMBER_LENGTH_OFFSET = 1;
constexpr int32_t ANR_ADDITION_NUMBER_OFFSET = 3;
constexpr int32_t MAX_EXT_BCD_LENGTH = 10;
const std::u16string NUMBER_SPLIT = u";";
constexpr int64_t PROCESS_PBR_DELAY_MS = 10 * 1000;

std::mutex UsimDiallingNumbersService::mtx_;

UsimDiallingNumbersService::UsimDiallingNumbersService() : TelEventHandler("UsimDiallingNumbersService")
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
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            memberFunc(event);
        }
    }
}

void UsimDiallingNumbersService::InitFuncMap()
{
    memberFuncMap_[MSG_USIM_LOAD_PBR] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { LoadPbrFiles(); };
    memberFuncMap_[MSG_USIM_PBR_LOAD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { ProcessPbrLoadDone(event); };
    memberFuncMap_[MSG_USIM_ADN_LOAD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { ProcessDiallingNumberLoadDone(event); };
    memberFuncMap_[MSG_USIM_ANR_LOAD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { ProcessDiallingNumber2LoadDone(event); };
}

void UsimDiallingNumbersService::ProcessPbrLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object == nullptr) {
        TELEPHONY_LOGE("ProcessPbrLoadDone: get null pointer!!!");
        return;
    }
    if (object->exception == nullptr) {
        std::vector<std::string> &files = object->fileResults;
        GeneratePbrFile(files);
    }
    TELEPHONY_LOGI("ProcessPbrLoadDone start load %{public}zu", pbrFiles_.size());
    if (pbrFiles_.empty()) {
        std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> list =
            std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
        SendBackResult(list);
        TELEPHONY_LOGI("ProcessPbrLoadDone empty pbr");
        return;
    }
    for (size_t i = 0; i < pbrFiles_.size(); i++) {
        LoadDiallingNumberFiles(i);
        LoadDiallingNumber2Files(i);
    }
}

void UsimDiallingNumbersService::ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }

    std::unique_ptr<DiallingNumbersHandlerResult> resultObject = event->GetUniqueObject<DiallingNumbersHandlerResult>();
    if (resultObject == nullptr) {
        TELEPHONY_LOGE("process adn file: object is nullptr");
        return;
    }
    TELEPHONY_LOGI("usimservice load adn done, fileId=%{public}d", resultObject->fileID);
    adns_[resultObject->fileID] = std::vector<std::shared_ptr<DiallingNumbersInfo>>();
    if (resultObject->exception != nullptr) {
        auto exception = std::static_pointer_cast<RadioResponseInfo>(resultObject->exception);
        TELEPHONY_LOGE("process adn file exception occured, errno: %{public}d",
            static_cast<uint32_t>(exception->error));
        CheckQueryDone();
        return;
    }
 
    if (resultObject->result == nullptr) {
        TELEPHONY_LOGE("process adn file result nullptr");
        CheckQueryDone();
        return;
    }
 
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
        std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(resultObject->result);
    adns_[resultObject->fileID] =  *diallingNumberList;
    CheckQueryDone();
}
std::u16string UsimDiallingNumbersService::FetchAnrContent(const std::string &recordData)
{
    int recordLen = 0;
    std::shared_ptr<unsigned char> data = SIMUtils::HexStringConvertToBytes(recordData, recordLen);
    if (data == nullptr) {
        TELEPHONY_LOGE("anr file record bytes null data");
        return u"";
    }
    /* parse record lenth */
    if (recordLen < MIN_ANR_RECORD_LENGTH_BYTES) {
        TELEPHONY_LOGE("anr file record record length error");
        return u"";
    }
    unsigned char *record = data.get();
    /* parse extension data lenth */
    int length = static_cast<int>(record[ANR_ADDITION_NUMBER_LENGTH_OFFSET]);
    if (length > MAX_EXT_BCD_LENGTH) {
        length = MAX_EXT_BCD_LENGTH;
        TELEPHONY_LOGE("FetchExtensionContent number error");
    }
    /* parse extension data */
    std::string number2 =
        SimNumberDecode::ExtensionBCDConvertToString(data, recordLen, ANR_ADDITION_NUMBER_OFFSET, length);
    return Str8ToStr16(number2);
}

void UsimDiallingNumbersService::ProcessDiallingNumber2LoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object != nullptr) {
        std::vector<std::string> &dataList = object->fileResults;
        std::vector<std::u16string> number2s;
        for (const auto &item : dataList) {
            number2s.push_back(FetchAnrContent(item));
        }
        anrs_[event->GetParam()] = number2s;
    }
    CheckQueryDone();
}

void UsimDiallingNumbersService::ObtainUsimElementaryFiles(const AppExecFwk::InnerEvent::Pointer &pointer)
{
    callerPointer_ = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(pointer));
    LoadPbrFiles();
}

void UsimDiallingNumbersService::LoadPbrFiles()
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (isProcessingPbr) {
        SendEvent(MSG_USIM_LOAD_PBR, 0, PROCESS_PBR_DELAY_MS);
        return;
    }
    isProcessingPbr = true;
    AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(MSG_USIM_PBR_LOAD_DONE);
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("LoadPbrFiles fileController_ is nullptr");
        return;
    }
    fileController_->ObtainAllLinearFixedFile(ELEMENTARY_FILE_PBR, event);
}

bool UsimDiallingNumbersService::LoadDiallingNumberFiles(size_t recId)
{
    if (recId >= pbrFiles_.size()) {
        TELEPHONY_LOGI("LoadDiallingNumberFiles finish %{public}zu", recId);
        NextStep(MSG_USIM_ADN_LOAD_DONE);
        return false;
    }

    TELEPHONY_LOGI("usimservice load adn recId: %{public}ld", recId);
    std::unique_lock<std::mutex> lock(mtx_);
    std::map<int, std::shared_ptr<TagData>> files = pbrFiles_.at(recId)->fileIds_;
    if (files.find(TAG_SIM_USIM_EXT1) == files.end() || files.find(TAG_SIM_USIM_ADN) == files.end()) {
        TELEPHONY_LOGE("pbr tag data is incomplete at index: %{public}zu", recId);
        NextStep(MSG_USIM_ADN_LOAD_DONE);
        return false;
    }

    int extEf = files.at(TAG_SIM_USIM_EXT1) != nullptr ? files.at(TAG_SIM_USIM_EXT1)->fileId : 0;
    if (extEf >= 0 && files.at(TAG_SIM_USIM_ADN) != nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::LoadDiallingNumberFiles start %{public}zu", recId);
        int efId = files.at(TAG_SIM_USIM_ADN)->fileId;
        AppExecFwk::InnerEvent::Pointer event = CreateHandlerPointer(MSG_USIM_ADN_LOAD_DONE, efId, 0, nullptr);
        if (diallingNumbersHandler_ == nullptr) {
            TELEPHONY_LOGE("LoadDiallingNumberFiles diallingNumbersHandler_ is nullptr");
            return false;
        }
        diallingNumbersHandler_->GetAllDiallingNumbers(efId, extEf, event);
        return true;
    } else {
        bool fileNull = files.at(TAG_SIM_USIM_ADN) == nullptr;
        TELEPHONY_LOGE("LoadDiallingNumberFiles error params %{public}d, nullfile %{public}d", extEf, fileNull);
        NextStep(MSG_USIM_ADN_LOAD_DONE);
        return false;
    }
}

bool UsimDiallingNumbersService::LoadDiallingNumber2Files(size_t recId)
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (recId >= pbrFiles_.size()) {
        TELEPHONY_LOGE("load number anr files error: recId over");
        anrs_[recId] = {};
        return false;
    }
    TELEPHONY_LOGI("usimservice load anr recId: %{public}ld", recId);
    std::map<int, std::shared_ptr<TagData>> files = pbrFiles_.at(recId)->fileIds_;
    auto anrIter = files.find(TAG_SIM_USIM_ANR);
    if (anrIter == files.end()) {
        TELEPHONY_LOGE("load number anr files error: have not anr file");
        anrs_[recId] = {};
        return false;
    }
    std::shared_ptr<TagData> anrTag = anrIter->second;
    if (anrTag == nullptr) {
        TELEPHONY_LOGE("load number anr files error: anr file is nullptr");
        anrs_[recId] = {};
        return false;
    }
    AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(MSG_USIM_ANR_LOAD_DONE);
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("LoadPbrFiles fileController_ is nullptr");
        anrs_[recId] = {};
        return false;
    }
    fileController_->ObtainAllLinearFixedFile(anrTag->fileId, event);
    return true;
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
        if (pbrFile != nullptr) {
            pbrFiles_.push_back(pbrFile);
            auto fileIt = pbrFile->fileIds_.find(TAG_SIM_USIM_ADN);
            if (fileIt == pbrFile->fileIds_.end()) {
                continue;
            }
            std::shared_ptr<TagData> file = fileIt->second;
            if (file == nullptr || file->shortFileId == INVALID_SFI) {
                continue;
            }
            efIdOfSfi_.insert(std::pair<int, int>(file->shortFileId, file->fileId));
        }
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
    if (tlv == nullptr) {
        TELEPHONY_LOGI("StorePbrDetailInfo: tlv is nullptr!");
        return;
    }
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

void UsimDiallingNumbersService::CheckQueryDone()
{
    bool done = adns_.size() == pbrFiles_.size() && anrs_.size() == pbrFiles_.size();
    if (!done) {
        return;
    }
    auto result = std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    auto adnIter = adns_.begin();
    auto anrIter = anrs_.begin();
    for (; adnIter != adns_.end() && anrIter != anrs_.end(); ++adnIter, ++anrIter) {
        MergeNumbers(adnIter->second, anrIter->second);
        result->insert(result->end(), adnIter->second.begin(), adnIter->second.end());
    }
    adns_.clear();
    anrs_.clear();
    SendBackResult(result);
}

void UsimDiallingNumbersService::MergeNumbers(
    std::vector<std::shared_ptr<DiallingNumbersInfo>> &adn, const std::vector<std::u16string> &anr)
{
    if (adn.size() != anr.size()) {
        TELEPHONY_LOGE(
            "adn size [%{public}zu] not equal anr size [%{public}zu]", adn.size(), anr.size());
        return;
    }
    for (size_t i = 0; i < adn.size(); i++) {
        if (!anr[i].empty()) {
            auto numbers = adn[i]->GetNumber() + NUMBER_SPLIT + anr[i];
            adn[i]->UpdateNumber(numbers);
        }
    }
}

void UsimDiallingNumbersService::SendBackResult(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &diallingnumbers)
{
    isProcessingPbr = false;
    if (callerPointer_ == nullptr) {
        TELEPHONY_LOGE("callerPointer_ is nullptr");
        return;
    }
    auto owner = callerPointer_->GetOwner();
    if (owner == nullptr) {
        TELEPHONY_LOGE("owner is nullptr");
        return;
    }
    uint32_t id = callerPointer_->GetInnerEventId();
    std::unique_ptr<UsimFetcher> fd = callerPointer_->GetUniqueObject<UsimFetcher>();
    std::unique_ptr<UsimResult> data = std::make_unique<UsimResult>(fd.get());
    if (data == nullptr) {
        TELEPHONY_LOGE("data is nullptr");
        return;
    }
    data->result = static_cast<std::shared_ptr<void>>(diallingnumbers);
    TelEventHandler::SendTelEvent(owner, id, data);
    TELEPHONY_LOGI("UsimDiallingNumbersService::SendBackResult send end");
}

void UsimDiallingNumbersService::NextStep(int msgId)
{
    std::unique_ptr<int> step = std::make_unique<int>(NEXT);
    SendEvent(msgId, step);
}

UsimDiallingNumbersService::~UsimDiallingNumbersService() {}
} // namespace Telephony
} // namespace OHOS

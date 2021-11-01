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
UsimDiallingNumbersService::UsimDiallingNumbersService(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : AppExecFwk::EventHandler(runner)
{}

void UsimDiallingNumbersService::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    id = event->GetInnerEventId();
    TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessEvent Id is %{public}d", id);
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd != nullptr) {
        if (fd->exception != nullptr) {
            TELEPHONY_LOGE("UsimDiallingNumbersService::ProcessEvent: get error result");
            return;
        }
    }

    switch (id) {
        case MSG_USIM_PBR_LOAD_DONE:
            ProcessPbrLoadDone(event);
            break;
        case MSG_USIM_USIM_ADN_LOAD_DONE:
            ProcessDiallingNumberLoadDone(event);
            break;
        case MSG_USIM_IAP_LOAD_DONE:
            ProcessIapLoadDone(event);
            break;
        case MSG_USIM_EMAIL_LOAD_DONE:
            ProcessEmailLoadDone(event);
            break;
        default:
            break;
    }
}

void UsimDiallingNumbersService::ProcessPbrLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object != nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessPbrLoadDone: %{public}d", object->resultLength);
        if (object->exception == nullptr) {
            std::vector<std::string> &files = object->fileResults;
            CreatePbrFile(files);
            for (std::vector<std::string>::iterator it = files.begin(); it != files.end(); it++) {
                std::string item = *it;
                TELEPHONY_LOGI("pbrfile: %{public}s", item.c_str());
            }
        }
    } else {
        TELEPHONY_LOGE("ProcessPbrLoadDone: get null pointer!!!");
    }
    processWait_.notify_all();
}

void UsimDiallingNumbersService::ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<PbHandlerResult> object = event->GetUniqueObject<PbHandlerResult>();
    if (object != nullptr) {
        if (object->exception == nullptr) {
            std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
                std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(object->result);
            FillPhoneBookRecords(diallingNumberList);
        } else {
            TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: exception occured");
        }
    } else {
        TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: get null pointer!!!");
    }
    processWait_.notify_all();
}

void UsimDiallingNumbersService::FillPhoneBookRecords(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list)
{
    if (list != nullptr) {
        for (std::vector<std::shared_ptr<DiallingNumbersInfo>>::iterator it = list->begin(); it != list->end();
             it++) {
            diallingNumbersFils_.push_back(*it);
        }
        TELEPHONY_LOGI(
            "UsimDiallingNumbersService::FillPhoneBookRecords  %{public}zu", diallingNumbersFils_.size());
    } else {
        TELEPHONY_LOGE("FillPhoneBookRecords: get null vectors!!!");
    }
}

void UsimDiallingNumbersService::ProcessIapLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object != nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessIapLoadDone: %{public}d", object->resultLength);
        if (object->exception == nullptr) {
            iapFiles_.assign(object->fileResults.begin(), object->fileResults.end());
        }
    } else {
        TELEPHONY_LOGE("ProcessIapLoadDone: get null pointer!!!");
    }
    processWait_.notify_all();
}

void UsimDiallingNumbersService::ProcessEmailLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object != nullptr) {
        TELEPHONY_LOGI("UsimDiallingNumbersService::ProcessEmailLoadDone: %{public}d", object->resultLength);
        if (object->exception == nullptr) {
            emailFiles_.assign(object->fileResults.begin(), object->fileResults.end());
        }
    } else {
        TELEPHONY_LOGE("ProcessEmailLoadDone: get null pointer!!!");
    }
    processWait_.notify_all();
}

std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> UsimDiallingNumbersService::LoadEfFilesFromUsim()
{
    if (!diallingNumbersFils_.empty()) {
        if (updateCache_) {
            updateCache_ = false;
            RefreshCache();
        }
        return std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(&diallingNumbersFils_);
    }

    if (!isPbrPresent_) {
        return std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    }

    if (pbrFiles_.empty()) {
        LoadPbrFiles();
    }

    if (pbrFiles_.empty()) {
        return std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    }

    int numRecs = pbrFiles_.size();
    TELEPHONY_LOGI("loadEfFilesFromUsim: Loading diallingNumber and emails  %{public}d", numRecs);
    for (int i = 0; i < numRecs; i++) {
        LoadDiallingNumberFiles(i);
        LoadEmailFiles(i);
    }

    UpdatePhoneDiallingNumberFile();
    TELEPHONY_LOGI("loadEfFilesFromUsim: finished");
    return std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(&diallingNumbersFils_);
}

void UsimDiallingNumbersService::RefreshCache()
{
    if (pbrFiles_.empty()) {
        return;
    }
    std::vector<std::shared_ptr<DiallingNumbersInfo>> nullVector;
    diallingNumbersFils_.swap(nullVector);

    int numRecs = pbrFiles_.size();
    for (int i = 0; i < numRecs; i++) {
        LoadDiallingNumberFiles(i);
    }
}

void UsimDiallingNumbersService::InvalidateCache()
{
    updateCache_ = true;
}

void UsimDiallingNumbersService::LoadPbrFiles()
{
    std::unique_lock<std::mutex> lock(mtx_);
    AppExecFwk::InnerEvent::Pointer event = CreatePointer(MSG_USIM_PBR_LOAD_DONE);
    fileController_->ObtainAllLinearFixedFile(ELEMENTARY_FILE_PBR, event);
    processWait_.wait(lock);
}

void UsimDiallingNumbersService::LoadEmailFiles(int recId)
{
    std::map<int, std::shared_ptr<TagFile>> &files = pbrFiles_.at(recId)->fileIds_;
    if (files.empty()) {
        return;
    }

    std::shared_ptr<TagFile> &email = files.at(UF_EMAIL);
    TELEPHONY_LOGI("LoadEmailFiles start: %{public}d", recId);
    if (email != nullptr) {
        if (email->tag == TYPE2_FLAG) {
            if (files.find(UF_IAP) == files.end()) {
                TELEPHONY_LOGE("Can't locate EF_IAP in ELEMENTARY_FILE_PBR.");
                return;
            }

            TELEPHONY_LOGI("EF_IAP exists. Loading EF_IAP to retrieve the index.");
            LoadIapFiles(files.at(UF_IAP)->fileId);
            if (iapFiles_.empty()) {
                TELEPHONY_LOGE("Error: IAP file is empty");
                return;
            }
            TELEPHONY_LOGI("EF_EMAIL order in PBR record: %{public}d", email->index);
        }
        int emailEfid = email->fileId;
        if (!CheckEmailFiles(email, recId)) {
            return;
        }

        AppExecFwk::InnerEvent::Pointer event = CreatePointer(MSG_USIM_EMAIL_LOAD_DONE);
        fileController_->ObtainAllLinearFixedFile(emailEfid, event);
        TELEPHONY_LOGI("LoadEmailFiles start wait: %{public}d", recId);
        std::unique_lock<std::mutex> lock(mtx_);
        processWait_.wait(lock);
        if (emailFiles_.empty()) {
            TELEPHONY_LOGE("Error: Email file is empty");
            return;
        }

        if (email->tag == TYPE2_FLAG && !iapFiles_.empty()) {
            CreateType2Emails(recId);
        } else {
            CreateType1Emails(recId);
        }
    }
}

bool UsimDiallingNumbersService::CheckEmailFiles(const std::shared_ptr<TagFile> &email, int recId)
{
    int emailEfid = email->fileId;
    for (int i = 0; i < recId; i++) {
        if (pbrFiles_.at(i) != nullptr) {
            std::map<int, std::shared_ptr<TagFile>> &previousFileIds = pbrFiles_.at(i)->fileIds_;
            if (!previousFileIds.empty()) {
                std::shared_ptr<TagFile> &id = previousFileIds.at(UF_EMAIL);
                bool result = ((id != nullptr) && (id->fileId == emailEfid));
                TELEPHONY_LOGI("Skipped this EF_EMAIL which was loaded earlier %{public}d", result);
                return result;
            }
        }
    }
    return true;
}

void UsimDiallingNumbersService::CreateType1Emails(int recId)
{
    if (pbrFiles_.at(recId) == nullptr) {
        return;
    }

    int numRecs = pbrFiles_.at(recId)->ObtainMasterFileNum();
    TELEPHONY_LOGI("Building type 1 email list. recId = %{public}d  numRecs = %{public}d", recId, numRecs);

    std::string emailRecPac = "";
    unsigned char *emailRec = nullptr;
    for (int i = 0; i < numRecs; i++) {
        emailRecPac = emailFiles_.at(i);
        const char *constData = emailRecPac.c_str();
        char *rawData = const_cast<char *>(constData);
        emailRec = reinterpret_cast<unsigned char *>(rawData);
        int emLen = emailRecPac.size();
        int sfi = emailRec[emLen - LEN_MIN];
        uint diallingNumberRecId = emailRec[emLen - 1];

        std::string email = GetEmailContents(i);
        if (email.empty()) {
            continue;
        }

        int diallingNumberEfid = 0;
        if (sfi == INVALID_SFI || efIdOfSfi_.at(sfi) == 0) {
            std::shared_ptr<TagFile> file = pbrFiles_.at(recId)->fileIds_.at(UF_ADN);
            if (file == nullptr) {
                continue;
            }
            diallingNumberEfid = file->fileId;
        } else {
            diallingNumberEfid = efIdOfSfi_.at(sfi);
        }

        int index = (((diallingNumberEfid & 0xFFFF) << BYTE_BIT) | ((diallingNumberRecId - 1) & 0xFF));
        std::vector<std::string> emailList = emailsOfDiallingNumbers_.at(index);
        if (emailList.empty()) {
        }
        TELEPHONY_LOGI("Adding email # %{public}d, list to index 0x %{public}s", i, std::to_string(index).c_str());
        emailList.push_back(email);
        emailsOfDiallingNumbers_.insert(std::pair<int, std::vector<std::string>>(index, emailList));
    }
}

bool UsimDiallingNumbersService::CreateType2Emails(int recId)
{
    if (pbrFiles_.at(recId) == nullptr) {
        return false;
    }

    int numRecs = pbrFiles_.at(recId)->ObtainMasterFileNum();
    TELEPHONY_LOGI("Building type 2 email list. recId = %{public}d  numRecs = %{public}d", recId, numRecs);

    std::shared_ptr<TagFile> diallingNumberFile = pbrFiles_.at(recId)->fileIds_.at(UF_ADN);
    if (diallingNumberFile == nullptr) {
        TELEPHONY_LOGE("Error: Improper ICC card: EF_ADN does not exist in PBR files");
        return false;
    }
    uint diallingNumberEfid = diallingNumberFile->fileId;

    for (int i = 0; i < numRecs; i++) {
        std::string recordPac = iapFiles_.at(i);
        unsigned char *record = nullptr;
        int emailRecId = 0;

        if (!recordPac.empty()) {
            const char *constData = recordPac.c_str();
            char *rawData = const_cast<char *>(constData);
            record = reinterpret_cast<unsigned char *>(rawData);

            std::map<int, std::shared_ptr<TagFile>> &fileIds = pbrFiles_.at(recId)->fileIds_;
            auto iter = fileIds.find(UF_EMAIL);
            if (iter == fileIds.end()) {
                continue;
            }
            std::shared_ptr<TagFile> mailFile = iter->second;
            int pos = mailFile->index;
            emailRecId = record[pos];
        } else {
            continue;
        }

        std::string email = GetEmailContents(emailRecId - 1);
        if (!email.empty()) {
            int index = (((diallingNumberEfid & 0xFFFF) << BYTE_BIT) | (i & 0xFF));
            std::vector<std::string> emailList = emailsOfDiallingNumbers_.at(index);
            if (emailList.empty()) {
            }
            emailList.push_back(email);
            TELEPHONY_LOGI("Adding email list to index 0x %{public}s", std::to_string(index).c_str());
            emailsOfDiallingNumbers_.insert(std::pair<int, std::vector<std::string>>(index, emailList));
        }
    }
    return true;
}

void UsimDiallingNumbersService::LoadIapFiles(int efid)
{
    std::unique_lock<std::mutex> lock(mtx_);
    AppExecFwk::InnerEvent::Pointer event = CreatePointer(MSG_USIM_IAP_LOAD_DONE);
    fileController_->ObtainAllLinearFixedFile(efid, event);
    processWait_.wait(lock);
}

void UsimDiallingNumbersService::UpdatePhoneDiallingNumberFile()
{
    int numDiallingNumberRecs = diallingNumbersFils_.size();
    for (int i = 0; i < numDiallingNumberRecs; i++) {
        std::shared_ptr<DiallingNumbersInfo> rec = diallingNumbersFils_.at(i);
        uint diallingNumberEfid = rec->GetEfid();
        int diallingNumberRecId = rec->GetRecId();
        int index = (((diallingNumberEfid & 0xFFFF) << BYTE_BIT) | ((diallingNumberRecId - 1) & 0xFF));
        TELEPHONY_LOGI("UpdatePhoneDiallingNumberFile item %{public}d", index);
        auto iter = emailsOfDiallingNumbers_.find(index);
        if (iter == emailsOfDiallingNumbers_.end()) {
            continue;
        }
        std::vector<std::string> &emailList = iter->second;
        if (emailList.empty()) {
            continue;
        }

        std::vector<std::u16string> emailResult;
        auto it = emailList.begin();
        while (it != emailList.end()) {
            std::u16string str = Str8ToStr16(*it);
            emailResult.emplace_back(str);
            it++;
        }
        rec->SetEmails(emailResult);
        diallingNumbersFils_.at(i) = rec;
    }
}

std::string UsimDiallingNumbersService::GetEmailContents(int recId)
{
    int len = 0;
    std::string emailData = emailFiles_.at(recId);
    std::shared_ptr<unsigned char> emailRec = SIMUtils::HexStringConvertToBytes(emailData, len);
    return SIMUtils::DiallingNumberStringFieldConvertToString(emailRec, 0, len - LEN_MIN, 0);
}

void UsimDiallingNumbersService::LoadDiallingNumberFiles(int recId)
{
    std::unique_lock<std::mutex> lock(mtx_);
    std::map<int, std::shared_ptr<TagFile>> files = pbrFiles_.at(recId)->fileIds_;
    if (files.empty() || files.size() == 0) {
        TELEPHONY_LOGI("LoadDiallingNumberFiles empty file %{public}d", recId);
        return;
    }

    int extEf = 0;
    if (files.at(UF_EXT1) != nullptr) {
        extEf = files.at(UF_EXT1)->fileId;
    }

    if (extEf < 0) {
        TELEPHONY_LOGE("LoadDiallingNumberFiles error extEf %{public}d", extEf);
        return;
    }

    if (files.at(UF_ADN) == nullptr) {
        TELEPHONY_LOGE("LoadDiallingNumberFiles efdiallingNumber nullptr %{public}d", recId);
        return;
    }
    TELEPHONY_LOGI("UsimDiallingNumbersService::LoadDiallingNumberFiles start %{public}d", recId);
    int previousSize = diallingNumbersFils_.size();
    int efId = files.at(UF_ADN)->fileId;
    AppExecFwk::InnerEvent::Pointer event = CreateHandlerPointer(MSG_USIM_USIM_ADN_LOAD_DONE, efId, 0, nullptr);
    pbLoader_->GetAllDiallingNumbers(efId, extEf, event);

    processWait_.wait(lock);
    int num = diallingNumbersFils_.size() - previousSize;
    pbrFiles_.at(recId)->UpdateMasterFileNum(num);
}

void UsimDiallingNumbersService::CreatePbrFile(std::vector<std::string> &records)
{
    if (records.empty()) {
        std::vector<std::shared_ptr<UsimDiallingNumberFile>> nullVector;
        pbrFiles_.swap(nullVector);
        isPbrPresent_ = false;
        return;
    }

    char invalidChar = INVALID_VALUE;
    for (std::vector<std::string>::iterator it = records.begin(); it != records.end(); it++) {
        std::string &dataPac = *it;
        TELEPHONY_LOGI("CreatePbrFile: %{public}s", dataPac.c_str());
        if (dataPac.empty()) {
            continue;
        }

        int lent = 0;
        std::shared_ptr<unsigned char> ucc = SIMUtils::HexStringConvertToBytes(dataPac, lent);
        unsigned char *data = ucc.get();
        if (data[0] != invalidChar) {
            pbrFiles_.push_back(std::make_shared<UsimDiallingNumberFile>(dataPac));
        }
    }

    for (std::vector<std::shared_ptr<UsimDiallingNumberFile>>::iterator it = pbrFiles_.begin();
         it != pbrFiles_.end(); it++) {
        std::shared_ptr<UsimDiallingNumberFile> record = *it;
        if (record->fileIds_.find(UF_ADN) == record->fileIds_.end()) {
            continue;
        }

        std::shared_ptr<TagFile> file = record->fileIds_.at(UF_ADN);
        if (file != nullptr) {
            int sfi = file->shortFileId;
            if (sfi != INVALID_SFI) {
                efIdOfSfi_.insert(std::pair<int, int>(sfi, file->fileId));
            }
        }
    }
}

AppExecFwk::InnerEvent::Pointer UsimDiallingNumbersService::CreatePointer(int eventId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer UsimDiallingNumbersService::CreateHandlerPointer(
    int eventid, int efId, int index, std::shared_ptr<void> pobj)
{
    std::unique_ptr<PbLoadHolder> holder = std::make_unique<PbLoadHolder>();
    holder->fileID = efId;
    holder->index = index;
    holder->diallingNumber = pobj;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventid, holder, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

void UsimDiallingNumbersService::SetFileControllerAndDiallingNumberHandler(
    std::shared_ptr<IccFileController> &ctrl, std::shared_ptr<SimDiallingNumbersHandler> handler)
{
    fileController_ = ctrl;
    pbLoader_ = handler;
}

void UsimDiallingNumbersService::Reset()
{
    std::vector<std::shared_ptr<UsimDiallingNumberFile>> nullPbr;
    std::vector<std::string> nullIap;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> nullPhoneBook;
    std::vector<std::string> nullEmailFile;

    diallingNumbersFils_.swap(nullPhoneBook);
    iapFiles_.swap(nullIap);
    emailFiles_.swap(nullEmailFile);
    pbrFiles_.swap(nullPbr);

    isPbrPresent_ = true;
    updateCache_ = false;
    emailsOfDiallingNumbers_.clear();
    efIdOfSfi_.clear();
}

UsimDiallingNumbersService::~UsimDiallingNumbersService() {}
} // namespace Telephony
} // namespace OHOS

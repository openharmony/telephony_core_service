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

#include "icc_dialling_numbers_cache.h"

namespace OHOS {
namespace Telephony {
IccDiallingNumbersCache::IccDiallingNumbersCache(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimFileManager> simFileManager)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager)
{
    InitFileTypeMap();
}

IccDiallingNumbersCache::~IccDiallingNumbersCache() {}

void IccDiallingNumbersCache::Init()
{
    if ((usimDiallingNumberSrv_ != nullptr) && (diallingNumbersHandler_ != nullptr)) {
        TELEPHONY_LOGI("IccDiallingNumbersCache init already done");
        return;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersCache int get null pointer");
        return;
    }
    diallingNumbersHandler_ = simFileManager_->ObtainDiallingNumberHandler();
    if (diallingNumbersHandler_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersCache failed to InitDiallingNumbersLoader");
        return;
    }

    std::shared_ptr<AppExecFwk::EventRunner> loaderLoop = AppExecFwk::EventRunner::Create("usimpdiallingnumbers");
    if (loaderLoop.get() == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersCache failed to create usimpdiallingnumbers loop");
        return;
    }
    usimDiallingNumberSrv_ = std::make_shared<UsimDiallingNumbersService>(loaderLoop);
    if (usimDiallingNumberSrv_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersCache failed to create usimpdiallingnumbers.");
        return;
    }
    std::shared_ptr<IccFileController> fileController = simFileManager_->GetIccFileController();
    usimDiallingNumberSrv_->SetFileControllerAndDiallingNumberHandler(fileController, diallingNumbersHandler_);
    loaderLoop->Run();
}

void IccDiallingNumbersCache::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    uint32_t id = event->GetInnerEventId();
    TELEPHONY_LOGI("IccDiallingNumbersCache ProcessEvent Id is %{public}d", id);
    switch (id) {
        case MSG_SIM_OBTAIN_ADN_DETAILS_DONE:
            ProcessObtainAdnDetailsDone(event);
            break;
        case MSG_SIM_CHANGE_DIALLING_NUMBERS_DONE:
            ProcessChangeDiallingNumbersDone(event);
            break;
        case MSG_SIM_OBTAIN_PBR_DETAILS_DONE:
            ProcessObtainPbrDetailsDone(event);
            break;
        default:
            break;
    }
}

void IccDiallingNumbersCache::ProcessObtainPbrDetailsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<UsimResult> fd = event->GetUniqueObject<UsimResult>();
    int fileId = fd->fileID;
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
        std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(fd->result);
    auto iter = diallingNumberFileList_.find(fileId);
    if (iter != diallingNumberFileList_.end()) {
        diallingNumberFileList_.erase(fileId);
    }
    diallingNumberFileList_.insert(
        std::pair<int, std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>>(
        fileId, diallingNumberList));
    SendBackResult(fd->callerCache->caller, diallingNumberList, fd->exception);
    TELEPHONY_LOGI("IccDiallingNumbersCache::ProcessUsimDiallingNumberLoadDone finished");
}

void IccDiallingNumbersCache::ProcessObtainAdnDetailsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<DiallingNumbersHandlerResult> fd = event->GetUniqueObject<DiallingNumbersHandlerResult>();
    int fileId = fd->fileID;
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
        std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(fd->result);
    if (diallingNumberList == nullptr) {
        TELEPHONY_LOGE("diallingNumber loader ProcessObtainAdnDetailsDone error occured");
    } else {
        TELEPHONY_LOGI("ProcessObtainAdnDetailsDone %{public}zu", diallingNumberList->size());
    }
    auto iter = diallingNumberFileList_.find(fileId);
    if (iter != diallingNumberFileList_.end()) {
        diallingNumberFileList_.erase(fileId);
    }
    diallingNumberFileList_.insert(
        std::pair<int, std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>>(
            fileId, diallingNumberList));
    SendBackResult(fd->callerCache->caller, diallingNumberList, fd->exception);
    TELEPHONY_LOGI("IccDiallingNumbersCache::ProcessObtainAdnDetailsDone finished");
}

void IccDiallingNumbersCache::ProcessChangeDiallingNumbersDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<DiallingNumbersHandlerResult> fd = event->GetUniqueObject<DiallingNumbersHandlerResult>();
    int fileId = fd->fileID;
    int index = fd->index;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::static_pointer_cast<DiallingNumbersInfo>(fd->result);
    auto iter = diallingNumberFileList_.find(fileId);
    if (iter != diallingNumberFileList_.end()) {
        if (fd->exception == nullptr) {
            diallingNumberFileList_.at(fileId)->at(index - 1) = diallingNumber;
        } else {
            std::shared_ptr<HRilRadioResponseInfo> responseInfo =
                std::static_pointer_cast<HRilRadioResponseInfo>(fd->exception);
            if (responseInfo == nullptr) {
                return;
            }
            if (responseInfo->error == HRilErrType::NONE) {
                diallingNumberFileList_.at(fileId)->at(index - 1) = diallingNumber;
            }
        }
    } else {
        TELEPHONY_LOGE("no diallingNumber list");
    }
    SendUpdateResult(fd->callerCache->caller, fd->exception);
    TELEPHONY_LOGI("IccDiallingNumbersCache::ProcessChangeDiallingNumbersDone finished");
}

std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> IccDiallingNumbersCache::LoadReadyDiallingNumbers
    (int fileId)
{
    auto itDiallingNumbers = diallingNumberFileList_.find(fileId);
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList = nullptr;
    if (itDiallingNumbers != diallingNumberFileList_.end()) {
        diallingNumberList = itDiallingNumbers->second;
    }
    return diallingNumberList;
}

int IccDiallingNumbersCache::ExtendedElementFile(int fileId)
{
    auto iter = extTypeMap_.find(fileId);
    return (iter != extTypeMap_.end()) ? iter->second : -1;
}

void IccDiallingNumbersCache::UpdateDiallingNumberToIcc(int fileId,
    std::shared_ptr<DiallingNumbersInfo> diallingNumberInfor, int index,
    bool isDel, const AppExecFwk::InnerEvent::Pointer &caller)
{
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> oldDiallingNumberList =
        LoadReadyDiallingNumbers(fileId);

    if (oldDiallingNumberList == nullptr) {
        SendExceptionResult(caller, LOADER_ERROR);
        TELEPHONY_LOGE("WriteDiallingNumberToSim not load at first");
        return;
    }
    if (diallingNumberInfor == nullptr) {
        TELEPHONY_LOGE("diallingNumberInfor is nullptr!");
        return;
    }
    if (isDel && index == DiallingNumbersInfo::EMPTY_INDEX) {
        SearchIndexByNameAndNumber(oldDiallingNumberList, diallingNumberInfor, index);
    }
    if (!CheckValueAndOperation(oldDiallingNumberList, diallingNumberInfor, index, fileId)) {
        SendExceptionResult(caller, LOADER_ERROR);
        return;
    }
    diallingNumberInfor->elementaryFileId_ = fileId;
    diallingNumberInfor->index_ = index;
    std::string pin2 = Str16ToStr8(diallingNumberInfor->pin2_);
    diallingNumberInfor->pin2_ = u""; // reset

    DiallingNumberUpdateInfor infor;
    infor.diallingNumber = diallingNumberInfor;
    infor.fileId = fileId;
    infor.extFile = ExtendedElementFile(fileId);
    infor.index = index;
    infor.pin2 = pin2;
    infor.isDel = isDel;
    AppExecFwk::InnerEvent::Pointer event =
        BuildCallerInfo(MSG_SIM_CHANGE_DIALLING_NUMBERS_DONE, fileId, index, diallingNumberInfor, caller);
    diallingNumbersHandler_->UpdateDiallingNumbers(infor, event);
}

bool IccDiallingNumbersCache::CheckValueAndOperation(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
    const std::shared_ptr<DiallingNumbersInfo> &info, int &index, int fileId)
{
    if (index == ADD_FLAG) { // insert into nullpos
        int count = 0;
        for (auto it = list->begin(); it != list->end(); it++) {
            std::shared_ptr<DiallingNumbersInfo> &item = *it;
            count++;
            if (item->IsEmpty()) {  // find first null position for save
                index = count;
                return true;
            }
        }
    } else {
        auto iter = diallingNumberFileList_.find(fileId);
        if (iter != diallingNumberFileList_.end()) {
            std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &vc = iter->second;
            int size = (int)vc->size();
            if ((index < 1) || (index > size)) { // check index range
                TELEPHONY_LOGE("error index!!");
                return false;
            }
        }
        // check unnormal opearion del or update
        for (auto it = list->begin(); it != list->end(); it++) {
            std::shared_ptr<DiallingNumbersInfo> &item = *it;
            if (item->GetIndex() == index && item->IsEmpty()) {
                TELEPHONY_LOGE("update or del on null pos, invalid operation!!");
                return false;
            }
        }
    }
    return true;
}

void IccDiallingNumbersCache::SearchIndexByNameAndNumber(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
    const std::shared_ptr<DiallingNumbersInfo> &info, int &index)
{
    for (auto it = list->begin(); it != list->end(); it++) {
        std::shared_ptr<DiallingNumbersInfo> &item = *it;
        if (IsDiallingNumberEqual(info, item)) {
            index = item->GetIndex();
            TELEPHONY_LOGI("Search index is %{public}d", index);
        }
    }
}

void IccDiallingNumbersCache::ObtainAllDiallingNumberFiles(
    int fileId, int extFileId, const AppExecFwk::InnerEvent::Pointer &caller)
{
    TELEPHONY_LOGI("ObtainAllDiallingNumberFiles fileId: %{public}d %{public}d", fileId, extFileId);
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> result = LoadReadyDiallingNumbers(fileId);

    if (result != nullptr && caller != nullptr) {
        std::shared_ptr<void> object = nullptr;
        TELEPHONY_LOGI("ObtainAllDiallingNumberFiles has already loaded");
        SendBackResult(caller, result, object);
        return;
    }

    if (fileId == ELEMENTARY_FILE_PBR) {
        TELEPHONY_LOGI("ObtainAllDiallingNumberFiles start usim adn");
        AppExecFwk::InnerEvent::Pointer pointer = CreateUsimPointer(MSG_SIM_OBTAIN_PBR_DETAILS_DONE, fileId, caller);
        usimDiallingNumberSrv_->ObtainUsimElementaryFiles(pointer);
    } else {
        AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(
            MSG_SIM_OBTAIN_ADN_DETAILS_DONE, fileId, 0, nullptr, caller);
        diallingNumbersHandler_->GetAllDiallingNumbers(fileId, extFileId, event);
    }
}

void IccDiallingNumbersCache::SendExceptionResult(const AppExecFwk::InnerEvent::Pointer &caller, int errCode)
{
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList = nullptr;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = std::make_shared<HRilRadioResponseInfo>();
    responseInfo->error = static_cast<Telephony::HRilErrType>(errCode);
    std::shared_ptr<void> exception = static_cast<std::shared_ptr<void>>(responseInfo);
    SendBackResult(caller, diallingNumberList, exception);
}

void IccDiallingNumbersCache::SendBackResult(const AppExecFwk::InnerEvent::Pointer &callPointer,
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &ar,
    const std::shared_ptr<void> &object)
{
    if (callPointer == nullptr) {
        TELEPHONY_LOGE("callPointer is null pointer");
        return;
    }
    auto owner = callPointer->GetOwner();
    uint32_t id = callPointer->GetInnerEventId();
    std::unique_ptr<ResultObtain> fd = callPointer->GetUniqueObject<ResultObtain>();
    std::unique_ptr<ResponseResult> data = std::make_unique<ResponseResult>(fd.get());
    data->result = static_cast<std::shared_ptr<void>>(ar);
    data->exception = object;
    if (owner != nullptr) {
        owner->SendEvent(id, data);
    } else {
        TELEPHONY_LOGE("IccDiallingNumbersCache::SendBackResult null owner");
    }
    TELEPHONY_LOGI("IccDiallingNumbersCache::SendBackResult send end");
}

void IccDiallingNumbersCache::SendUpdateResult(
    const AppExecFwk::InnerEvent::Pointer &response, const std::shared_ptr<void> &object)
{
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumbers = nullptr;
    SendBackResult(response, diallingNumbers, object);
}

AppExecFwk::InnerEvent::Pointer IccDiallingNumbersCache::BuildCallerInfo(
    int eventid, int efId, int index, std::shared_ptr<void> pobj, const AppExecFwk::InnerEvent::Pointer &caller)
{
    std::unique_ptr<DiallingNumbersHandleHolder> holder = std::make_unique<DiallingNumbersHandleHolder>();
    holder->fileID = efId;
    holder->index = index;
    holder->diallingNumber = pobj;
    holder->callerCache = std::make_shared<PointerWrapper>();
    holder->callerCache->caller = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(caller));
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventid, holder, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccDiallingNumbersCache::CreateUsimPointer(
    int eventid, int efId, const AppExecFwk::InnerEvent::Pointer &caller)
{
    std::unique_ptr<UsimFetcher> holder = std::make_unique<UsimFetcher>();
    holder->fileID = efId;
    holder->callerCache = std::make_shared<PointerWrapper>();
    holder->callerCache->caller = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(caller));
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventid, holder, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

bool IccDiallingNumbersCache::IsDiallingNumberEqual(
    const std::shared_ptr<DiallingNumbersInfo> &src, const std::shared_ptr<DiallingNumbersInfo> &dest)
{
    return (StringEqual(src->name_, dest->name_) &&
        StringEqual(src->number_, dest->number_) && ArrayEqual(src->emails_, dest->emails_));
}

bool IccDiallingNumbersCache::StringEqual(const std::u16string &s1, const std::u16string &s2)
{
    return s1.compare(s2) == 0;
}

bool IccDiallingNumbersCache::ArrayEqual(
    const std::vector<std::u16string> &mailsSrc, const std::vector<std::u16string> &mailsDest)
{
    return std::equal(mailsSrc.begin(), mailsSrc.end(), mailsDest.begin(), mailsDest.end());
}

void IccDiallingNumbersCache::InitFileTypeMap()
{
    extTypeMap_[ELEMENTARY_FILE_MBDN] = ELEMENTARY_FILE_EXT6;
    extTypeMap_[ELEMENTARY_FILE_ADN] = ELEMENTARY_FILE_EXT1;
    extTypeMap_[ELEMENTARY_FILE_SDN] = ELEMENTARY_FILE_EXT3;
    extTypeMap_[ELEMENTARY_FILE_FDN] = ELEMENTARY_FILE_EXT2;
    extTypeMap_[ELEMENTARY_FILE_MSISDN] = ELEMENTARY_FILE_EXT1;
    extTypeMap_[ELEMENTARY_FILE_PBR] = 0;
}
} // namespace Telephony
} // namespace OHOS

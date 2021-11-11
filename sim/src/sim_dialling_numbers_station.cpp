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

#include "sim_dialling_numbers_station.h"

namespace OHOS {
namespace Telephony {
SimDiallingNumbersStation::SimDiallingNumbersStation(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<ISimFileManager> simFileManager)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager)
{}

SimDiallingNumbersStation::~SimDiallingNumbersStation() {}

void SimDiallingNumbersStation::Init()
{
    if ((usimDiallingNumberSrv_ != nullptr) && (pbLoader_ != nullptr)) {
        TELEPHONY_LOGI("SimDiallingNumbersStation init already done");
        return;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("SimDiallingNumbersStation int get null pointer");
        return;
    }
    std::shared_ptr<SimFileManager> fileMannager = std::static_pointer_cast<SimFileManager>(simFileManager_);
    pbLoader_ = fileMannager->ObtainDiallingNumberHandler();
    if (pbLoader_ == nullptr) {
        TELEPHONY_LOGE("SimDiallingNumbersStation failed to InitPhoneBookLoader");
        return;
    }

    std::shared_ptr<AppExecFwk::EventRunner> loaderLoop = AppExecFwk::EventRunner::Create("usimphonebook");
    if (loaderLoop.get() == nullptr) {
        TELEPHONY_LOGE("SimDiallingNumbersStation failed to create usimphonebook loop");
        return;
    }
    usimDiallingNumberSrv_ = std::make_shared<UsimDiallingNumbersService>(loaderLoop);
    if (usimDiallingNumberSrv_ == nullptr) {
        TELEPHONY_LOGE("SimDiallingNumbersStation failed to create usimphonebook.");
        return;
    }
    std::shared_ptr<IccFileController> fileController = fileMannager->GetIccFileController();
    usimDiallingNumberSrv_->SetFileControllerAndDiallingNumberHandler(fileController, pbLoader_);
    loaderLoop->Run();
}

void SimDiallingNumbersStation::ResetPointers()
{
    diallingNumberFilePointers_.clear();
}

void SimDiallingNumbersStation::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    id = event->GetInnerEventId();
    TELEPHONY_LOGI("SimDiallingNumbersStation ProcessEvent Id is %{public}d", id);
    switch (id) {
        case MSG_SIM_OBTAIN_ALL_ADN_FILES_DONE:
            ProcessDiallingNumberAllLikeLoadDone(event);
            break;
        case MSG_SIM_CHANGE_ADN_COMPLETED:
            ProcessDiallingNumberUpdateDone(event);
            break;
        default:
            break;
    }
}

void SimDiallingNumbersStation::ProcessDiallingNumberAllLikeLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<PbHandlerResult> fd = event->GetUniqueObject<PbHandlerResult>();
    int efid = fd->fileID;
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
        std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(fd->result);
    if (diallingNumberList == nullptr) {
        TELEPHONY_LOGE("diallingNumber loader ProcessDiallingNumberAllLikeLoadDone error occured");
    } else {
        TELEPHONY_LOGI("ProcessDiallingNumberAllLikeLoadDone %{public}zu", diallingNumberList->size());
    }

    diallingNumberFileList_.insert(
        std::pair<int, std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>>(
            efid, diallingNumberList));
    if (diallingNumberFilePointers_.find(efid) != diallingNumberFilePointers_.end()) {
        std::vector<AppExecFwk::InnerEvent::Pointer> &waiters = diallingNumberFilePointers_.at(efid);
        BackToAllPointers(waiters, diallingNumberList, fd->exception);
        diallingNumberFilePointers_.erase(efid);
    }
}

void SimDiallingNumbersStation::ProcessDiallingNumberUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<PbHandlerResult> fd = event->GetUniqueObject<PbHandlerResult>();
    int efid = fd->fileID;
    int index = fd->index;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::static_pointer_cast<DiallingNumbersInfo>(fd->result);
    auto iter = diallingNumberFileList_.find(efid);
    if (iter != diallingNumberFileList_.end()) {
        if (fd->exception == nullptr) {
            diallingNumberFileList_.at(efid)->at(index - 1) = diallingNumber;
        } else {
            std::shared_ptr<HRilRadioResponseInfo> responseInfo =
                std::static_pointer_cast<HRilRadioResponseInfo>(fd->exception);
            if (responseInfo->error == HRilErrType::NONE) {
                diallingNumberFileList_.at(efid)->at(index - 1) = diallingNumber;
            }
        }
    }
    usimDiallingNumberSrv_->InvalidateCache();
    SendUpdateResult(callerPointers_.at(efid), fd->exception);
    if (callerPointers_.find(efid) != callerPointers_.end()) {
        callerPointers_.erase(efid);
    }
    TELEPHONY_LOGI("SimDiallingNumbersStation::ProcessDiallingNumberUpdateDone finished");
}

void SimDiallingNumbersStation::ResetCallerPointers()
{
    std::map<int, AppExecFwk::InnerEvent::Pointer>::iterator iter;
    for (iter = callerPointers_.begin(); iter != callerPointers_.end(); iter++) {
        TELEPHONY_LOGE("SimCace reset");
        SendExceptionResult(iter->second, 0);
    }
    callerPointers_.clear();
}

void SimDiallingNumbersStation::Reset()
{
    diallingNumberFileList_.clear();
    usimDiallingNumberSrv_->Reset();
    ResetPointers();
    ResetCallerPointers();
}

std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> SimDiallingNumbersStation::LoadReadyDiallingNumbers
    (int efid)
{
    auto itDiallingNumbers = diallingNumberFileList_.find(efid);
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList = nullptr;
    if (itDiallingNumbers != diallingNumberFileList_.end()) {
        diallingNumberList = itDiallingNumbers->second;
    }
    return diallingNumberList;
}

int SimDiallingNumbersStation::ExtendedElementFile(int efid)
{
    switch (efid) {
        case ELEMENTARY_FILE_MBDN:
            return ELEMENTARY_FILE_EXT6;
        case ELEMENTARY_FILE_ADN:
            return ELEMENTARY_FILE_EXT1;
        case ELEMENTARY_FILE_SDN:
            return ELEMENTARY_FILE_EXT3;
        case ELEMENTARY_FILE_FDN:
            return ELEMENTARY_FILE_EXT2;
        case ELEMENTARY_FILE_MSISDN:
            return ELEMENTARY_FILE_EXT1;
        case ELEMENTARY_FILE_PBR:
            return 0;
        default:
            return -1;
    }
}

void SimDiallingNumbersStation::ChangeDiallingNumberForContents(int efid,
    std::shared_ptr<DiallingNumbersInfo> oldDiallingNumber, std::shared_ptr<DiallingNumbersInfo> latestDiallingNumber,
    std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    int extensionEF = ExtendedElementFile(efid);
    if (extensionEF < 0) {
        TELEPHONY_LOGE("EF is not known ADN-like EF:0x");
        SendExceptionResult(response, 0);
        return;
    }
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> oldDiallingNumberList = nullptr;
    if (efid == ELEMENTARY_FILE_PBR) {
        oldDiallingNumberList = usimDiallingNumberSrv_->LoadEfFilesFromUsim();
    } else {
        oldDiallingNumberList = LoadReadyDiallingNumbers(efid);
    }
    int index = -1;
    if (!CheckForSearch(oldDiallingNumberList, oldDiallingNumber, index, response)) {
        return;
    }

    if (efid == ELEMENTARY_FILE_PBR) {
        std::shared_ptr<DiallingNumbersInfo> foundDiallingNumber = oldDiallingNumberList->at(index - 1);
        efid = foundDiallingNumber->efid_;
        extensionEF = foundDiallingNumber->extRecord_;
        index = foundDiallingNumber->recordNumber_;

        latestDiallingNumber->efid_ = efid;
        latestDiallingNumber->extRecord_ = extensionEF;
        latestDiallingNumber->recordNumber_ = index;
    }

    if (callerPointers_.at(efid) != nullptr) {
        TELEPHONY_LOGE("Have pending update for EF:0x");
        SendExceptionResult(callerPointers_.at(efid), 0);
        return;
    }
    callerPointers_.insert(std::pair<int, AppExecFwk::InnerEvent::Pointer>(
        efid, std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(response))));
    AppExecFwk::InnerEvent::Pointer event =
        CreatePointer(MSG_SIM_CHANGE_ADN_COMPLETED, efid, index, latestDiallingNumber);
    pbLoader_->UpdateDiallingNumbers(latestDiallingNumber, efid, extensionEF, index, pin2, event);
}

bool SimDiallingNumbersStation::CheckForSearch(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
    const std::shared_ptr<DiallingNumbersInfo> &info, int &index, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (list != nullptr && list->empty()) {
        TELEPHONY_LOGE("DiallingNumber list not exist for EF:0x");
        SendExceptionResult(response, 0);
        return false;
    }
    index = -1;
    int count = 1;
    for (auto itr = list->begin(); itr != list->end(); ++itr) {
        if (IsDiallingNumberEqual(info, (*itr))) {
            index = count;
            break;
        }
        count++;
    }

    if (index == -1) {
        TELEPHONY_LOGE("DiallingNumber record don't exist for ");
        SendExceptionResult(response, 0);
        return false;
    }
    return true;
}

void SimDiallingNumbersStation::ChangeDiallingNumberForId(int efid,
    std::shared_ptr<DiallingNumbersInfo> diallingNumberInfor, int recordIndex, std::string pin2,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    int extensionEF = ExtendedElementFile(efid);
    if (extensionEF < 0) {
        TELEPHONY_LOGE("EF is not known ADN-like EF:0x");
        SendExceptionResult(response, LOADER_ERROR);
        return;
    }
    if ((callerPointers_.find(efid) != callerPointers_.end()) && callerPointers_.at(efid) != nullptr) {
        TELEPHONY_LOGE("Have pending update for EF:0x");
        SendExceptionResult(callerPointers_.at(efid), 0);
    }
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> oldDiallingNumberList = nullptr;
    if (efid == ELEMENTARY_FILE_PBR) {
        oldDiallingNumberList = usimDiallingNumberSrv_->LoadEfFilesFromUsim();
    } else {
        oldDiallingNumberList = LoadReadyDiallingNumbers(efid);
    }
    if (oldDiallingNumberList == nullptr) {
        SendExceptionResult(response, LOADER_ERROR);
        TELEPHONY_LOGE("ChangeDiallingNumberForId not load at first");
        return;
    }

    if (!CheckValueAndOperation(oldDiallingNumberList, diallingNumberInfor, recordIndex, efid)) {
        SendExceptionResult(response, LOADER_ERROR);
        return;
    }
    diallingNumberInfor->efid_ = efid;
    diallingNumberInfor->recordNumber_ = recordIndex;
    pin2 = Str16ToStr8(diallingNumberInfor->pin2_);
    diallingNumberInfor->pin2_ = u""; // reset

    callerPointers_.insert(std::pair<int, AppExecFwk::InnerEvent::Pointer>(
        efid, std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(response))));
    AppExecFwk::InnerEvent::Pointer event =
        CreatePointer(MSG_SIM_CHANGE_ADN_COMPLETED, efid, recordIndex, diallingNumberInfor);
    pbLoader_->UpdateDiallingNumbers(diallingNumberInfor, efid, extensionEF, recordIndex, pin2, event);
}

bool SimDiallingNumbersStation::CheckValueAndOperation(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
    const std::shared_ptr<DiallingNumbersInfo> &info, int &index, int efId)
{
    if (index == -1) { // insert into nullpos
        int count = 0;
        for (auto it = list->begin(); it != list->end(); it++) {
            std::shared_ptr<DiallingNumbersInfo> &item = *it;
            if (IsDiallingNumberEqual(info, item)) { // whether exist
                TELEPHONY_LOGE("the diallingNumber has already exist");
                return false;
            }
            count++;
            if (item->IsEmpty() && index == -1) {
                index = count; // find first null position for save
            }
        }
    } else {
        auto iter = diallingNumberFileList_.find(efId);
        if (iter != diallingNumberFileList_.end()) {
            std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &vc = iter->second;
            int size = vc->size();
            if ((index < 1) || (index > size)) { // check index range
                TELEPHONY_LOGE("error index!!");
                return false;
            }
        }
        // check unnormal opearion del or update
        for (auto it = list->begin(); it != list->end(); it++) {
            std::shared_ptr<DiallingNumbersInfo> &item = *it;
            if (item->GetRecId() == index && item->IsEmpty()) {
                TELEPHONY_LOGE("update or del on null pos, invalid operation!!");
                return false;
            }
        }
    }
    return true;
}

void SimDiallingNumbersStation::ObtainAllDiallingNumberFiles(
    int efid, int extensionEf, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::vector<AppExecFwk::InnerEvent::Pointer> waiters;
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> result = nullptr;
    TELEPHONY_LOGI("ObtainAllDiallingNumberFiles efid: %{public}d %{public}d", efid, extensionEf);

    if (efid == ELEMENTARY_FILE_PBR) {
        result = usimDiallingNumberSrv_->LoadEfFilesFromUsim();
    } else {
        result = LoadReadyDiallingNumbers(efid);
    }

    if (result != nullptr && !result->empty()) {
        if (response != nullptr) {
            std::shared_ptr<void> object = nullptr;
            SendBackResult(response, result, object);
            return;
        }
    }

    auto iter = diallingNumberFilePointers_.find(efid);
    if (iter != diallingNumberFilePointers_.end()) {
        diallingNumberFilePointers_.at(efid).push_back(
            std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(response)));
    } else {
        diallingNumberFilePointers_.insert(std::pair<int, std::vector<AppExecFwk::InnerEvent::Pointer>>(
            efid, std::vector<AppExecFwk::InnerEvent::Pointer>()));
        diallingNumberFilePointers_.at(efid).push_back(
            std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(response)));
    }

    if (extensionEf < 0) {
        if (response != nullptr) {
            TELEPHONY_LOGE("EF is not known type");
        }
        SendExceptionResult(response, LOADER_ERROR);
        return;
    }

    AppExecFwk::InnerEvent::Pointer event = CreatePointer(MSG_SIM_OBTAIN_ALL_ADN_FILES_DONE, efid, 0, nullptr);
    pbLoader_->GetAllDiallingNumbers(efid, extensionEf, event);
}

void SimDiallingNumbersStation::SendExceptionResult(const AppExecFwk::InnerEvent::Pointer &response, int errCode)
{
    if (errCode != LOADER_ERROR) { // not handle
        return;
    }

    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList = nullptr;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = std::make_shared<HRilRadioResponseInfo>();
    responseInfo->error = static_cast<Telephony::HRilErrType>(errCode);
    std::shared_ptr<void> exception = static_cast<std::shared_ptr<void>>(responseInfo);
    SendBackResult(response, diallingNumberList, exception);
}

void SimDiallingNumbersStation::BackToAllPointers(const std::vector<AppExecFwk::InnerEvent::Pointer> &waiters,
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &ar,
    const std::shared_ptr<void> &object)
{
    int id = 0;
    int size = waiters.size();
    while (id < size) {
        if (waiters.at(id) != nullptr) {
            SendBackResult(waiters[id], ar, object);
        }
        id++;
    }
}

void SimDiallingNumbersStation::SendBackResult(const AppExecFwk::InnerEvent::Pointer &response,
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &ar,
    const std::shared_ptr<void> &object)
{
    if (response == nullptr) {
        return;
    }
    auto owner = response->GetOwner();
    int id = response->GetInnerEventId();
    std::unique_ptr<StationFetcher> fd = response->GetUniqueObject<StationFetcher>();
    std::unique_ptr<StationResult> data = std::make_unique<StationResult>(fd.get());
    data->result = static_cast<std::shared_ptr<void>>(ar);
    data->exception = object;
    owner->SendEvent(id, data);
    TELEPHONY_LOGI("SimDiallingNumbersStation::SendBackResult send end");
}

void SimDiallingNumbersStation::SendUpdateResult(
    const AppExecFwk::InnerEvent::Pointer &response, const std::shared_ptr<void> &object)
{
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumbers = nullptr;
    SendBackResult(response, diallingNumbers, object);
}

AppExecFwk::InnerEvent::Pointer SimDiallingNumbersStation::CreatePointer(
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

bool SimDiallingNumbersStation::IsDiallingNumberEqual(
    const std::shared_ptr<DiallingNumbersInfo> &src, const std::shared_ptr<DiallingNumbersInfo> &dest)
{
    return (StringCompareNullEqualsEmpty(src->alphaTag_, dest->alphaTag_) &&
        StringCompareNullEqualsEmpty(src->number_, dest->number_) && ArrayEqual(src->emails_, dest->emails_));
}

bool SimDiallingNumbersStation::StringCompareNullEqualsEmpty(std::u16string &s1, std::u16string &s2)
{
    if (s1 == s2) {
        return true;
    }
    if (s1.empty()) {
        s1 = u"";
    }
    if (s2.empty()) {
        s2 = u"";
    }
    return (s1 == s2);
}

bool SimDiallingNumbersStation::ArrayEqual(
    const std::vector<std::u16string> &mailsSrc, const std::vector<std::u16string> &mailsDest)
{
    return std::equal(mailsSrc.begin(), mailsSrc.end(), mailsDest.begin(), mailsDest.end());
}
} // namespace Telephony
} // namespace OHOS

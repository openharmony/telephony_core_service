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

#include "icc_dialling_numbers_handler.h"

using namespace std;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Telephony {
std::atomic_int IccDiallingNumbersHandler::nextSerialId_(1);
std::unordered_map<int, std::shared_ptr<DiallingNumberLoadRequest>> IccDiallingNumbersHandler::requestMap_;
static std::mutex requestLock_;

IccDiallingNumbersHandler::IccDiallingNumbersHandler(std::shared_ptr<IccFileController> fh)
    : TelEventHandler("IccDiallingNumbersHandler"), fileController_(fh)
{
    InitFuncMap();
}

std::shared_ptr<DiallingNumberLoadRequest> IccDiallingNumbersHandler::CreateLoadRequest(
    int fileId, int exId, int indexNum, const std::string &pin2Str, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::lock_guard<std::mutex> lock(requestLock_);
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest =
        std::make_shared<DiallingNumberLoadRequest>(GetNextSerialId(), fileId, exId, indexNum, pin2Str, result);
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersHandler loadRequest is nullptr");
        return nullptr;
    }
    IccDiallingNumbersHandler::requestMap_.insert(std::make_pair(loadRequest->GetLoadId(), loadRequest));
    return loadRequest;
}

std::string IccDiallingNumbersHandler::GetFilePath(int elementaryFileId)
{
    // GSM SIM file path from TS 51.011
    std::string mf = MASTER_FILE_SIM;
    mf.append(DEDICATED_FILE_TELECOM);
    return elementaryFileId == ELEMENTARY_FILE_ADN ? mf : "";
}

void IccDiallingNumbersHandler::GetDiallingNumbers(
    int ef, int exid, int index, AppExecFwk::InnerEvent::Pointer &response)
{
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("fileController_ is null pointer");
        return;
    }
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = CreateLoadRequest(ef, exid, index, "", response);
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("loadRequest is null pointer");
        return;
    }
    AppExecFwk::InnerEvent::Pointer ptDiallingNumberRead =
        BuildCallerInfo(MSG_SIM_OBTAIN_ADN_DONE, loadRequest->GetLoadId());
    fileController_->ObtainLinearFixedFile(ef, GetFilePath(ef), index, ptDiallingNumberRead);
}

void IccDiallingNumbersHandler::GetAllDiallingNumbers(int ef, int exid, AppExecFwk::InnerEvent::Pointer &response)
{
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("fileController_ is null pointer");
        return;
    }
    TELEPHONY_LOGI("IccDiallingNumbersHandler::GetAllDiallingNumbers start");
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = CreateLoadRequest(ef, exid, 0, "", response);
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("loadRequest is null pointer");
        return;
    }
    AppExecFwk::InnerEvent::Pointer ptDiallingNumberReadAll =
        BuildCallerInfo(MSG_SIM_OBTAIN_ALL_ADN_DONE, loadRequest->GetLoadId());
    fileController_->ObtainAllLinearFixedFile(ef, GetFilePath(ef), ptDiallingNumberReadAll);
}

void IccDiallingNumbersHandler::UpdateDiallingNumbers(
    const DiallingNumberUpdateInfor &infor, AppExecFwk::InnerEvent::Pointer &response)
{
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("fileController_ is null pointer");
        return;
    }
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest =
        CreateLoadRequest(infor.fileId, infor.extFile, infor.index, infor.pin2, response);
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("loadRequest is null pointer");
        return;
    }
    loadRequest->SetIsDelete(infor.isDel);
    TELEPHONY_LOGI("UpdateDiallingNumbers contents ready");
    std::shared_ptr<void> diallingNumberObj = static_cast<std::shared_ptr<void>>(infor.diallingNumber);
    AppExecFwk::InnerEvent::Pointer linearFileSize =
        BuildCallerInfo(MSG_SIM_OBTAIN_LINEAR_FILE_SIZE_DONE, diallingNumberObj, loadRequest->GetLoadId());
    fileController_->ObtainLinearFileSize(infor.fileId, GetFilePath(infor.fileId), linearFileSize);
}

void IccDiallingNumbersHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    auto id = event->GetInnerEventId();
    int loadId = 0;
    TELEPHONY_LOGD("IccDiallingNumbersHandler::ProcessEvent id %{public}d", id);
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(event, loadId);
            SendBackResult(loadId);
        }
    } else {
        TELEPHONY_LOGI("IccDiallingNumbersHandler::ProcessEvent unknown id %{public}d", id);
    }
}

void IccDiallingNumbersHandler::ProcessLinearSizeDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    std::unique_ptr<ControllerToFileMsg> fdError = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = 0;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    if (fdError != nullptr) {
        loadId = fdError->arg1;
        id = loadId;
        loadRequest = FindLoadRequest(loadId);
        if (loadRequest != nullptr) {
            loadRequest->SetException(fdError->exception);
        }
        TELEPHONY_LOGE("ProcessLinearSizeDone error occured");
        return;
    }
    std::shared_ptr<EfLinearResult> object = event->GetSharedObject<EfLinearResult>();
    if (object == nullptr) {
        TELEPHONY_LOGE("object is nullptr!");
        return;
    }
    std::shared_ptr<DiallingNumbersInfo> diallingNumberLoad = nullptr;
    loadId = object->arg1;
    id = loadId;
    loadRequest = FindLoadRequest(loadId);
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("loadRequest is nullptr!");
        return;
    }
    if (object->exception == nullptr) {
        std::shared_ptr<void> baseLoad = object->iccLoader;
        int *dataSize = object->valueData;
        if (baseLoad != nullptr) {
            diallingNumberLoad = std::static_pointer_cast<DiallingNumbersInfo>(baseLoad);
        }
        if (!FormatNameAndNumber(diallingNumberLoad, loadRequest->GetIsDelete())) {
            loadRequest->SetException(static_cast<std::shared_ptr<void>>(MakeExceptionResult(PARAMETER_INCORRECT)));
            return;
        }
        SendUpdateCommand(diallingNumberLoad, dataSize[0], loadRequest, loadId);
    }
}

void IccDiallingNumbersHandler::ProcessUpdateRecordDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    std::unique_ptr<ControllerToFileMsg> object = event->GetUniqueObject<ControllerToFileMsg>();
    if (object == nullptr) {
        TELEPHONY_LOGE("object is nullptr!");
        return;
    }
    int loadId = object->arg1;
    id = loadId;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    if (loadRequest != nullptr) {
        loadRequest->ClearCount();
        loadRequest->SetException(object->exception);
        if (loadRequest->GetException() == nullptr) {
            loadRequest->SetResult(object->iccLoader);
        }
    }
}

void IccDiallingNumbersHandler::ProcessDiallingNumberAllLoadDone(
    const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    std::unique_ptr<ControllerToFileMsg> fdError = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = 0;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    if (fdError != nullptr) {
        loadId = fdError->arg1;
        id = loadId;
        loadRequest = FindLoadRequest(loadId);
        if (loadRequest != nullptr) {
            loadRequest->SetException(fdError->exception);
        }
        TELEPHONY_LOGE("ProcessDiallingNumberAllLoadDone error occured");
        return;
    }

    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    if (object == nullptr) {
        TELEPHONY_LOGE("object is nullptr!");
        return;
    }
    loadId = object->arg1;
    id = loadId;
    loadRequest = FindLoadRequest(loadId);
    if (object->exception != nullptr) {
        TELEPHONY_LOGE("ProcessDiallingNumberAllLoadDone load failed");
        if (loadRequest != nullptr) {
            loadRequest->SetException(object->exception);
        }
        return;
    }

    ProcessDiallingNumber(loadRequest, object);
}

void IccDiallingNumbersHandler::ProcessDiallingNumber(
    const std::shared_ptr<DiallingNumberLoadRequest> &loadRequest, const std::shared_ptr<MultiRecordResult> &object)
{
    if (loadRequest == nullptr || object == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersHandler::ProcessDiallingNumber loadRequest or object is nullptr");
        return;
    }
    loadRequest->ClearCount();
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
        std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    loadRequest->SetResult(static_cast<std::shared_ptr<void>>(diallingNumberList));

    std::vector<std::string> &dataList = object->fileResults;
    TELEPHONY_LOGI("ProcessDiallingNumberAllLoadDone start: %{public}zu", dataList.size());
    int i = 0;
    for (std::vector<std::string>::iterator it = dataList.begin(); it != dataList.end(); ++it, i++) {
        std::string item = *it;
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(loadRequest->GetElementaryFileId(), 1 + i);
        FetchDiallingNumberContent(diallingNumber, item);
        diallingNumberList->push_back(diallingNumber);
    }
}

void IccDiallingNumbersHandler::ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = fd->arg1;
    id = loadId;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    if (fd->exception != nullptr) {
        if (loadRequest != nullptr) {
            loadRequest->SetException(fd->exception);
        }
        TELEPHONY_LOGE("ProcessDiallingNumberLoadDone load failed with exception");
        return;
    }

    std::string iccData = fd->resultData;
    TELEPHONY_LOGI("ProcessDiallingNumberLoadDone handle start");
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("ProcessDiallingNumberLoadDone loadRequest is nullptr");
        return;
    }
    std::shared_ptr<DiallingNumbersInfo> diallingNumber =
    std::make_shared<DiallingNumbersInfo>(loadRequest->GetElementaryFileId(), loadRequest->GetIndex());
    FetchDiallingNumberContent(diallingNumber, iccData);
    loadRequest->SetResult(static_cast<std::shared_ptr<void>>(diallingNumber));
}

void IccDiallingNumbersHandler::SendUpdateCommand(const std::shared_ptr<DiallingNumbersInfo> &diallingNumber,
    int length, const std::shared_ptr<DiallingNumberLoadRequest> &loadRequest, int loadId)
{
    int dataLen = length;
    if (dataLen == INVALID_LENGTH) {
        dataLen = RECORD_LENGTH;
    }
    TELEPHONY_LOGI("DiallingNumbersHandler::SendUpdateCommand start!! %{public}d %{public}d", dataLen, length);
    std::shared_ptr<unsigned char> dataDiallingNumber = nullptr;
    if (dataLen > 0) {
        dataDiallingNumber = CreateSavingSequence(diallingNumber, dataLen);
    }
    if (dataDiallingNumber != nullptr) {
        std::string data = SIMUtils::BytesConvertToHexString(dataDiallingNumber.get(), dataLen);
        AppExecFwk::InnerEvent::Pointer event =
            BuildCallerInfo(MSG_SIM_RENEW_ADN_DONE, diallingNumber, loadId);
        fileController_->UpdateLinearFixedFile(loadRequest->GetElementaryFileId(),
            GetFilePath(loadRequest->GetElementaryFileId()), loadRequest->GetIndex(), data, dataLen,
            loadRequest->GetPin2(), event);
        loadRequest->InitCount();
    } else {
        TELEPHONY_LOGE("invalid adn data");
        loadRequest->SetException(static_cast<std::shared_ptr<void>>(MakeExceptionResult(
            PARAMETER_INCORRECT)));
    }
}

bool IccDiallingNumbersHandler::SendBackResult(int loadId)
{
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    if (loadRequest == nullptr) {
        return false;
    }
    if (loadRequest->GetCaller() == nullptr || loadRequest->HasCount()) {
        return false;
    }
    auto owner = loadRequest->GetCaller()->GetOwner();
    uint32_t id = loadRequest->GetCaller()->GetInnerEventId();
    std::unique_ptr<DiallingNumbersHandleHolder> fd =
        loadRequest->GetCaller()->GetUniqueObject<DiallingNumbersHandleHolder>();
    if (fd == nullptr) {
        TELEPHONY_LOGE("fd is nullptr!");
        return false;
    }
    std::unique_ptr<DiallingNumbersHandlerResult> data = make_unique<DiallingNumbersHandlerResult>(fd.get());
    data->result = loadRequest->GetResult();
    data->exception = loadRequest->GetException();
    if (owner == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersHandler::SendBackResult owner null pointer");
        return false;
    }
    TelEventHandler::SendTelEvent(owner, id, data);
    ClearLoadRequest(loadId);
    TELEPHONY_LOGI("IccDiallingNumbersHandler::SendBackResult send end");
    return true;
}

AppExecFwk::InnerEvent::Pointer IccDiallingNumbersHandler::BuildCallerInfo(int eventId, int loadId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->arg1 = loadId;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccDiallingNumbersHandler::BuildCallerInfo(
    int eventId, std::shared_ptr<void> pobj, int loadId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->arg1 = loadId;
    object->iccLoader = pobj;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

std::shared_ptr<DiallingNumberLoadRequest> IccDiallingNumbersHandler::FindLoadRequest(int serial)
{
    std::lock_guard<std::mutex> lock(requestLock_);
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    auto iter = IccDiallingNumbersHandler::requestMap_.find(serial);
    if (iter == IccDiallingNumbersHandler::requestMap_.end()) {
        TELEPHONY_LOGI("FindLoadRequest not found serial:%{public}d", serial);
    } else {
        loadRequest = iter->second;
    }
    TELEPHONY_LOGI("FindLoadRequest : %{public}d", serial);
    return loadRequest;
}

void IccDiallingNumbersHandler::ClearLoadRequest(int serial)
{
    std::lock_guard<std::mutex> lock(requestLock_);
    IccDiallingNumbersHandler::requestMap_.erase(serial);
}

void IccDiallingNumbersHandler::FetchDiallingNumberContent(
    const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, const std::string &recordData)
{
    TELEPHONY_LOGI("FetchDiallingNumberContent start");
    int recordLen = 0;
    std::shared_ptr<unsigned char> data = SIMUtils::HexStringConvertToBytes(recordData, recordLen);
    if (diallingNumber == nullptr || data == nullptr) {
        TELEPHONY_LOGE("FetchDiallingNumberContent null data");
        return;
    }
    /* parse name */
    int offset = 0;
    int length = recordLen - PRE_BYTES_NUM;
    unsigned char *record = data.get();
    std::string tempStrTag = SIMUtils::DiallingNumberStringFieldConvertToString(data, offset, length, NAME_CHAR_POS);
    diallingNumber->name_ = Str8ToStr16(tempStrTag);
    /* parse length */
    offset += length;
    length = static_cast<int>(record[offset]);
    if (length > MAX_NUMBER_SIZE_BYTES) {
        diallingNumber->number_ = u"";
        TELEPHONY_LOGE("FetchDiallingNumberContent number error");
        return;
    }
    /* parse number */
    ++offset;
    std::string tempStrNumber =
    SimNumberDecode::BCDConvertToString(data, offset, length, SimNumberDecode::BCD_TYPE_ADN);
    diallingNumber->number_ = Str8ToStr16(tempStrNumber);
    TELEPHONY_LOGI("FetchDiallingNumberContent result end");
}

std::shared_ptr<unsigned char> IccDiallingNumbersHandler::CreateSavingSequence(
    const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int dataLength)
{
    std::shared_ptr<unsigned char> byteTagPac = nullptr;
    std::shared_ptr<unsigned char> diallingNumberStringPac = nullptr;
    unsigned char *byteTag = nullptr;
    unsigned char *diallingNumberString = nullptr;
    int offset = dataLength - PRE_BYTES_NUM;
    int byteTagLen = 0;
    if (dataLength < 0) {
        return nullptr;
    }
    unsigned char *cache = (unsigned char *)calloc(dataLength, sizeof(unsigned char));
    if (cache == nullptr) {
        return nullptr;
    }
    diallingNumberStringPac = std::shared_ptr<unsigned char>(cache, [](unsigned char *ptr) {
        if (ptr != nullptr) {
            free(ptr);
            ptr = nullptr;
        }
    });
    diallingNumberString = diallingNumberStringPac.get();
    for (int i = 0; i < dataLength; i++) {
        diallingNumberString[i] = (unsigned char)BYTE_VALUE;
    }
    TELEPHONY_LOGI("CreateSavingSequence contents start");

    uint maxNumberSize = (DIALING_NUMBERS_END - DIALING_NUMBERS_BEGIN + 1) * LENGTH_RATE;
    if (diallingNumber->number_.empty()) {
        TELEPHONY_LOGE("CreateSavingSequence number should not be empty");
        return diallingNumberStringPac;
    } else if (diallingNumber->number_.size() > maxNumberSize) {
        TELEPHONY_LOGE("CreateSavingSequence number length exceed the maximum");
        return nullptr;
    }
    byteTagPac = CreateNameSequence(diallingNumber->name_, byteTagLen);
    byteTag = byteTagPac.get();

    if (byteTagLen <= offset) {
        std::string tempNum = Str16ToStr8(diallingNumber->number_);
        FillNumberFiledForDiallingNumber(diallingNumberStringPac, tempNum, dataLength);
        if (byteTagLen > 0) {
            SIMUtils::ArrayCopy(byteTag, 0, diallingNumberString, 0, byteTagLen);
        }
        TELEPHONY_LOGI("CreateSavingSequence result: %{public}d", byteTagLen);
        return diallingNumberStringPac;
    } else {
        TELEPHONY_LOGE("CreateSavingSequence max data length is %{public}d", offset);
        return nullptr;
    }
}

void IccDiallingNumbersHandler::FillNumberFiledForDiallingNumber(
    std::shared_ptr<unsigned char> diallingNumber, const std::string &number, int dataLength)
{
    if (diallingNumber == nullptr) {
        return;
    }
    unsigned char *diallingNumberString = diallingNumber.get();
    int offSet = dataLength - PRE_BYTES_NUM;
    std::vector<uint8_t> bcdCodes;
    if (!SimNumberDecode::NumberConvertToBCD(number, bcdCodes, false, SimNumberDecode::BCD_TYPE_ADN)) {
        TELEPHONY_LOGE("FillNumberFiledForDiallingNumber fail at to SimNumberDecode::NumberConvertToBCD");
        return;
    }
    TELEPHONY_LOGI(" get result from SimNumberDecode::NumberConvertToBCD !! size:%{public}zu", bcdCodes.size());
    for (size_t i = 0; i < bcdCodes.size(); ++i) {
        diallingNumberString[offSet + TON_NPI_NUMBER + i] = bcdCodes.at(i);
    }
    int index = offSet + BCD_NUMBER_BYTES;
    unsigned char value = (unsigned char)(bcdCodes.size());
    diallingNumberString[index] = value;
    index = offSet + MORE_FILE_ID;
    value = (unsigned char)(BYTE_VALUE);
    diallingNumberString[index] = value;
    index = offSet + EXTRA_FILE_ID;
    diallingNumberString[index] = value;
}

std::shared_ptr<unsigned char> IccDiallingNumbersHandler::CreateNameSequence(
    const std::u16string &name, int &seqLength)
{
    std::string tempTag = Str16ToStr8(name);
    std::shared_ptr<unsigned char> seqResult = nullptr;
    if (SimCharDecode::IsChineseString(tempTag)) {
        std::string sq = SimCharDecode::CharCodeToSequence(name, true);
        seqResult = SIMUtils::HexStringConvertToBytes(sq, seqLength);
        TELEPHONY_LOGI("chinese alphabet encode result %{public}s %{public}d", sq.c_str(), seqLength);
    } else {
        std::string sq = SimCharDecode::CharCodeToSequence(tempTag, false);
        seqResult = SIMUtils::HexStringConvertToBytes(sq, seqLength);
        TELEPHONY_LOGI("english alphabet encode result %{public}s %{public}d", sq.c_str(), seqLength);
    }
    return seqResult;
}

bool IccDiallingNumbersHandler::FormatNameAndNumber(
    std::shared_ptr<DiallingNumbersInfo> &diallingNumber, bool isDel)
{
    if (diallingNumber == nullptr) {
        TELEPHONY_LOGE("diallingNumber is nullptr!");
        return false;
    }
    if (isDel) {
        diallingNumber->number_ = u"";
        diallingNumber->name_ = u"";
        return true;
    }
    std::string nameTemp = Str16ToStr8(diallingNumber->name_);
    std::string numberTemp = Str16ToStr8(diallingNumber->number_);
    std::string &&name = SIMUtils::Trim(nameTemp);
    std::string &&number = SIMUtils::Trim(numberTemp);

    std::u16string &&nameWide = Str8ToStr16(name);
    std::u16string &&numberWide = Str8ToStr16(number);

    uint nameMaxNum = SimCharDecode::IsChineseString(name) ? MAX_CHINESE_NAME : MAX_ENGLISH_NAME;
    if (nameWide.size() > nameMaxNum) {
        diallingNumber->name_ = nameWide.substr(0, nameMaxNum);
    }

    uint numberMaxNum = MAX_NUMBER_CHAR;
    if (numberWide.size() > numberMaxNum) {
        std::string tempNum = number.substr(0, numberMaxNum);
        if (SimNumberDecode::IsValidNumberString(tempNum)) {
            diallingNumber->number_ = Str8ToStr16(tempNum);
        } else {
            TELEPHONY_LOGE("invalid number full string");
            return false;
        }
    } else {
        if (!SimNumberDecode::IsValidNumberString(number)) {
            TELEPHONY_LOGE("invalid number string");
            return false;
        }
    }
    return true;
}

std::shared_ptr<HRilRadioResponseInfo> IccDiallingNumbersHandler::MakeExceptionResult(int code)
{
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = std::make_shared<HRilRadioResponseInfo>();
    responseInfo->error = static_cast<Telephony::HRilErrType>(code);
    return responseInfo;
}

void IccDiallingNumbersHandler::InitFuncMap()
{
    memberFuncMap_[MSG_SIM_OBTAIN_ADN_DONE] = &IccDiallingNumbersHandler::ProcessDiallingNumberLoadDone;
    memberFuncMap_[MSG_SIM_OBTAIN_ALL_ADN_DONE] = &IccDiallingNumbersHandler::ProcessDiallingNumberAllLoadDone;
    memberFuncMap_[MSG_SIM_OBTAIN_LINEAR_FILE_SIZE_DONE] = &IccDiallingNumbersHandler::ProcessLinearSizeDone;
    memberFuncMap_[MSG_SIM_RENEW_ADN_DONE] = &IccDiallingNumbersHandler::ProcessUpdateRecordDone;
}

void IccDiallingNumbersHandler::UpdateFileController(const std::shared_ptr<IccFileController> &fileController)
{
    fileController_ = fileController;
}
IccDiallingNumbersHandler::~IccDiallingNumbersHandler() {}
} // namespace Telephony
} // namespace OHOS

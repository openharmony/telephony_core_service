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

#include "sim_dialling_numbers_handler.h"

using namespace std;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Telephony {
std::atomic_int SimDiallingNumbersHandler::nextSerialId_(1);
std::unordered_map<int, std::shared_ptr<DiallingNumberLoadRequest>> SimDiallingNumbersHandler::requestMap_;

SimDiallingNumbersHandler::SimDiallingNumbersHandler(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<IccFileController> fh)
    : AppExecFwk::EventHandler(runner), fileController_(fh)
{}

std::shared_ptr<DiallingNumberLoadRequest> SimDiallingNumbersHandler::CreateLoadRequest(
    const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<DiallingNumberLoadRequest> laodRequest =
        std::make_shared<DiallingNumberLoadRequest>(GetNextSerialId(), result);
    if (laodRequest == nullptr) {
        TELEPHONY_LOGE("SimDiallingNumbersHandler laodRequest is nullptr");
        return nullptr;
    }
    SimDiallingNumbersHandler::requestMap_.insert(std::make_pair(laodRequest->loadId, laodRequest));
    return laodRequest;
}

std::string SimDiallingNumbersHandler::GetEFPath(int efid)
{
    if (efid == ELEMENTARY_FILE_ADN) {
        std::string mf = MASTER_FILE_SIM;
        mf.append(DEDICATED_FILE_TELECOM);
        return mf;
    }
    return "";
}

void SimDiallingNumbersHandler::LoadFromEF(
    int ef, int extensionEF, int recordNumber, AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = CreateLoadRequest(response);
    loadRequest->ef = ef;
    loadRequest->extensionEF = extensionEF;
    loadRequest->recordNumber = recordNumber;
    AppExecFwk::InnerEvent::Pointer ptDiallingNumberRead =
        CreatePointer(MSG_SIM_OBTAIN_ADN_COMPLETED, loadRequest->loadId);
    fileController_->ObtainLinearFixedFile(ef, GetEFPath(ef), recordNumber, ptDiallingNumberRead);
}

void SimDiallingNumbersHandler::GetAllDiallingNumbers(
    int ef, int extensionEF, AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGI("SimDiallingNumbersHandler::GetAllDiallingNumbers start");
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = CreateLoadRequest(response);
    loadRequest->ef = ef;
    loadRequest->extensionEF = extensionEF;
    AppExecFwk::InnerEvent::Pointer ptDiallingNumberReadAll =
        CreatePointer(MSG_SIM_OBTAIN_ALL_ADN_COMPLETED, loadRequest->loadId);
    fileController_->ObtainAllLinearFixedFile(ef, GetEFPath(ef), ptDiallingNumberReadAll);
}

void SimDiallingNumbersHandler::UpdateDiallingNumbers(std::shared_ptr<DiallingNumbersInfo> diallingNumber, int ef,
    int extensionEF, int recordNumber, std::string pin2, AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = CreateLoadRequest(response);
    loadRequest->ef = ef;
    loadRequest->extensionEF = extensionEF;
    loadRequest->recordNumber = recordNumber;
    loadRequest->pin2 = pin2;

    std::string name = Str16ToStr8(diallingNumber->GetAlphaTag());
    std::string number = Str16ToStr8(diallingNumber->GetNumber());
    TELEPHONY_LOGI("UpdateDiallingNumbers contents: %{public}s %{public}s", name.c_str(), number.c_str());
    std::shared_ptr<void> diallingNumberObj = static_cast<std::shared_ptr<void>>(diallingNumber);
    AppExecFwk::InnerEvent::Pointer linearFileSize =
        CreatePointer(MSG_SIM_OBTAIN_LINEAR_FILE_SIZE_COMPLETED, diallingNumberObj, loadRequest->loadId);
    fileController_->ObtainLinearFileSize(ef, GetEFPath(ef), linearFileSize);
}

void SimDiallingNumbersHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    int loadId = 0;
    id = event->GetInnerEventId();
    TELEPHONY_LOGI("SimDiallingNumbersHandler ProcessEvent ----%{public}d", id);

    switch (id) {
        case MSG_SIM_OBTAIN_LINEAR_FILE_SIZE_COMPLETED:
            ProcessLinearSizeDone(event, loadId);
            break;
        case MSG_SIM_RENEW_ADN_COMPLETED:
            ProcessUpdateRecordDone(event, loadId);
            break;
        case MSG_SIM_OBTAIN_ADN_COMPLETED:
            ProcessDiallingNumberLoadDone(event, loadId);
            break;
        case MSG_SIM_OBTAIN_EXTRA_FILE_COMPLETED:
            ProcessExtRecordLoadDone(event, loadId);
            break;
        case MSG_SIM_OBTAIN_ALL_ADN_COMPLETED:
            ProcessDiallingNumberAllLoadDone(event, loadId);
            break;
        default:
            break;
    }
    SendBackResult(loadId);
}

void SimDiallingNumbersHandler::ProcessLinearSizeDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    std::unique_ptr<ControllerToFileMsg> fdError = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = 0;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    if (fdError != nullptr) {
        loadId = fdError->arg1;
        id = loadId;
        loadRequest = FindLoadRequest(loadId);
        loadRequest->exception = fdError->exception;
        TELEPHONY_LOGE("ProcessLinearSizeDone error occured");
        return;
    }

    std::shared_ptr<EfLinearResult> object = event->GetSharedObject<EfLinearResult>();
    std::shared_ptr<DiallingNumbersInfo> diallingNumberLoad = nullptr;
    loadId = object->arg1;
    id = loadId;
    loadRequest = FindLoadRequest(loadId);
    if (object != nullptr) {
        if (object->exception == nullptr) {
            std::shared_ptr<void> baseLoad = object->iccLoader;
            int *dataSize = object->valueData;
            // 2 is filenum, 1 is total filelength  0 * 2 = 1
            if (loadRequest->recordNumber > dataSize[SIZE_POS]) {
                TELEPHONY_LOGE("get wrong EF record size format");
            }
            if (baseLoad != nullptr) {
                diallingNumberLoad = std::static_pointer_cast<DiallingNumbersInfo>(baseLoad);
            }
            if (!FormatNameAndNumber(diallingNumberLoad)) {
                loadRequest->exception = static_cast<std::shared_ptr<void>>(MakeExceptionResult(PARAMETER_INCORRECT));
                return;
            }
            int dataLen = dataSize[0]; // 0 is file length
            dataLen = RECORD_LENGTH;
            std::shared_ptr<unsigned char> dataDiallingNumber = CreateSavingSequence(diallingNumberLoad, dataLen);
            if (dataDiallingNumber == nullptr) {
                TELEPHONY_LOGE("wrong ADN format");
                loadRequest->exception = static_cast<std::shared_ptr<void>>(MakeExceptionResult(0));
                return;
            }
            TELEPHONY_LOGI("DNIHandler::ProcessLinearSizeDone start!! %{public}d %{public}d", dataLen, dataSize[0]);
            std::string data = SIMUtils::BytesConvertToHexString(dataDiallingNumber.get(), dataLen);
            AppExecFwk::InnerEvent::Pointer event =
                CreatePointer(MSG_SIM_RENEW_ADN_COMPLETED, diallingNumberLoad, loadId);
            fileController_->UpdateLinearFixedFile(loadRequest->ef, GetEFPath(loadRequest->ef),
                loadRequest->recordNumber, data, dataLen, loadRequest->pin2, event);
            loadRequest->pendingExtLoads = 1;
        }
    } else {
        TELEPHONY_LOGE("ProcessLinearSizeDone: get null pointer!!!");
    }
}

void SimDiallingNumbersHandler::ProcessUpdateRecordDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    std::unique_ptr<ControllerToFileMsg> object = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = object->arg1;
    id = loadId;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    loadRequest->pendingExtLoads = 0;
    loadRequest->exception = object->exception;
    if (loadRequest->exception == nullptr) {
        loadRequest->result = object->iccLoader;
    }
}

void SimDiallingNumbersHandler::ProcessDiallingNumberAllLoadDone(
    const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    std::unique_ptr<ControllerToFileMsg> fdError = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = 0;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    if (fdError != nullptr) {
        loadId = fdError->arg1;
        id = loadId;
        loadRequest = FindLoadRequest(loadId);
        loadRequest->exception = fdError->exception;
        TELEPHONY_LOGE("ProcessDiallingNumberAllLoadDone error occured");
        return;
    }

    std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
    loadId = object->arg1;
    id = loadId;
    loadRequest = FindLoadRequest(loadId);

    if (object->exception != nullptr) {
        TELEPHONY_LOGE("ProcessDiallingNumberAllLoadDone load failed");
        loadRequest->exception = object->exception;
        return;
    }
    loadRequest->pendingExtLoads = 0;
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
        std::make_shared<std::vector<std::shared_ptr<DiallingNumbersInfo>>>();
    loadRequest->result = static_cast<std::shared_ptr<void>>(diallingNumberList);
    std::vector<std::string> &dataList = object->fileResults;
    TELEPHONY_LOGI("ProcessDiallingNumberAllLoadDone start: %{public}zu", dataList.size());
    int i = 0;
    for (std::vector<std::string>::iterator it = dataList.begin(); it != dataList.end(); it++, i++) {
        std::string item = *it;
        TELEPHONY_LOGI("diallingNumberdata item: %{public}s", item.c_str());
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(loadRequest->ef, 1 + i);
        FetchDiallingNumberContent(diallingNumber, item);
        diallingNumberList->push_back(diallingNumber);
        if (diallingNumber->HasExtendedRecord()) {
            TELEPHONY_LOGI("alldiallingNumber start load extend...");
            loadRequest->pendingExtLoads++;
            AppExecFwk::InnerEvent::Pointer event =
                CreatePointer(MSG_SIM_OBTAIN_EXTRA_FILE_COMPLETED, diallingNumber, loadId);
            fileController_->ObtainLinearFixedFile(loadRequest->extensionEF, diallingNumber->extRecord_, event);
        }
    }
}

void SimDiallingNumbersHandler::ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = fd->arg1;
    id = loadId;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    if (fd->exception != nullptr) {
        loadRequest->exception = fd->exception;
        TELEPHONY_LOGE("ProcessDiallingNumberLoadDone load failed with exception");
        return;
    }

    std::string iccData = fd->resultData;
    TELEPHONY_LOGI("ProcessDiallingNumberLoadDone start: %{public}s", iccData.c_str());
    std::shared_ptr<DiallingNumbersInfo> diallingNumber =
        std::make_shared<DiallingNumbersInfo>(loadRequest->ef, loadRequest->recordNumber);
    FetchDiallingNumberContent(diallingNumber, iccData);
    loadRequest->result = static_cast<std::shared_ptr<void>>(diallingNumber);

    if (diallingNumber->HasExtendedRecord()) {
        TELEPHONY_LOGI("diallingNumber start load extend...");
        loadRequest->pendingExtLoads = 1;
        AppExecFwk::InnerEvent::Pointer event =
            CreatePointer(MSG_SIM_OBTAIN_EXTRA_FILE_COMPLETED, loadRequest->result, loadId);
        fileController_->ObtainLinearFixedFile(loadRequest->extensionEF, diallingNumber->extRecord_, event);
    }
}

void SimDiallingNumbersHandler::ProcessExtRecordLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    int loadId = fd->arg1;
    id = loadId;
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    if (fd->exception != nullptr) {
        loadRequest->exception = fd->exception;
        TELEPHONY_LOGE("ProcessExtRecordLoadDone load failed with exception");
        return;
    }

    std::string iccData = fd->resultData;
    std::shared_ptr<void> baseLoad = fd->iccLoader;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::static_pointer_cast<DiallingNumbersInfo>(baseLoad);

    if (fd->exception == nullptr) {
        AppendExtRecord(diallingNumber, iccData);
    } else {
        diallingNumber->SetNumber(u"");
        TELEPHONY_LOGE("Failed to read ext record. Clear the number now");
    }
    loadRequest->pendingExtLoads--;
}

bool SimDiallingNumbersHandler::SendBackResult(int loadId)
{
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = FindLoadRequest(loadId);
    if (loadRequest == nullptr) {
        return false;
    }
    if (loadRequest->userResponse == nullptr || loadRequest->pendingExtLoads != 0) {
        return false;
    }
    auto owner = loadRequest->userResponse->GetOwner();
    int id = loadRequest->userResponse->GetInnerEventId();
    std::unique_ptr<PbLoadHolder> fd = loadRequest->userResponse->GetUniqueObject<PbLoadHolder>();
    std::unique_ptr<PbHandlerResult> data = make_unique<PbHandlerResult>(fd.get());
    data->result = loadRequest->result;
    data->exception = loadRequest->exception;
    owner->SendEvent(id, data);
    ClearLoadRequest(loadId);
    TELEPHONY_LOGI("SimDiallingNumbersHandler::SendBackResult send end");
    return true;
}

AppExecFwk::InnerEvent::Pointer SimDiallingNumbersHandler::CreatePointer(int eventId, int loadId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->arg1 = loadId;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer SimDiallingNumbersHandler::CreatePointer(
    int eventId, std::shared_ptr<void> pobj, int loadId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->arg1 = loadId;
    object->iccLoader = pobj;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

std::shared_ptr<DiallingNumberLoadRequest> SimDiallingNumbersHandler::FindLoadRequest(int serial)
{
    std::shared_ptr<DiallingNumberLoadRequest> loadRequest = nullptr;
    auto iter = SimDiallingNumbersHandler::requestMap_.find(serial);
    if (iter == SimDiallingNumbersHandler::requestMap_.end()) {
        TELEPHONY_LOGD("FindLoadRequest not found serial:%{public}d", serial);
    } else {
        loadRequest = iter->second;
    }
    TELEPHONY_LOGD("FindLoadRequest : %{public}d", serial);
    if (loadRequest == nullptr) {
        TELEPHONY_LOGE("Unexpected diallingNumber ack response! sn: %{public}d", serial);
        return loadRequest;
    }
    return loadRequest;
}

void SimDiallingNumbersHandler::ClearLoadRequest(int serial)
{
    SimDiallingNumbersHandler::requestMap_.erase(serial);
}

void SimDiallingNumbersHandler::FetchDiallingNumberContent(
    const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, const std::string &recordData)
{
    TELEPHONY_LOGI("FetchDiallingNumberContent start: %{public}s", recordData.c_str());
    int recordLen = 0;
    std::shared_ptr<unsigned char> data = SIMUtils::HexStringConvertToBytes(recordData, recordLen);
    if (diallingNumber == nullptr || data == nullptr) {
        TELEPHONY_LOGE("FetchDiallingNumberContent null data");
        return;
    }

    unsigned char *record = data.get();
    std::string tpStrTag =
        SIMUtils::DiallingNumberStringFieldConvertToString(data, 0, recordLen - FOOTER_SIZE_BYTES, NAME_CHAR_POS);
    diallingNumber->alphaTag_ = Str8ToStr16(tpStrTag);
    int footerOffset = recordLen - FOOTER_SIZE_BYTES;
    int numberLength = 0xff & record[footerOffset];
    if (numberLength > MAX_NUMBER_SIZE_BYTES) {
        diallingNumber->number_ = u"";
        TELEPHONY_LOGE("FetchDiallingNumberContent number error: %{public}s", recordData.c_str());
        return;
    }

    std::string tpStrNumber =
        SimNumberDecode::BCDConvertToString(data, footerOffset + 1, numberLength, BCD_EXTENDED_TYPE_EF_ADN);
    diallingNumber->number_ = Str8ToStr16(tpStrNumber);
    diallingNumber->extRecord_ = 0xff & record[recordLen - 1];
    TELEPHONY_LOGI(
        "FetchDiallingNumberContent result: %{public}s %{public}s", tpStrTag.c_str(), tpStrNumber.c_str());
    std::vector<std::u16string> nullVector;
    diallingNumber->emails_.swap(nullVector);
}

void SimDiallingNumbersHandler::AppendExtRecord(
    const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, const std::string &recordData)
{
    if (diallingNumber == nullptr || recordData.empty()) {
        TELEPHONY_LOGE("AppendExtRecord null data");
        return;
    }
    int extRecordLen = recordData.size();
    const char *constData = recordData.c_str();
    char *rawData = const_cast<char *>(constData);
    unsigned char *extRecord = reinterpret_cast<unsigned char *>(rawData);
    TELEPHONY_LOGI("SimDiallingNumbersHandler::AppendExtRecord load success:%{public}s", extRecord);

    if (extRecordLen != EXT_RECORD_LENGTH_BYTES) {
        TELEPHONY_LOGE("SimDiallingNumbersHandler::AppendExtRecord length error:%{public}d", extRecordLen);
        return;
    }
    if ((extRecord[0] & EXT_RECORD_TYPE_MASK) != EXT_RECORD_TYPE_ADDITIONAL_DATA) {
        TELEPHONY_LOGE("SimDiallingNumbersHandler::AppendExtRecord type error:%{public}d", extRecord[0]);
        return;
    }

    if ((BYTE_VALUE & extRecord[1]) > MAX_EXT_CALLED_PARTY_LENGTH) {
        TELEPHONY_LOGE("SimDiallingNumbersHandler::AppendExtRecord party error:%{public}d", extRecord[1]);
        return;
    }
    std::shared_ptr<unsigned char> extRecordPac = std::shared_ptr<unsigned char>(extRecord);
    std::string str = SimNumberDecode::BCDSectionConvertToString(
        extRecordPac, DEFAULT_MNC, BYTE_VALUE & extRecord[1], BCD_EXTENDED_TYPE_EF_ADN);
    diallingNumber->number_.append(Str8ToStr16(str));
}

std::shared_ptr<unsigned char> SimDiallingNumbersHandler::CreateSavingSequence(
    const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int recordSize)
{
    std::shared_ptr<unsigned char> byteTagPac = nullptr;
    std::shared_ptr<unsigned char> diallingNumberStringPac = nullptr;
    unsigned char *byteTag = nullptr;
    unsigned char *diallingNumberString = nullptr;
    int footerOffset = recordSize - FOOTER_SIZE_BYTES;
    int byteTagLen = 0;
    if (recordSize < 0) {
        return nullptr;
    }
    unsigned char *cache = (unsigned char *)calloc(recordSize, sizeof(unsigned char));
    if (cache == nullptr) {
        return nullptr;
    }
    diallingNumberStringPac = std::shared_ptr<unsigned char>(cache);
    diallingNumberString = diallingNumberStringPac.get();
    for (int i = 0; i < recordSize; i++) {
        diallingNumberString[i] = (unsigned char)BYTE_VALUE;
    }
    std::string name = Str16ToStr8(diallingNumber->alphaTag_);
    std::string number = Str16ToStr8(diallingNumber->number_);
    TELEPHONY_LOGI("CreateSavingSequence contentsx: %{public}s %{public}s", name.c_str(), number.c_str());

    uint maxNumberSize = (ADN_DIALING_NUMBER_END - ADN_DIALING_NUMBER_START + 1) * LENGTH_RATE;
    if (diallingNumber->number_.empty()) {
        TELEPHONY_LOGE("[buildDiallingNumberstring] Empty dialing number");
        return diallingNumberStringPac;
    } else if (diallingNumber->number_.size() > maxNumberSize) {
        TELEPHONY_LOGE("[buildDiallingNumberstring] Max length of dialing number is 20");
        return nullptr;
    }
    byteTagPac = CreateNameSequence(diallingNumber->alphaTag_, byteTagLen);
    byteTag = byteTagPac.get();

    if (byteTagLen > footerOffset) {
        TELEPHONY_LOGE("[buildDiallingNumberstring] Max length of tag is %{public}d", footerOffset);
        return nullptr;
    } else {
        std::string tpNum = Str16ToStr8(diallingNumber->number_);
        FillNumberFiledForDiallingNumber(diallingNumberStringPac, tpNum, recordSize);
        if (byteTagLen > 0) {
            SIMUtils::ArrayCopy(byteTag, 0, diallingNumberString, 0, byteTagLen);
        }
        TELEPHONY_LOGI("CreateSavingSequence result: %{public}d  %{public}s", byteTagLen, diallingNumberString);
        return diallingNumberStringPac;
    }
}

void SimDiallingNumbersHandler::FillNumberFiledForDiallingNumber(
    std::shared_ptr<unsigned char> diallingNumber, const std::string &number, int recordSize)
{
    if (diallingNumber == nullptr) {
        return;
    }
    unsigned char *diallingNumberString = diallingNumber.get();
    std::shared_ptr<unsigned char> bcdNumberPac = nullptr;
    unsigned char *bcdNumber = nullptr;
    int bcdNumberLen = 0;
    int footerOffset = recordSize - FOOTER_SIZE_BYTES;

    bcdNumberPac = SimNumberDecode::NumberConvertToBCD(number, BCD_EXTENDED_TYPE_EF_ADN, bcdNumberLen);
    bcdNumber = bcdNumberPac.get();
    TELEPHONY_LOGI("number encode result %{public}s  %{public}d", bcdNumber, bcdNumberLen);
    SIMUtils::ArrayCopy(bcdNumber, 0, diallingNumberString, footerOffset + ADN_TON_AND_NPI, bcdNumberLen);
    diallingNumberString[footerOffset + ADN_BCD_NUMBER_LENGTH] = (unsigned char)(bcdNumberLen);
    diallingNumberString[footerOffset + ADN_CAPABILITY_ID] = (unsigned char)BYTE_VALUE;
    diallingNumberString[footerOffset + ADN_EXTENSION_ID] = (unsigned char)BYTE_VALUE;
}

std::shared_ptr<unsigned char> SimDiallingNumbersHandler::CreateNameSequence(
    const std::u16string &name, int &seqLength)
{
    std::string tpTag = Str16ToStr8(name);
    std::shared_ptr<unsigned char> seqResult = nullptr;
    if (SimCharDecode::IsChineseString(tpTag)) {
        std::string sq = SimCharDecode::CharCodeToSequence(name, true);
        seqResult = SIMUtils::HexStringConvertToBytes(sq, seqLength);
        TELEPHONY_LOGI("chinese alphabet encode result %{public}s %{public}d", sq.c_str(), seqLength);
    } else {
        std::string sq = SimCharDecode::CharCodeToSequence(tpTag, false);
        seqResult = SIMUtils::HexStringConvertToBytes(sq, seqLength);
        TELEPHONY_LOGI("english alphabet encode result %{public}s %{public}d", sq.c_str(), seqLength);
    }
    return seqResult;
}

bool SimDiallingNumbersHandler::FormatNameAndNumber(std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::string &&name = Str16ToStr8(diallingNumber->alphaTag_);
    std::string &&number = Str16ToStr8(diallingNumber->number_);

    uint nameMaxNum = SimCharDecode::IsChineseString(name) ? MAX_CHINESE_NAME : MAX_ENGLISH_NAME;
    if (name.size() > nameMaxNum) {
        diallingNumber->alphaTag_ = Str8ToStr16(name.substr(0, nameMaxNum));
    }

    uint numberMaxNum = MAX_NUMBER_CHAR;
    if (number.size() > numberMaxNum) {
        std::string tpNum = number.substr(0, numberMaxNum);
        if (SimNumberDecode::IsValidNumberString(tpNum)) {
            diallingNumber->number_ = Str8ToStr16(tpNum);
        } else {
            TELEPHONY_LOGE("invalid number full string  %{public}s", number.c_str());
            return false;
        }
    } else {
        if (!SimNumberDecode::IsValidNumberString(number)) {
            TELEPHONY_LOGE("invalid number string  %{public}s", number.c_str());
            return false;
        }
    }
    return true;
}

std::shared_ptr<HRilRadioResponseInfo> SimDiallingNumbersHandler::MakeExceptionResult(int code)
{
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = std::make_shared<HRilRadioResponseInfo>();
    responseInfo->error = static_cast<Telephony::HRilErrType>(code);
    return responseInfo;
}

SimDiallingNumbersHandler::~SimDiallingNumbersHandler() {}
} // namespace Telephony
} // namespace OHOS

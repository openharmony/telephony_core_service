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
#include "icc_file_controller.h"
using namespace std;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace SIM {
IccFileController::IccFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : AppExecFwk::EventHandler(runner)
{}

void IccFileController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    id = event->GetInnerEventId();
    TELEPHONY_INFO_LOG("IccFileController ProcessEvent Id is %{public}d", id);
    switch (id) {
        case MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE:
            ProcessLinearRecordSize(event);
            break;
        case MSG_SIM_OBTAIN_SIZE_OF_FIXED_ELEMENTARY_FILE_DONE:
            ProcessRecordSize(event);
            break;
        case MSG_SIM_OBTAIN_SIZE_OF_TRANSPARENT_ELEMENTARY_FILE_DONE:
            ProcessBinarySize(event);
            break;
        case MSG_SIM_OBTAIN_FIXED_ELEMENTARY_FILE_DONE:
            ProcessReadRecord(event);
            break;
        case MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE:
            ProcessReadBinary(event);
            break;
        default:
            break;
    }
}

void IccFileController::ProcessLinearRecordSize(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string str = NULLSTR;
    std::string path = NULLSTR;
    auto eventId = event->GetInnerEventId();
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    const AppExecFwk::InnerEvent::Pointer &response = rcvMsg->controlHolder->fileLoaded;
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> &hd = rcvMsg->controlHolder;
    path = hd->filePath;
    const char *cdata = (result->resultData).c_str();
    char *pdata = const_cast<char *>(cdata);
    unsigned char *data = reinterpret_cast<unsigned char *>(pdata); // for unsigned int bitwise

    if (IsValidSizeData(data)) {
        int fileSize[] = {0, 0, 0};
        ParseFileSize(fileSize, RECORD_NUM, data);
        SendEfLinearResult(response, fileSize, RECORD_NUM);
    } else {
        TELEPHONY_INFO_LOG("IccFileTypeMismatch --%d", eventId);
    }
}

void IccFileController::ProcessRecordSize(const AppExecFwk::InnerEvent::Pointer &event)
{
    int size = 0;
    std::string str = NULLSTR;
    std::string path = NULLSTR;
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> &hd = rcvMsg->controlHolder;
    const char *cdata = (result->resultData).c_str();
    char *pdata = const_cast<char *>(cdata);
    unsigned char *data = reinterpret_cast<unsigned char *>(pdata); // for unsigned int bitwise

    path = hd->filePath;
    if (path.empty()) {
        path = ObtainElementFilePath(hd->fileId);
    }
    if (!IsValidSizeData(data)) {
        return;
    }
    GetFileAndDataSize(data, hd->fileSize, size);
    if (hd->fileSize != 0) {
        hd->countFiles = size / hd->fileSize;
    }
    if (hd->getAll) {
        hd->fileResults.resize(hd->countFiles);
    }
    rilManager_->ReadIccFile(CONTROLLER_REQ_READ_RECORD, hd->fileId, path, hd->fileNum, ICC_FILE_CURRENT_MODE,
        hd->fileSize, NULLSTR, NULLSTR, aid_, CreatePointer(MSG_SIM_OBTAIN_FIXED_ELEMENTARY_FILE_DONE, hd));
}

void IccFileController::ProcessBinarySize(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string str = NULLSTR;
    std::string path = NULLSTR;
    TELEPHONY_INFO_LOG("IccFileController::ProcessBinarySize init--");
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    bool isNull = rcvMsg->controlHolder == nullptr;
    TELEPHONY_INFO_LOG("IccFileController::ProcessBinarySize get point--%{public}d", isNull);
    const AppExecFwk::InnerEvent::Pointer &evt = rcvMsg->controlHolder->fileLoaded;
    isNull = evt->GetOwner() == nullptr;
    TELEPHONY_INFO_LOG("IccFileController::ProcessBinarySize prepare--%{public}d", isNull);
    int fileId = rcvMsg->arg1;
    int size = 0;
    AppExecFwk::InnerEvent::Pointer response =
        CreatePointer(MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE, fileId, 0, evt);
    rilManager_->ReadIccFile(CONTROLLER_REQ_READ_BINARY, fileId, ObtainElementFilePath(fileId), 0, 0, size,
        NULLSTR, NULLSTR, aid_, response);
    TELEPHONY_INFO_LOG("IccFileController::ProcessBinarySize finish--%{public}d", fileId);
}

void IccFileController::ProcessReadRecord(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string str = NULLSTR;
    std::string path = NULLSTR;
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    const AppExecFwk::InnerEvent::Pointer &response = rcvMsg->controlHolder->fileLoaded;
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> &hd = rcvMsg->controlHolder;
    path = hd->filePath;
    if (path.empty()) {
        path = ObtainElementFilePath(hd->fileId);
    }

    if (hd->getAll) {
        hd->fileResults.push_back(result->resultData);
        hd->fileNum++;
        if (hd->fileNum > hd->countFiles) {
            SendMultiRecordResult(response, hd->fileResults);
        } else {
            rilManager_->ReadIccFile(CONTROLLER_REQ_READ_RECORD, hd->fileId, path, hd->fileNum,
                ICC_FILE_CURRENT_MODE, hd->fileSize, NULLSTR, NULLSTR, aid_,
                CreatePointer(MSG_SIM_OBTAIN_FIXED_ELEMENTARY_FILE_DONE, hd));
        }
    } else {
        SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
    }
}

void IccFileController::ProcessReadBinary(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_INFO_LOG("IccFileController MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE");
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
}

std::string IccFileController::GetCommonElementFilePath(int efId)
{
    std::string mf = MASTER_FILE_SIM;
    switch (efId) {
        case ELEMENTARY_FILE_ADN:
        case ELEMENTARY_FILE_FDN:
        case ELEMENTARY_FILE_MSISDN:
        case ELEMENTARY_FILE_SDN:
        case ELEMENTARY_FILE_EXT1:
        case ELEMENTARY_FILE_EXT2:
        case ELEMENTARY_FILE_EXT3:
        case ELEMENTARY_FILE_PSI:
            mf.append(DEDICATED_FILE_TELECOM);
            return mf;
        case ELEMENTARY_FILE_ICCID:
        case ELEMENTARY_FILE_PL:
            return mf;
        case ELEMENTARY_FILE_PBR:
            mf.append(DEDICATED_FILE_TELECOM);
            mf.append(DEDICATED_FILE_PHONEBOOK);
            return mf;
        case ELEMENTARY_FILE_IMG:
            mf.append(DEDICATED_FILE_TELECOM);
            mf.append(DEDICATED_FILE_GRAPHICS);
            return mf;
        default:
            break;
    }
    return NULLSTR;
}

// implementation GetTransparentFile
void IccFileController::GetTransparentFile(int fileId, AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_INFO_LOG("IccFileController::GetTransparentFile start");
    AppExecFwk::InnerEvent::Pointer response =
        CreatePointer(MSG_SIM_OBTAIN_SIZE_OF_TRANSPARENT_ELEMENTARY_FILE_DONE, fileId, 0, event);
    rilManager_->ReadIccFile(CONTROLLER_REQ_GET_RESPONSE, fileId, ObtainElementFilePath(fileId), 0, 0,
        GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES, NULLSTR, NULLSTR, aid_, response);
    TELEPHONY_INFO_LOG("IccFileController::GetTransparentFile end");
}

void IccFileController::GetTransparentFile(int fileId, int size, AppExecFwk::InnerEvent::Pointer &event)
{
    AppExecFwk::InnerEvent::Pointer response =
        CreatePointer(MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE, fileId, 0, event);
    rilManager_->ReadIccFile(CONTROLLER_REQ_READ_BINARY, fileId, ObtainElementFilePath(fileId), 0, 0, size,
        NULLSTR, NULLSTR, aid_, response);
}

void IccFileController::GetTransparentFile(int fileId, std::string path, AppExecFwk::InnerEvent::Pointer &event)
{
    SendResponse(nullptr, nullptr);
}

// implementation GetFixedLinearFile
void IccFileController::GetFixedLinearFile(
    int fileId, std::string path, int fileNum, AppExecFwk::InnerEvent::Pointer &event)
{
    std::string efPath = (path.empty()) ? ObtainElementFilePath(fileId) : path;
    std::shared_ptr<IccControllerHolder> ctrlHolder =
        std::make_shared<IccControllerHolder>(fileId, fileNum, efPath);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(event));
    AppExecFwk::InnerEvent::Pointer response =
        CreatePointer(MSG_SIM_OBTAIN_SIZE_OF_FIXED_ELEMENTARY_FILE_DONE, ctrlHolder);
    rilManager_->ReadIccFile(CONTROLLER_REQ_GET_RESPONSE, fileId, efPath, 0, 0,
        GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES, NULLSTR, NULLSTR, aid_, response);
}

void IccFileController::GetFixedLinearFile(int fileId, int fileNum, AppExecFwk::InnerEvent::Pointer &event)
{
    GetFixedLinearFile(fileId, ObtainElementFilePath(fileId), fileNum, event);
}

// implementation GetAllFixedLinearFile
void IccFileController::GetAllFixedLinearFile(int fileId, std::string path, AppExecFwk::InnerEvent::Pointer &event)
{
    std::string efPath = (path.empty()) ? ObtainElementFilePath(fileId) : path;
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId, efPath);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(event));
    AppExecFwk::InnerEvent::Pointer response =
        CreatePointer(MSG_SIM_OBTAIN_SIZE_OF_FIXED_ELEMENTARY_FILE_DONE, ctrlHolder);
    rilManager_->ReadIccFile(CONTROLLER_REQ_GET_RESPONSE, fileId, efPath, 0, 0,
        GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES, NULLSTR, NULLSTR, aid_, response);
}

void IccFileController::GetAllFixedLinearFile(int fileId, AppExecFwk::InnerEvent::Pointer &event)
{
    GetAllFixedLinearFile(fileId, ObtainElementFilePath(fileId), event);
}

void IccFileController::GetAllFixedLinearFile(int fileId, AppExecFwk::InnerEvent::Pointer &event, bool dedicated)
{
    SendResponse(nullptr, nullptr);
}

void IccFileController::GetAllFixedLinearFile(int fileId, int mode, AppExecFwk::InnerEvent::Pointer &event)
{
    SendResponse(nullptr, nullptr);
}

void IccFileController::GetLinearFileSize(int fileId, std::string path, AppExecFwk::InnerEvent::Pointer &event)
{
    std::string efPath = (path.empty()) ? ObtainElementFilePath(fileId) : path;
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId, efPath);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(event));
    AppExecFwk::InnerEvent::Pointer response =
        CreatePointer(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE, ctrlHolder);
    rilManager_->ReadIccFile(CONTROLLER_REQ_GET_RESPONSE, fileId, efPath, 0, 0,
        GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES, NULLSTR, NULLSTR, aid_, response);
}

void IccFileController::GetLinearFileSize(int fileId, AppExecFwk::InnerEvent::Pointer &event)
{
    GetLinearFileSize(fileId, ObtainElementFilePath(fileId), event);
}

void IccFileController::UpdateFixedLinearFile(int fileId, std::string path, int fileNum, std::string data,
    int dataLength, std::string pin2, AppExecFwk::InnerEvent::Pointer &onComplete)
{
    std::string efPath = (path.empty()) ? ObtainElementFilePath(fileId) : path;
    rilManager_->ReadIccFile(CONTROLLER_REQ_UPDATE_RECORD, fileId, efPath, fileNum, ICC_FILE_CURRENT_MODE,
        dataLength, data, pin2, aid_, onComplete);
}

void IccFileController::UpdateFixedLinearFile(int fileId, int fileNum, std::string data, int dataLength,
    std::string pin2, AppExecFwk::InnerEvent::Pointer &onComplete)
{
    rilManager_->ReadIccFile(CONTROLLER_REQ_UPDATE_RECORD, fileId, ObtainElementFilePath(fileId), fileNum,
        ICC_FILE_CURRENT_MODE, dataLength, data, pin2, aid_, onComplete);
}

void IccFileController::UpdateTransparentFile(
    int fileId, std::string data, int dataLength, AppExecFwk::InnerEvent::Pointer &onComplete)
{
    rilManager_->ReadIccFile(CONTROLLER_REQ_UPDATE_BINARY, fileId, ObtainElementFilePath(fileId), 0, 0, dataLength,
        data, NULLSTR, aid_, onComplete);
}

void IccFileController::SendResponse(std::shared_ptr<IccControllerHolder> holder, const IccFileData *fd)
{
    if (holder == nullptr || fd == nullptr) {
        TELEPHONY_ERR_LOG("IccFileController::SendResponse  result is null");
        return;
    }
    AppExecFwk::InnerEvent::Pointer &response = holder->fileLoaded;
    bool isNull = response == nullptr;
    TELEPHONY_INFO_LOG("IccFileController::SendResponse start response %{public}d", isNull);
    auto owner = response->GetOwner();
    std::unique_ptr<IccFileData> object = std::make_unique<IccFileData>();
    if (object == nullptr) {
        TELEPHONY_ERR_LOG("IccFileController::SendResponse  create IccFileData is null");
        return;
    }
    object->sw1 = fd->sw1;
    object->sw2 = fd->sw2;
    object->resultData = fd->resultData;
    int id = response->GetInnerEventId();
    int eventParam = 0;
    isNull = owner == nullptr;
    TELEPHONY_INFO_LOG("IccFileController::SendResponse owner: %{public}d evtId: %{public}d--", isNull, id);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(id, object, eventParam);
    owner->SendEvent(event);
    TELEPHONY_INFO_LOG("IccFileController::SendResponse send end");
}

void IccFileController::SendEfLinearResult(
    const AppExecFwk::InnerEvent::Pointer &response, const int val[], int len)
{
    std::shared_ptr<AppExecFwk::EventHandler> hanler = response->GetOwner();
    std::shared_ptr<EfLinearResult> object = std::make_shared<EfLinearResult>();
    object->valueData[0] = val[0];
    object->valueData[1] = val[1];
    object->valueData[MAX_FILE_INDEX] = val[MAX_FILE_INDEX];
    int id = response->GetInnerEventId();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(id, object, eventParam);
    hanler->SendEvent(event);
}

void IccFileController::SendMultiRecordResult(
    const AppExecFwk::InnerEvent::Pointer &response, std::vector<std::string> &strValue)
{
    std::shared_ptr<AppExecFwk::EventHandler> hanler = response->GetOwner();
    std::shared_ptr<MultiRecordResult> object = std::make_shared<MultiRecordResult>();
    object->fileResults.assign(strValue.begin(), strValue.end());
    object->resultLength = strValue.size();
    int id = response->GetInnerEventId();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(id, object, eventParam);
    hanler->SendEvent(event);
}

AppExecFwk::InnerEvent::Pointer IccFileController::CreatePointer(
    int eventId, std::shared_ptr<IccControllerHolder> &holderObject)
{
    std::unique_ptr<IccToRilMsg> msgTo = std::make_unique<IccToRilMsg>(holderObject);
    if (msgTo == nullptr) {
        TELEPHONY_ERR_LOG("IccFileController::CreatePointer1  create null poniter");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    int64_t eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, msgTo, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFileController::CreatePointer(
    int eventId, int arg1, int arg2, std::shared_ptr<IccControllerHolder> &holderObject)
{
    std::unique_ptr<IccToRilMsg> msgTo = std::make_unique<IccToRilMsg>(holderObject);
    if (msgTo == nullptr) {
        TELEPHONY_ERR_LOG("IccFileController::CreatePointer2  create null poniter");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    msgTo->arg1 = arg1;
    msgTo->arg2 = arg2;
    int64_t eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, msgTo, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFileController::CreatePointer(
    int eventId, int arg1, int arg2, const AppExecFwk::InnerEvent::Pointer &msg)
{
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(arg1);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(msg));
    bool isNull = ctrlHolder->fileLoaded->GetOwner() == nullptr;
    TELEPHONY_INFO_LOG("IccFileController::CreatePointer stage init owner: %{public}d", isNull);
    std::unique_ptr<IccToRilMsg> msgTo = std::make_unique<IccToRilMsg>(ctrlHolder);
    if (msgTo == nullptr) {
        TELEPHONY_ERR_LOG("IccFileController::CreatePointer3  create null poniter");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    TELEPHONY_INFO_LOG("IccFileController::CreatePointer stage end");
    msgTo->arg1 = arg1;
    msgTo->arg2 = arg2;
    int64_t eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, msgTo, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

void IccFileController::ParseFileSize(int val[], int len, const unsigned char *data)
{
    if (len > MAX_FILE_INDEX) {
        GetFileAndDataSize(data, val[0], val[1]);
        val[MAX_FILE_INDEX] = val[1] / val[0];
    }
}
bool IccFileController::IsValidSizeData(const unsigned char *data)
{
    if (ICC_ELEMENTARY_FILE != data[TYPE_OF_FILE]) {
        TELEPHONY_ERR_LOG("IccFileTypeMismatch ERROR TYPE_OF_FILE");
        return false;
    }
    if (ELEMENTARY_FILE_TYPE_LINEAR_FIXED != data[STRUCTURE_OF_DATA]) {
        TELEPHONY_ERR_LOG("IccFileTypeMismatch ERROR STRUCTURE_OF_DATA");
        return false;
    }
    return true;
}
void IccFileController::GetFileAndDataSize(const unsigned char *data, int &fileSize, int &dataSize)
{
    if (data != nullptr) {
        fileSize = data[LENTH_OF_RECORD] & BYTE_NUM;
        dataSize = ((data[SIZE_ONE_OF_FILE] & BYTE_NUM) << OFFSET) + (data[SIZE_TWO_OF_FILE] & BYTE_NUM);
    }
}
void IccFileController::SetRilManager(IRilManager *ril)
{
    rilManager_ = ril;
}

IccFileController::~IccFileController() {}
} // namespace SIM
} // namespace OHOS

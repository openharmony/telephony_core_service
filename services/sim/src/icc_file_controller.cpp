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
namespace Telephony {
IccFileController::IccFileController(const std::string &name, int slotId) : TelEventHandler(name), slotId_(slotId) {}

void IccFileController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    uint32_t id = event->GetInnerEventId();
    TELEPHONY_LOGD("IccFileController ProcessEvent Id is %{public}d", id);
    if (ProcessErrorResponse(event)) {
        return;
    }
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
        case MSG_SIM_OBTAIN_ICON_DONE:
        case MSG_SIM_UPDATE_LINEAR_FIXED_FILE_DONE:
        case MSG_SIM_UPDATE_TRANSPARENT_ELEMENTARY_FILE_DONE:
        case MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE:
            ProcessReadBinary(event);
            break;
        default:
            break;
    }
}

void IccFileController::ProcessLinearRecordSize(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> hd = rcvMsg->controlHolder;
    if (result == nullptr || hd == nullptr) {
        TELEPHONY_LOGE("result or hd is nullptr");
        return;
    }
    const AppExecFwk::InnerEvent::Pointer &process = hd->fileLoaded;
    TELEPHONY_LOGI("ProcessLinearRecordSize --- resultData: --- %{public}s", result->resultData.c_str());
    int recordLen = 0;
    int fileSize[] = { 0, 0, 0 };
    std::shared_ptr<unsigned char> rawData = SIMUtils::HexStringConvertToBytes(result->resultData, recordLen);
    if (recordLen > LENGTH_OF_RECORD) {
        unsigned char *fileData = rawData.get();
        ParseFileSize(fileSize, RECORD_NUM, fileData);
    }
    SendEfLinearResult(process, fileSize, RECORD_NUM);
}

void IccFileController::ProcessRecordSize(const AppExecFwk::InnerEvent::Pointer &event)
{
    int size = 0;
    std::string str = IccFileController::NULLSTR;
    std::string path = IccFileController::NULLSTR;
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> hd = rcvMsg->controlHolder;
    if (result == nullptr || hd == nullptr) {
        TELEPHONY_LOGE("result or hd is nullptr");
        return;
    }
    TELEPHONY_LOGI("ProcessRecordSize --- resultData: --- %{public}s", result->resultData.c_str());
    int recordLen = 0;
    std::shared_ptr<unsigned char> rawData = SIMUtils::HexStringConvertToBytes(result->resultData, recordLen);
    if (rawData == nullptr) {
        TELEPHONY_LOGE("rawData is nullptr");
        SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
        return;
    }
    unsigned char *fileData = rawData.get();
    path = CheckRightPath(hd->filePath, hd->fileId);
    if (recordLen > LENGTH_OF_RECORD) {
        if (!IsValidRecordSizeData(fileData)) {
            TELEPHONY_LOGE("ProcessRecordSize get error filetype");
            SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
            return;
        }
        GetFileAndDataSize(fileData, hd->fileSize, size);
        if (hd->fileSize != 0) {
            hd->countFiles = size / hd->fileSize;
        }
    }
    TELEPHONY_LOGI("ProcessRecordSize fileId:%{public}d %{public}d %{public}d %{public}d", hd->fileId, size,
        hd->fileSize, hd->countFiles);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_READ_RECORD;
        msg.fileId = hd->fileId;
        msg.p1 = hd->fileNum;
        msg.p2 = ICC_FILE_CURRENT_MODE;
        msg.p3 = hd->fileSize;
        msg.data = IccFileController::NULLSTR;
        msg.path = path;
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, BuildCallerInfo(MSG_SIM_OBTAIN_FIXED_ELEMENTARY_FILE_DONE, hd));
    }
}

void IccFileController::ProcessBinarySize(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string str = IccFileController::NULLSTR;
    std::string path = IccFileController::NULLSTR;
    TELEPHONY_LOGD("ProcessBinarySize init");
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> &hd = rcvMsg->controlHolder;
    if (result == nullptr || hd == nullptr) {
        TELEPHONY_LOGE("ProcessBinarySize result or hd is nullptr");
        return;
    }
    TELEPHONY_LOGI("ProcessBinarySize --- resultData: --- %{public}s", result->resultData.c_str());
    int binaryLen = 0;
    std::shared_ptr<unsigned char> rawData = SIMUtils::HexStringConvertToBytes(result->resultData, binaryLen);
    if (rawData == nullptr) {
        TELEPHONY_LOGE("ProcessBinarySize rawData is nullptr");
        SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
        return;
    }
    unsigned char *fileData = rawData.get();
    int size = 0;
    if (binaryLen > STRUCTURE_OF_DATA) {
        if (!IsValidBinarySizeData(fileData)) {
            TELEPHONY_LOGE("ProcessBinarySize get error filetype");
            SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
            return;
        }
        GetDataSize(fileData, size);
    }
    int fileId = rcvMsg->arg1;
    TELEPHONY_LOGI("ProcessBinarySize fileId:%{public}d size:%{public}d", fileId, size);
    const AppExecFwk::InnerEvent::Pointer &evt = hd->fileLoaded;
    if (evt->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ProcessBinarySize isNull is null pointer");
        return;
    }
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE, fileId, 0, evt);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_READ_BINARY;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = static_cast<int32_t>(size);
        msg.data = IccFileController::NULLSTR;
        msg.path = ObtainElementFilePath(fileId);
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::ProcessReadRecord(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string str = IccFileController::NULLSTR;
    std::string path = IccFileController::NULLSTR;
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return;
    }
    const AppExecFwk::InnerEvent::Pointer &process = rcvMsg->controlHolder->fileLoaded;
    IccFileData *result = &(rcvMsg->fileData);
    std::shared_ptr<IccControllerHolder> hd = rcvMsg->controlHolder;
    TELEPHONY_LOGI("ProcessReadRecord %{public}d %{public}d %{public}d %{public}s", hd->getAllFile, hd->fileNum,
        hd->countFiles, result->resultData.c_str());
    path = CheckRightPath(hd->filePath, hd->fileId);
    if (hd->getAllFile) {
        hd->fileResults.push_back(result->resultData);
        hd->fileNum++;
        if (hd->fileNum > hd->countFiles) {
            SendMultiRecordResult(process, hd->fileResults);
        } else {
            SimIoRequestInfo msg;
            msg.command = CONTROLLER_REQ_READ_RECORD;
            msg.fileId = hd->fileId;
            msg.p1 = hd->fileNum;
            msg.p2 = ICC_FILE_CURRENT_MODE;
            msg.p3 = hd->fileSize;
            msg.data = IccFileController::NULLSTR;
            msg.path = path;
            msg.pin2 = "";
            telRilManager_->GetSimIO(slotId_, msg, BuildCallerInfo(MSG_SIM_OBTAIN_FIXED_ELEMENTARY_FILE_DONE, hd));
        }
    } else {
        SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
    }
}

void IccFileController::ProcessReadBinary(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("IccFileController MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE");
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr || rcvMsg->controlHolder == nullptr) {
        TELEPHONY_LOGE("rcvMsg or rcvMsg->controlHolder is nullptr");
        return;
    }
    SendResponse(rcvMsg->controlHolder, &(rcvMsg->fileData));
}

std::string IccFileController::ObtainElementFileForPublic(int efId)
{
    std::string mf = MASTER_FILE_SIM;
    if (efId == ELEMENTARY_FILE_ICCID || efId == ELEMENTARY_FILE_PL) {
        return mf;
    }
    mf.append(DEDICATED_FILE_TELECOM);
    if (efId == ELEMENTARY_FILE_ADN || efId == ELEMENTARY_FILE_FDN || efId == ELEMENTARY_FILE_MSISDN ||
        efId == ELEMENTARY_FILE_SDN || efId == ELEMENTARY_FILE_EXT1 || efId == ELEMENTARY_FILE_EXT2 ||
        efId == ELEMENTARY_FILE_EXT3) {
        return mf;
    }
    if (efId == ELEMENTARY_FILE_PBR) {
        mf.append(DEDICATED_FILE_DIALLING_NUMBERS);
        return mf;
    }
    if (efId == ELEMENTARY_FILE_IMG) {
        mf.append(DEDICATED_FILE_GRAPHICS);
        return mf;
    }
    return IccFileController::NULLSTR;
}

// implementation ObtainBinaryFile
void IccFileController::ObtainBinaryFile(int fileId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("IccFileController::ObtainBinaryFile start");
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_OBTAIN_SIZE_OF_TRANSPARENT_ELEMENTARY_FILE_DONE, fileId, 0, event);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_GET_RESPONSE;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES;
        msg.data = IccFileController::NULLSTR;
        msg.path = ObtainElementFilePath(fileId);
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
    TELEPHONY_LOGD("IccFileController::ObtainBinaryFile end");
}

void IccFileController::ObtainBinaryFile(int fileId, int size, const AppExecFwk::InnerEvent::Pointer &event)
{
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_OBTAIN_TRANSPARENT_ELEMENTARY_FILE_DONE, fileId, 0, event);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_READ_BINARY;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = size;
        msg.data = IccFileController::NULLSTR;
        msg.path = ObtainElementFilePath(fileId);
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

// implementation ObtainLinearFixedFile
void IccFileController::ObtainLinearFixedFile(
    int fileId, const std::string &path, int fileNum, const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string filePath = CheckRightPath(path, fileId);
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId, fileNum, filePath);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(event));
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_OBTAIN_SIZE_OF_FIXED_ELEMENTARY_FILE_DONE, ctrlHolder);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_GET_RESPONSE;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES;
        msg.data = IccFileController::NULLSTR;
        msg.path = filePath;
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::ObtainLinearFixedFile(int fileId, int fileNum, const AppExecFwk::InnerEvent::Pointer &event)
{
    ObtainLinearFixedFile(fileId, ObtainElementFilePath(fileId), fileNum, event);
}

// implementation ObtainAllLinearFixedFile
void IccFileController::ObtainAllLinearFixedFile(
    int fileId, const std::string &path, const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string filePath = CheckRightPath(path, fileId);
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId, filePath);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(event));
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_OBTAIN_SIZE_OF_FIXED_ELEMENTARY_FILE_DONE, ctrlHolder);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_GET_RESPONSE;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES;
        msg.data = IccFileController::NULLSTR;
        msg.path = filePath;
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::ObtainAllLinearFixedFile(int fileId, const AppExecFwk::InnerEvent::Pointer &event)
{
    ObtainAllLinearFixedFile(fileId, ObtainElementFilePath(fileId), event);
}

void IccFileController::ObtainLinearFileSize(
    int fileId, const std::string &path, const AppExecFwk::InnerEvent::Pointer &event)
{
    std::string filePath = CheckRightPath(path, fileId);
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId, filePath);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(event));
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_OBTAIN_SIZE_OF_LINEAR_ELEMENTARY_FILE_DONE, ctrlHolder);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_GET_RESPONSE;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = GET_RESPONSE_ELEMENTARY_FILE_SIZE_BYTES;
        msg.data = IccFileController::NULLSTR;
        msg.path = filePath;
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::ObtainLinearFileSize(int fileId, const AppExecFwk::InnerEvent::Pointer &event)
{
    ObtainLinearFileSize(fileId, ObtainElementFilePath(fileId), event);
}

void IccFileController::UpdateLinearFixedFile(int fileId, const std::string &path, int fileNum, std::string data,
    int dataLength, const std::string pin2, const AppExecFwk::InnerEvent::Pointer &onComplete)
{
    std::string filePath = CheckRightPath(path, fileId);
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(onComplete));
    AppExecFwk::InnerEvent::Pointer process = BuildCallerInfo(MSG_SIM_UPDATE_LINEAR_FIXED_FILE_DONE, ctrlHolder);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_UPDATE_RECORD;
        msg.fileId = fileId;
        msg.p1 = fileNum;
        msg.p2 = ICC_FILE_CURRENT_MODE;
        msg.p3 = dataLength;
        msg.data = data;
        msg.path = filePath;
        msg.pin2 = pin2;
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::UpdateLinearFixedFile(int fileId, int fileNum, const std::string data, int dataLength,
    const std::string pin2, const AppExecFwk::InnerEvent::Pointer &onComplete)
{
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(onComplete));
    AppExecFwk::InnerEvent::Pointer process = BuildCallerInfo(MSG_SIM_UPDATE_LINEAR_FIXED_FILE_DONE, ctrlHolder);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_UPDATE_RECORD;
        msg.fileId = fileId;
        msg.p1 = fileNum;
        msg.p2 = ICC_FILE_CURRENT_MODE;
        msg.p3 = dataLength;
        msg.data = data;
        msg.path = ObtainElementFilePath(fileId);
        msg.pin2 = pin2;
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::UpdateBinaryFile(
    int fileId, const std::string data, int dataLength, const AppExecFwk::InnerEvent::Pointer &onComplete)
{
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(fileId);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(onComplete));
    AppExecFwk::InnerEvent::Pointer process =
        BuildCallerInfo(MSG_SIM_UPDATE_TRANSPARENT_ELEMENTARY_FILE_DONE, ctrlHolder);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_UPDATE_BINARY;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = dataLength;
        msg.data = data;
        msg.path = ObtainElementFilePath(fileId);
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, process);
    }
}

void IccFileController::SendResponse(std::shared_ptr<IccControllerHolder> holder, const IccFileData *fd)
{
    if (holder == nullptr || fd == nullptr) {
        TELEPHONY_LOGE("IccFileController::SendResponse  result is null");
        return;
    }
    AppExecFwk::InnerEvent::Pointer &response = holder->fileLoaded;
    bool isNull = (response == nullptr);
    auto owner = response->GetOwner();
    if (owner == nullptr) {
        TELEPHONY_LOGE("owner is nullptr");
        return;
    }
    std::unique_ptr<FileToControllerMsg> cmdData = response->GetUniqueObject<FileToControllerMsg>();
    uint32_t id = response->GetInnerEventId();
    bool needShare = (id == MSG_SIM_OBTAIN_ICC_FILE_DONE);
    std::unique_ptr<ControllerToFileMsg> objectUnique = nullptr;
    std::shared_ptr<ControllerToFileMsg> objectShare = nullptr;
    TELEPHONY_LOGD("IccFileController::SendResponse start response %{public}d %{public}d", isNull, needShare);
    if (needShare) {
        objectShare = std::make_shared<ControllerToFileMsg>(cmdData.get(), fd);
    } else {
        objectUnique = std::make_unique<ControllerToFileMsg>(cmdData.get(), fd);
    }

    if ((objectUnique == nullptr) && (objectShare == nullptr)) {
        TELEPHONY_LOGE("IccFileController::SendResponse  create ControllerToFileMsg is null");
        return;
    }

    isNull = (owner == nullptr);
    TELEPHONY_LOGD("IccFileController::SendResponse owner: %{public}d evtId: %{public}d", isNull, id);
    SendEvent(owner, id, needShare, objectShare, objectUnique);
    TELEPHONY_LOGD("IccFileController::SendResponse send end");
}

void IccFileController::SendEfLinearResult(const AppExecFwk::InnerEvent::Pointer &response, const int val[], int len)
{
    std::shared_ptr<AppExecFwk::EventHandler> handler = response->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("handler is nullptr!");
        return;
    }
    std::unique_ptr<FileToControllerMsg> cmdData = response->GetUniqueObject<FileToControllerMsg>();
    std::shared_ptr<EfLinearResult> object = std::make_shared<EfLinearResult>(cmdData.get());
    object->valueData[0] = val[0];
    object->valueData[1] = val[1];
    object->valueData[MAX_FILE_INDEX] = val[MAX_FILE_INDEX];
    uint32_t id = response->GetInnerEventId();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(id, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    TelEventHandler::SendTelEvent(handler, event);
}

void IccFileController::SendMultiRecordResult(
    const AppExecFwk::InnerEvent::Pointer &response, std::vector<std::string> &strValue)
{
    std::shared_ptr<AppExecFwk::EventHandler> handler = response->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("handler is nullptr!");
        return;
    }
    std::unique_ptr<FileToControllerMsg> cmdData = response->GetUniqueObject<FileToControllerMsg>();
    std::shared_ptr<MultiRecordResult> object = std::make_shared<MultiRecordResult>(cmdData.get());
    object->fileResults.assign(strValue.begin(), strValue.end());
    object->resultLength = static_cast<int>(strValue.size());
    uint32_t id = response->GetInnerEventId();
    int eventParam = 0;
    TELEPHONY_LOGI("IccFileController::SendMultiRecordResult send end");
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(id, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    TelEventHandler::SendTelEvent(handler, event);
}

AppExecFwk::InnerEvent::Pointer IccFileController::BuildCallerInfo(
    int eventId, std::shared_ptr<IccControllerHolder> &holderObject)
{
    std::unique_ptr<IccToRilMsg> msgTo = std::make_unique<IccToRilMsg>(holderObject);
    if (msgTo == nullptr) {
        TELEPHONY_LOGE("IccFileController::BuildCallerInfo1  create null pointer");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    int64_t eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, msgTo, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFileController::BuildCallerInfo(
    int eventId, int arg1, int arg2, std::shared_ptr<IccControllerHolder> &holderObject)
{
    std::unique_ptr<IccToRilMsg> msgTo = std::make_unique<IccToRilMsg>(holderObject);
    if (msgTo == nullptr) {
        TELEPHONY_LOGE("IccFileController::BuildCallerInfo2  create null pointer");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    msgTo->arg1 = arg1;
    msgTo->arg2 = arg2;
    int64_t eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, msgTo, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFileController::BuildCallerInfo(
    int eventId, int arg1, int arg2, const AppExecFwk::InnerEvent::Pointer &msg)
{
    std::shared_ptr<IccControllerHolder> ctrlHolder = std::make_shared<IccControllerHolder>(arg1);
    ctrlHolder->fileLoaded = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(msg));
    bool isNull = ctrlHolder->fileLoaded->GetOwner() == nullptr;
    TELEPHONY_LOGD("IccFileController::BuildCallerInfo stage init owner: %{public}d", isNull);
    std::unique_ptr<IccToRilMsg> msgTo = std::make_unique<IccToRilMsg>(ctrlHolder);
    if (msgTo == nullptr) {
        TELEPHONY_LOGE("IccFileController::BuildCallerInfo3  create null pointer");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    TELEPHONY_LOGD("IccFileController::BuildCallerInfo stage end");
    msgTo->arg1 = arg1;
    msgTo->arg2 = arg2;
    int64_t eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, msgTo, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

void IccFileController::ParseFileSize(int val[], int len, const unsigned char *data)
{
    if (data == nullptr) {
        TELEPHONY_LOGE("ParseFileSize null data");
        return;
    }
    if (len > MAX_FILE_INDEX) {
        GetFileAndDataSize(data, val[0], val[1]);
        if (val[0] != 0) {
            val[MAX_FILE_INDEX] = val[1] / val[0];
        }
    }
    TELEPHONY_LOGD("ParseFileSize result %{public}d, %{public}d %{public}d", val[0], val[1], val[MAX_FILE_INDEX]);
}
bool IccFileController::IsValidRecordSizeData(const unsigned char *data)
{
    if (data == nullptr) {
        TELEPHONY_LOGE("IccFileTypeMismatch ERROR nullptr");
        return false;
    }
    if (ICC_ELEMENTARY_FILE != data[TYPE_OF_FILE]) {
        TELEPHONY_LOGE("IccFileTypeMismatch ERROR TYPE_OF_FILE");
        return false;
    }
    if (ELEMENTARY_FILE_TYPE_LINEAR_FIXED != data[STRUCTURE_OF_DATA]) {
        TELEPHONY_LOGE("IccFileTypeMismatch ERROR STRUCTURE_OF_DATA");
        return false;
    }
    return true;
}
bool IccFileController::IsValidBinarySizeData(const unsigned char *data)
{
    if (data == nullptr) {
        TELEPHONY_LOGE("IccFileTypeMismatch ERROR nullptr");
        return false;
    }
    if (ICC_ELEMENTARY_FILE != data[TYPE_OF_FILE]) {
        TELEPHONY_LOGE("IccFileTypeMismatch ERROR TYPE_OF_FILE");
        return false;
    }
    if (ELEMENTARY_FILE_TYPE_TRANSPARENT != data[STRUCTURE_OF_DATA]) {
        TELEPHONY_LOGE("IccFileTypeMismatch ERROR STRUCTURE_OF_DATA");
        return false;
    }
    return true;
}
void IccFileController::GetFileAndDataSize(const unsigned char *data, int &fileSize, int &dataSize)
{
    if (data == nullptr) {
        TELEPHONY_LOGE("GetFileAndDataSize null data");
        return;
    }
    fileSize = data[LENGTH_OF_RECORD] & BYTE_NUM;
    dataSize = ((data[SIZE_ONE_OF_FILE] & BYTE_NUM) << OFFSET) + (data[SIZE_TWO_OF_FILE] & BYTE_NUM);
}
void IccFileController::GetDataSize(const unsigned char *data, int &dataSize)
{
    if (data == nullptr) {
        TELEPHONY_LOGE("GetDataSize null data");
        return;
    }
    dataSize = ((data[SIZE_ONE_OF_FILE] & BYTE_NUM) << OFFSET) + (data[SIZE_TWO_OF_FILE] & BYTE_NUM);
}

void IccFileController::SetRilManager(std::shared_ptr<Telephony::ITelRilManager> ril)
{
    telRilManager_ = ril;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("IccFileController set NULL TelRilManager!!");
    }
}

std::string IccFileController::CheckRightPath(const std::string &path, int fileId)
{
    if (path.empty()) {
        return ObtainElementFilePath(fileId);
    } else {
        return path;
    }
}

bool IccFileController::ProcessErrorResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<IccFromRilMsg> rcvMsg = event->GetSharedObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        return false;
    }
    AppExecFwk::InnerEvent::Pointer &response = rcvMsg->controlHolder->fileLoaded;
    auto owner = response->GetOwner();
    if (owner == nullptr) {
        TELEPHONY_LOGE("owner is nullptr");
        return false;
    }
    uint32_t id = response->GetInnerEventId();
    std::unique_ptr<FileToControllerMsg> cmdData = response->GetUniqueObject<FileToControllerMsg>();
    bool needShare = (id == MSG_SIM_OBTAIN_ICC_FILE_DONE);
    std::unique_ptr<ControllerToFileMsg> objectUnique = nullptr;
    std::shared_ptr<ControllerToFileMsg> objectShare = nullptr;
    TELEPHONY_LOGD("ProcessErrorResponse start response %{public}d", needShare);
    if (needShare) {
        objectShare = std::make_shared<ControllerToFileMsg>(cmdData.get(), nullptr);
        objectShare->exception = rcvMsg->fileData.exception;
    } else {
        objectUnique = std::make_unique<ControllerToFileMsg>(cmdData.get(), nullptr);
        objectUnique->exception = rcvMsg->fileData.exception;
    }

    if ((objectUnique == nullptr) && (objectShare == nullptr)) {
        TELEPHONY_LOGE("ProcessErrorResponse  create ControllerToFileMsg is null");
        return true;
    }

    TELEPHONY_LOGI("ProcessErrorResponse owner: evtId: %{public}d", id);
    SendEvent(owner, id, needShare, objectShare, objectUnique);
    TELEPHONY_LOGD("ProcessErrorResponse send end");
    return true;
}

void IccFileController::SendEvent(std::shared_ptr<AppExecFwk::EventHandler> handler, uint32_t id, bool needShare,
    std::shared_ptr<ControllerToFileMsg> objectShare, std::unique_ptr<ControllerToFileMsg> &objectUnique)
{
    if (needShare) {
        TelEventHandler::SendTelEvent(handler, id, objectShare);
        return;
    }
    TelEventHandler::SendTelEvent(handler, id, objectUnique);
}

bool IccFileController::IsFixedNumberType(int efId)
{
    bool fixed = false;
    switch (efId) {
        case ELEMENTARY_FILE_ADN:
        case ELEMENTARY_FILE_FDN:
        case ELEMENTARY_FILE_USIM_ADN:
        case ELEMENTARY_FILE_USIM_IAP:
            fixed = true;
            return fixed;
        default:
            break;
    }
    return fixed;
}

IccFileController::~IccFileController() {}
} // namespace Telephony
} // namespace OHOS

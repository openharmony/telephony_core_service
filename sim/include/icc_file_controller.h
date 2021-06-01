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
#ifndef OHOS_ICC_FILE_CONTROLLER_H
#define OHOS_ICC_FILE_CONTROLLER_H

#include <cstring>
#include <string>
#include "event_handler.h"
#include "event_runner.h"
#include "i_tel_ril_manager.h"
#include "observer_handler.h"
#include "sim_constant.h"
#include "sim_data_type.h"
#include "sim_utils.h"
#include "telephony_log.h"
#define NULLSTR ""

namespace OHOS {
namespace SIM {
class IccFileController : public AppExecFwk::EventHandler {
public:
    IccFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    virtual void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    virtual ~IccFileController();
    void GetTransparentFile(int fileId, std::string path, AppExecFwk::InnerEvent::Pointer &event);
    void GetTransparentFile(int fileId, AppExecFwk::InnerEvent::Pointer &event);
    void GetTransparentFile(int fileId, int size, AppExecFwk::InnerEvent::Pointer &event);

    void GetFixedLinearFile(int fileId, std::string path, int fileNum, AppExecFwk::InnerEvent::Pointer &event);
    void GetFixedLinearFile(int fileId, int fileNum, AppExecFwk::InnerEvent::Pointer &event);

    void GetAllFixedLinearFile(int fileId, std::string path, AppExecFwk::InnerEvent::Pointer &event);
    void GetAllFixedLinearFile(int fileId, AppExecFwk::InnerEvent::Pointer &event);
    void GetAllFixedLinearFile(int fileId, AppExecFwk::InnerEvent::Pointer &event, bool dedicated);
    void GetAllFixedLinearFile(int fileId, int mode, AppExecFwk::InnerEvent::Pointer &event);
    void GetLinearFileSize(int fileId, std::string path, AppExecFwk::InnerEvent::Pointer &event);
    void GetLinearFileSize(int fileId, AppExecFwk::InnerEvent::Pointer &event);

    void UpdateFixedLinearFile(int fileId, std::string path, int fileNum, std::string data, int dataLength,
        std::string pin2, AppExecFwk::InnerEvent::Pointer &onComplete);
    void UpdateFixedLinearFile(int fileId, int fileNum, std::string data, int dataLength, std::string pin2,
        AppExecFwk::InnerEvent::Pointer &onComplete);
    void UpdateTransparentFile(
        int fileId, std::string data, int dataLength, AppExecFwk::InnerEvent::Pointer &onComplete);
    void SetRilManager(IRilManager *ril);

protected:
    IRilManager *rilManager_ = nullptr;
    virtual std::string ObtainElementFilePath(int efId) = 0;
    std::string aid_ = "";
    std::string GetCommonElementFilePath(int efId);
    void SendResponse(std::shared_ptr<IccControllerHolder> holder, const IccFileData *fd);
    void SendEfLinearResult(const AppExecFwk::InnerEvent::Pointer &response, const int val[], int len);
    void SendMultiRecordResult(const AppExecFwk::InnerEvent::Pointer &response, std::vector<std::string> &strValue);
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventId, std::shared_ptr<IccControllerHolder> &holderObject);
    AppExecFwk::InnerEvent::Pointer CreatePointer(
        int eventId, int arg1, int arg2, std::shared_ptr<IccControllerHolder> &holderObject);
    AppExecFwk::InnerEvent::Pointer CreatePointer(
        int eventId, int arg1, int arg2, const AppExecFwk::InnerEvent::Pointer &msg);
    void ProcessBinarySize(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessRecordSize(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessLinearRecordSize(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessReadRecord(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessReadBinary(const AppExecFwk::InnerEvent::Pointer &event);

private:
    const int RECORD_NUM = 3;
    const uint32_t OFFSET = 8;
    const uint8_t BYTE_NUM = 0xff;
    const int MAX_FILE_INDEX = 2;
    void ParseFileSize(int val[], int len, const unsigned char *data);
    bool IsValidSizeData(const unsigned char *data);
    void GetFileAndDataSize(const unsigned char *data, int &dataSize, int &fileSize);
};
} // namespace SIM
} // namespace OHOS

#endif
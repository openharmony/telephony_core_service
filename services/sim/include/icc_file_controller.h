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

#include "i_tel_ril_manager.h"
#include "sim_constant.h"
#include "sim_data_type.h"
#include "sim_utils.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class IccFileController : public TelEventHandler {
public:
    explicit IccFileController(const std::string &name, int slotId);
    virtual void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    virtual ~IccFileController();
    void ObtainBinaryFile(int fileId, const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainBinaryFile(int fileId, int size, const AppExecFwk::InnerEvent::Pointer &event);

    void ObtainLinearFixedFile(
        int fileId, const std::string &path, int fileNum, const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainLinearFixedFile(int fileId, int fileNum, const AppExecFwk::InnerEvent::Pointer &event);

    void ObtainAllLinearFixedFile(
        int fileId, const std::string &path, const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainAllLinearFixedFile(int fileId, const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainLinearFileSize(int fileId, const std::string &path, const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainLinearFileSize(int fileId, const AppExecFwk::InnerEvent::Pointer &event);

    void UpdateLinearFixedFile(int fileId, const std::string &path, int fileNum, const std::string data,
        int dataLength, const std::string pin2, const AppExecFwk::InnerEvent::Pointer &onComplete);
    void UpdateLinearFixedFile(int fileId, int fileNum, const std::string data, int dataLength,
        const std::string pin2, const AppExecFwk::InnerEvent::Pointer &onComplete);
    void UpdateBinaryFile(
        int fileId, const std::string data, int dataLength, const AppExecFwk::InnerEvent::Pointer &onComplete);
    void SetRilManager(std::shared_ptr<ITelRilManager> ril);
    inline const static std::string NULLSTR = "";

protected:
    // 3GPP TS 51.011 V4.1.0 section 10.7 files of gsm
    const std::string MASTER_FILE_SIM = "3F00";
    const std::string DEDICATED_FILE_TELECOM = "7F10";
    const std::string DEDICATED_FILE_GSM = "7F20";
    const std::string DEDICATED_FILE_GRAPHICS = "5F50";
    // ETSI TS 102 221 V3.3.0 section 8.6 reservation of file IDs
    const std::string DEDICATED_FILE_DIALLING_NUMBERS = "5F3A";
    const std::string DEDICATED_FILE_ADF = "7FFF";
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    int slotId_ = 0;
    virtual std::string ObtainElementFilePath(int efId) = 0;
    std::string ObtainElementFileForPublic(int efId);
    void SendResponse(std::shared_ptr<IccControllerHolder> holder, const IccFileData *fd);
    void SendEfLinearResult(const AppExecFwk::InnerEvent::Pointer &response, const int val[], int len);
    void SendMultiRecordResult(const AppExecFwk::InnerEvent::Pointer &response, std::vector<std::string> &strValue);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId, std::shared_ptr<IccControllerHolder> &holderObject);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(
        int eventId, int arg1, int arg2, std::shared_ptr<IccControllerHolder> &holderObject);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(
        int eventId, int arg1, int arg2, const AppExecFwk::InnerEvent::Pointer &msg);
    void ProcessBinarySize(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessRecordSize(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessLinearRecordSize(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessReadRecord(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessReadBinary(const AppExecFwk::InnerEvent::Pointer &event);
    void SendEvent(std::shared_ptr<AppExecFwk::EventHandler> handler, uint32_t id, bool needShare,
        std::shared_ptr<ControllerToFileMsg> objectShare, std::unique_ptr<ControllerToFileMsg> &objectUnique);

private:
    const int RECORD_NUM = 3;
    const uint32_t OFFSET = 8;
    const uint8_t BYTE_NUM = 0xff;
    const int MAX_FILE_INDEX = 2;
    const int ICC_FILE_CURRENT_MODE = 4;
    void ParseFileSize(int val[], int len, const unsigned char *data);
    bool IsValidRecordSizeData(const unsigned char *data);
    bool IsValidBinarySizeData(const unsigned char *data);
    void GetFileAndDataSize(const unsigned char *data, int &dataSize, int &fileSize);
    void GetDataSize(const unsigned char *data, int &dataSize);
    std::string CheckRightPath(const std::string &path, int fileId);
    bool ProcessErrorResponse(const AppExecFwk::InnerEvent::Pointer &event);
    bool IsFixedNumberType(int);
    bool CheckEvent(const AppExecFwk::InnerEvent::Pointer &event);
};
} // namespace Telephony
} // namespace OHOS

#endif

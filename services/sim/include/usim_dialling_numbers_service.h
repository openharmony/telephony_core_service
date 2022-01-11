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

#ifndef OHOS_USIM_DIALLING_NUMBERS_SERVICE_H
#define OHOS_USIM_DIALLING_NUMBERS_SERVICE_H

#include "icc_file_controller.h"
#include "sim_constant.h"
#include "icc_dialling_numbers_handler.h"
#include "tag_service.h"
#include "telephony_log_wrapper.h"
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
enum UsimMessage {
    MSG_USIM_PBR_LOAD_DONE = 1,
    MSG_USIM_USIM_ADN_LOAD_DONE = 2
};

struct UsimDiallingNumberFile {
    std::map<int, std::shared_ptr<TagData>> fileIds_;
    int fileNumber_ = 0;
};

enum UsimConstant {
    LEN_MIN = 2,
    LEN_MAX = 3,
    INVALID_SFI = -1,
    BIT_OF_BYTE = 8
};

class UsimDiallingNumbersService : public AppExecFwk::EventHandler {
public:
    UsimDiallingNumbersService(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~UsimDiallingNumbersService();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainUsimElementaryFiles(const AppExecFwk::InnerEvent::Pointer &pointer);
    void EnableReloadFiles();
    void SetFileControllerAndDiallingNumberHandler(
        std::shared_ptr<IccFileController> &ctrl, std::shared_ptr<IccDiallingNumbersHandler> handler);

protected:
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    bool pbrFileLoaded_ = true;
    std::vector<std::shared_ptr<UsimDiallingNumberFile>> pbrFiles_;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbersFiles_;
    std::map<int, int> efIdOfSfi_;
    uint pbrIndex_ = 0;
    void ReloadAllFiles();
    void LoadPbrFiles();
    std::shared_ptr<IccDiallingNumbersHandler> diallingNumbersHandler_ = nullptr;
    AppExecFwk::InnerEvent::Pointer callerPointer_ = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);

private:
    using ProcessFunc = void (UsimDiallingNumbersService::*)(const AppExecFwk::InnerEvent::Pointer &event);
    std::map<int, ProcessFunc> memberFuncMap_;
    void UpdatePhoneDiallingNumberFile();
    std::string GetEmailContents(int index);
    bool LoadDiallingNumberFiles(int index);
    void GeneratePbrFile(std::vector<std::string> &records);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId);
    AppExecFwk::InnerEvent::Pointer CreateHandlerPointer(
        int eventid, int efId, int index, std::shared_ptr<void> pobj);
    static std::mutex mtx_;
    void ProcessPbrLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void FillDiallingNumbersRecords(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list);
    bool CheckEmailFiles(const std::shared_ptr<TagData> &email, int index);

    std::shared_ptr<UsimDiallingNumberFile> BuildNumberFileByRecord(const std::string &record);
    void StorePbrDetailInfo(std::shared_ptr<UsimDiallingNumberFile> file,
        std::shared_ptr<TagService> tlv, int parentTag);
    void SendBackResult(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &diallingnumbers);
    void SendLocalBack();
    void InitFuncMap();
    void NextStep(int msgId);
    const int NEXT = 123;
    enum UsimFileType {
        TYPE1_FLAG = 168, // 3gpp 31102-9j0 4.4.2.1
        TYPE2_FLAG = 169,
        TYPE3_FLAG = 170,
        TAG_SIM_USIM_ADN = 192,
        TAG_SIM_USIM_IAP,
        TAG_SIM_USIM_EXT1,
        TAG_SIM_USIM_SNE,
        TAG_SIM_USIM_ANR, // 3gpp 31102-9j0 4.4.2.9
        TAG_SIM_USIM_PBC,
        TAG_SIM_USIM_GRP,
        TAG_SIM_USIM_AAS,
        TAG_SIM_USIM_GSD,
        TAG_SIM_USIM_UID,
        TAG_SIM_USIM_EMAIL,
        TAG_SIM_USIM_CCP1
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_USIM_DIALLING_NUMBERS_SERVICE_H
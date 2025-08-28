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

#include "icc_dialling_numbers_handler.h"
#include "icc_file_controller.h"
#include "sim_constant.h"
#include "sim_utils.h"
#include "tag_service.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
enum UsimMessage {
    MSG_USIM_LOAD_PBR = 0,
    MSG_USIM_PBR_LOAD_DONE = 1,
    MSG_USIM_ADN_LOAD_DONE = 2,
    MSG_USIM_ANR_LOAD_DONE = 3,
    MSG_USIM_IAP_LOAD_DONE = 4
};

struct UsimDiallingNumberFile {
    std::map<int, std::shared_ptr<TagData>> fileIds_ {};
    std::map<int, int> tagIndex_;
    std::map<int, int> parentTag_;
    int fileNumber_ = 0;
};

enum UsimConstant {
    LEN_MIN = 2,
    LEN_MAX = 3,
    INVALID_SFI = -1,
    BIT_OF_BYTE = 8
};

class UsimDiallingNumbersService : public TelEventHandler {
public:
    UsimDiallingNumbersService();
    ~UsimDiallingNumbersService();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainUsimElementaryFiles(const AppExecFwk::InnerEvent::Pointer &pointer);
    void SetFileControllerAndDiallingNumberHandler(
        std::shared_ptr<IccFileController> &ctrl, std::shared_ptr<IccDiallingNumbersHandler> handler);

protected:
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    bool pbrFileLoaded_ = true;
    std::vector<std::shared_ptr<UsimDiallingNumberFile>> pbrFiles_;
    std::map<int, int> efIdOfSfi_;
    uint pbrIndex_ = 0;
    void LoadPbrFiles();
    std::shared_ptr<IccDiallingNumbersHandler> diallingNumbersHandler_ = nullptr;

private:
    using ProcessFunc = std::function<void(const AppExecFwk::InnerEvent::Pointer &event)>;
    std::map<int, ProcessFunc> memberFuncMap_;
    bool isProcessingPbr = false;
    std::map<int, std::vector<std::shared_ptr<DiallingNumbersInfo>>> adns_;
    std::map<int, std::vector<std::u16string>> anrs_;
    std::map<int, std::vector<std::vector<uint8_t>>> iaps_;
    std::list<AppExecFwk::InnerEvent::Pointer> callers_;
    uint32_t iapNum_ = 0;
    void CheckQueryDone();
    void ProcessQueryDone();
    void MergeNumbers(std::vector<std::shared_ptr<DiallingNumbersInfo>> &adn, const std::vector<std::u16string> &anr);
    void MergeNumber(std::shared_ptr<DiallingNumbersInfo> &adn, const std::u16string &anr);
    void StartLoadByPbrFiles();
    bool LoadDiallingNumberFiles(size_t index);
    bool LoadDiallingNumber2Files(size_t index);
    bool LoadIapFiles(size_t index);
    void GeneratePbrFile(std::vector<std::string> &records);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId);
    AppExecFwk::InnerEvent::Pointer CreateHandlerPointer(
        int eventid, int efId, int index, std::shared_ptr<void> pobj);
    static std::mutex mtx_;
    void ProcessPbrLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDiallingNumber2LoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessIapLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    std::u16string FetchAnrContent(const std::string &recordData);
    std::vector<uint8_t> FetchIapContent(const std::string &recordData);
    bool IsValidTag(std::map<int, std::shared_ptr<TagData>> tags, int tag);
    std::shared_ptr<UsimDiallingNumberFile> BuildNumberFileByRecord(const std::string &record);
    void StorePbrDetailInfo(std::shared_ptr<UsimDiallingNumberFile> file,
        std::shared_ptr<TagService> tlv, int parentTag);
    void SendBackResult(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &diallingnumbers);
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
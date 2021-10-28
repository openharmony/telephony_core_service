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

#include <iostream>
#include <cstring>
#include <string>

#include "dialling_numbers_info.h"
#include "icc_file_controller.h"
#include "sim_constant.h"
#include "sim_dialling_numbers_handler.h"
#include "tag_service.h"
#include "telephony_log_wrapper.h"
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
enum UsimMessage {
    MSG_USIM_PBR_LOAD_DONE = 1,
    MSG_USIM_USIM_ADN_LOAD_DONE = 2,
    MSG_USIM_IAP_LOAD_DONE = 3,
    MSG_USIM_EMAIL_LOAD_DONE = 4
};
enum UsimFileType {
    TYPE1_FLAG = 168,
    TYPE2_FLAG = 169,
    TYPE3_FLAG = 170,
    UF_ADN = 192,
    UF_IAP,
    UF_EXT1,
    UF_SNE,
    UF_ANR,
    UF_PBC,
    UF_GRP,
    UF_AAS,
    UF_GSD,
    UF_UID,
    UF_EMAIL,
    UF_CCP1
};

enum UsimConstant { LEN_MIN = 2, LEN_MAX = 3, INVALID_SFI = -1 };
class SimDiallingNumbersStation;
class UsimDiallingNumberFile {
public:
    std::map<int, std::shared_ptr<TagFile>> fileIds_;
    UsimDiallingNumberFile(const std::string &record)
    {
        std::shared_ptr<TagService> recTlv = std::make_shared<TagService>(record, 0);
        ParseTag(recTlv);
    }
    ~UsimDiallingNumberFile() {}
    int ObtainMasterFileNum()
    {
        return masterFileNum_;
    }

    void UpdateMasterFileNum(int num)
    {
        masterFileNum_ = num;
    }

private:
    int masterFileNum_ = 0;

    void ParseTag(std::shared_ptr<TagService> tlv)
    {
        std::shared_ptr<TagService> tlvEfSfi = nullptr;
        int tag = 0;
        int dataLen = 0;
        std::shared_ptr<unsigned char> data = nullptr;

        do {
            tag = tlv->GetTag();
            switch (tag) {
                case TYPE1_FLAG:
                case TYPE3_FLAG:
                case TYPE2_FLAG: {
                    data = tlv->GetData(dataLen);
                    std::string dataStr = SIMUtils::BytesConvertToHexString(data.get(), dataLen);
                    tlvEfSfi = std::make_shared<TagService>(dataStr, 0);
                    ParseEfAndSFI(tlvEfSfi, tag);
                    }
                    break;
                default:
                    break;
            }
        } while (tlv->NextObject());
    }

    void ParseEfAndSFI(std::shared_ptr<TagService> tlv, int parentTag)
    {
        int tag = 0;
        int tagNumberWithinParentTag = 0;
        do {
            tag = tlv->GetTag();
            switch (tag) {
                case UF_EMAIL:
                case UF_ADN:
                case UF_EXT1:
                case UF_ANR:
                case UF_PBC:
                case UF_GRP:
                case UF_AAS:
                case UF_GSD:
                case UF_UID:
                case UF_CCP1:
                case UF_IAP:
                case UF_SNE:
                    MakeFiles(tlv, tag, parentTag, tagNumberWithinParentTag);
                    break;
                default:
                    break;
            }
            tagNumberWithinParentTag++;
        } while (tlv->NextObject());
    }

    void MakeFiles(const std::shared_ptr<TagService> &tlv, const int &tag, const int &parentTag, const int &tagNum)
    {
        int sfi = INVALID_SFI;
        int dataLen = 0;
        std::shared_ptr<unsigned char> dataPack = tlv->GetData(dataLen);
        unsigned char *data = dataPack.get();

        if (dataLen < LEN_MIN || dataLen > LEN_MAX) {
            TELEPHONY_LOGE("Invalid ts length: %{public}d", dataLen);
            return;
        }
        if (dataLen == LEN_MAX) {
            sfi = data[LEN_MIN] & 0xFF;
        }
        int efid = ((data[0] & 0xFF) << BYTE_BIT) | (data[1] & 0xFF);
        std::shared_ptr<TagFile> tfile = std::make_shared<TagFile>(parentTag, efid, sfi, tagNum);
        TELEPHONY_LOGI("prfiles: %{public}d %{public}d %{public}d %{public}d", parentTag, efid, sfi, tagNum);
        fileIds_.insert(std::pair<int, std::shared_ptr<TagFile>>(tag, tfile));
    }
};

class UsimDiallingNumbersService : public AppExecFwk::EventHandler {
public:
    UsimDiallingNumbersService(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~UsimDiallingNumbersService();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> LoadEfFilesFromUsim();
    void InvalidateCache();
    void SetFileControllerAndDiallingNumberHandler(
        std::shared_ptr<IccFileController> &ctrl, std::shared_ptr<SimDiallingNumbersHandler> handler);
    void Reset();

protected:
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    bool isPbrPresent_ = true;
    bool updateCache_ = false;
    std::vector<std::shared_ptr<UsimDiallingNumberFile>> pbrFiles_;
    std::vector<std::string> iapFiles_;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbersFils_;
    std::vector<std::string> emailFiles_;
    std::map<int, int> efIdOfSfi_;
    std::map<int, std::vector<std::string>> emailsOfDiallingNumbers_;
    std::condition_variable processWait_;
    void RefreshCache();
    void LoadPbrFiles();
    std::shared_ptr<SimDiallingNumbersHandler> pbLoader_ = nullptr;

private:
    void LoadEmailFiles(int recId);
    void CreateType1Emails(int recId);
    bool CreateType2Emails(int recId);
    void LoadIapFiles(int efid);
    void UpdatePhoneDiallingNumberFile();
    std::string GetEmailContents(int recId);
    void LoadDiallingNumberFiles(int recId);
    void CreatePbrFile(std::vector<std::string> &records);
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventId);
    AppExecFwk::InnerEvent::Pointer CreateHandlerPointer(
        int eventid, int efId, int index, std::shared_ptr<void> pobj);
    std::mutex mtx_;
    void ProcessPbrLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessIapLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessEmailLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void FillPhoneBookRecords(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list);
    bool CheckEmailFiles(const std::shared_ptr<TagFile> &email, int recId);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_USIM_DIALLING_NUMBERS_SERVICE_H
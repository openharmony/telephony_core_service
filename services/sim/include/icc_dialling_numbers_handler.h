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

#ifndef OHOS_SIM_DIALLING_NUMBERS_HANDLER_H
#define OHOS_SIM_DIALLING_NUMBERS_HANDLER_H

#include <unordered_map>
#include <thread>

#include "event_handler.h"
#include "event_runner.h"
#include "dialling_numbers_info.h"
#include "icc_file_controller.h"
#include "sim_data_type.h"
#include "sim_number_decode.h"
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
enum {
    MSG_SIM_OBTAIN_ADN_DONE = 1,
    MSG_SIM_OBTAIN_ALL_ADN_DONE = 2,
    MSG_SIM_OBTAIN_LINEAR_FILE_SIZE_DONE = 3,
    MSG_SIM_RENEW_ADN_DONE = 4
};

enum {
    // 3gpp ts51.011 10.5.1
    BCD_NUMBER_BYTES = 0,
    TON_NPI_NUMBER = 1,
    DIALING_NUMBERS_BEGIN = 2,
    DIALING_NUMBERS_END = 11,
    MORE_FILE_ID = 12,
    EXTRA_FILE_ID = 13
};

enum {
    MORE_FILE_TYPE_DATA = 0x02,
    MORE_FILE_FLAG = 0x03,
    MAX_MORE_PARTY_LENGTH = 0xa
};

struct DiallingNumberLoadRequest {
public:
    DiallingNumberLoadRequest(int serialId, int fileId, int exId, int indexNum, const std::string &pin2Str,
        const AppExecFwk::InnerEvent::Pointer &pointer) : elementaryFileId(fileId), extFileId(exId),
        pin2(pin2Str), index(indexNum), loadId(serialId)
    {
        callPointer = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(pointer));
    }
    void SetResult(std::shared_ptr<void> result)
    {
        this->result = result;
    }
    std::shared_ptr<void> GetResult()
    {
        return this->result;
    }

    void SetException(std::shared_ptr<void> exception)
    {
        this->exception = exception;
    }

    std::shared_ptr<void> GetException()
    {
        return this->exception;
    }

    void SetElementaryFileId(int id)
    {
        this->elementaryFileId = id;
    }

    int GetElementaryFileId()
    {
        return this->elementaryFileId;
    }

    void SetExEF(int ef)
    {
        this->extFileId = ef;
    }

    int GetExEF()
    {
        return this->extFileId;
    }

    void SetIndex(int index)
    {
        this->index = index;
    }

    int GetIndex()
    {
        return this->index;
    }

    void SetPin2(std::string pin2Code)
    {
        this->pin2 = pin2Code;
    }

    std::string GetPin2()
    {
        return this->pin2;
    }

    void SetIsDelete(bool del)
    {
        this->isDelete = del;
    }

    bool GetIsDelete()
    {
        return this->isDelete;
    }

    void SetLoadId(int id)
    {
        this->loadId = id;
    }

    int GetLoadId()
    {
        return this->loadId;
    }
    AppExecFwk::InnerEvent::Pointer &GetCaller()
    {
        return callPointer;
    }
    bool HasCount()
    {
        return moreFileToGet != 0;
    }
    void InitCount()
    {
        moreFileToGet = INIT_COUNT;
    }
    void CountUp()
    {
        ++moreFileToGet;
    }
    void CountDown()
    {
        --moreFileToGet;
    }
    void ClearCount()
    {
        moreFileToGet = 0;
    }

private:
    int elementaryFileId = 0;
    int extFileId = 0;
    int moreFileToGet = 0;
    std::string pin2 = "";
    int index = 0;
    int loadId = 0;
    bool isDelete = false;
    std::shared_ptr<void> result = nullptr;
    std::shared_ptr<void> exception = nullptr;
    AppExecFwk::InnerEvent::Pointer &callPointer = nullptr_;
    AppExecFwk::InnerEvent::Pointer nullptr_ = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    const int INIT_COUNT = 1;
};
struct DiallingNumberUpdateInfor {
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = nullptr;
    int index = 0;
    int fileId = 0;
    int extFile = 0;
    std::string pin2 = "";
    bool isDel = false;
};
class IccDiallingNumbersHandler : public AppExecFwk::EventHandler {
public:
    IccDiallingNumbersHandler(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<IccFileController> fh);
    ~IccDiallingNumbersHandler();
    void GetDiallingNumbers(int ef, int extensionEF, int recordNumber, AppExecFwk::InnerEvent::Pointer &response);
    void GetAllDiallingNumbers(int ef, int extensionEF, AppExecFwk::InnerEvent::Pointer &response);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void UpdateDiallingNumbers(const DiallingNumberUpdateInfor &infor, AppExecFwk::InnerEvent::Pointer &response);
    static int GetNextSerialId()
    {
        return nextSerialId_++;
    }
    static std::atomic_int nextSerialId_;
    static std::unordered_map<int, std::shared_ptr<DiallingNumberLoadRequest>> requestMap_;
    static std::shared_ptr<DiallingNumberLoadRequest> FindLoadRequest(int serial);
    static void ClearLoadRequest(int serial);
    static std::shared_ptr<DiallingNumberLoadRequest> CreateLoadRequest(int fileId,
        int exId, int indexNum, const std::string &pin2Str, const AppExecFwk::InnerEvent::Pointer &result);
    void UpdateFileController(const std::shared_ptr<IccFileController> &fileController);

protected:
    std::shared_ptr<IccFileController> fileController_;
    std::string GetFilePath(int elementaryFileId);
    // 3GPP TS 51.011 V4.1.0 section 10.7 files of gsm
    const std::string MASTER_FILE_SIM = "3F00";
    const std::string DEDICATED_FILE_TELECOM = "7F10";

private:
    using ProcessFunc = void (IccDiallingNumbersHandler::*)(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    std::map<int, ProcessFunc> memberFuncMap_;
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId, int loadId);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId, std::shared_ptr<void> pobj, int loadId);
    void ProcessDiallingNumberAllLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessLinearSizeDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessUpdateRecordDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    bool SendBackResult(int loadId);
    void FetchDiallingNumberContent(
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, const std::string &recordData);
    std::shared_ptr<unsigned char> CreateSavingSequence(
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int dataLength);
    std::shared_ptr<unsigned char> CreateNameSequence(const std::u16string &name, int &seqLength);
    std::shared_ptr<HRilRadioResponseInfo> MakeExceptionResult(int code);
    void FillNumberFiledForDiallingNumber(
        std::shared_ptr<unsigned char> diallingNumber, const std::string &number, int dataLength);
    bool FormatNameAndNumber(std::shared_ptr<DiallingNumbersInfo> &diallingNumber, bool isDel);
    void SendUpdateCommand(const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int length,
        const std::shared_ptr<DiallingNumberLoadRequest> &loadRequest, int loadId);
    void InitFuncMap();
    const int RECORD_LENGTH = 28;
    const int LENGTH_RATE = 2;
    const int INVALID_LENGTH = 49;
    const static int32_t PRE_BYTES_NUM = 14;
    const static int32_t MAX_NUMBER_SIZE_BYTES = 11;
    const static int32_t EXT_FILE_BITYES_NUM = 13;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_DIALLING_NUMBERS_HANDLER_H

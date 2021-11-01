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

#include <stdlib.h>
#include <string>
#include <thread>

#include "event_handler.h"
#include "event_runner.h"

#include "dialling_numbers_info.h"
#include "icc_file_controller.h"
#include "sim_data_type.h"
#include "sim_number_decode.h"
#include "sim_utils.h"

#define MSG_SIM_OBTAIN_ADN_COMPLETED 1
#define MSG_SIM_OBTAIN_EXTRA_FILE_COMPLETED 2
#define MSG_SIM_OBTAIN_ALL_ADN_COMPLETED 3
#define MSG_SIM_OBTAIN_LINEAR_FILE_SIZE_COMPLETED 4
#define MSG_SIM_RENEW_ADN_COMPLETED 5

#define FOOTER_SIZE_BYTES 14
#define MAX_NUMBER_SIZE_BYTES 11
#define EXT_RECORD_LENGTH_BYTES 13
#define EXT_RECORD_TYPE_ADDITIONAL_DATA 2
#define EXT_RECORD_TYPE_MASK 3
#define MAX_EXT_CALLED_PARTY_LENGTH 0xa
#define ADN_BCD_NUMBER_LENGTH 0
#define ADN_TON_AND_NPI 1
#define ADN_DIALING_NUMBER_START 2
#define ADN_DIALING_NUMBER_END 11
#define ADN_CAPABILITY_ID 12
#define ADN_EXTENSION_ID 13

namespace OHOS {
namespace Telephony {
struct DiallingNumberLoadRequest {
    int ef = 0;
    int extensionEF = 0;
    int pendingExtLoads = 0;
    std::string pin2 = "";
    int recordNumber = 0;
    int loadId = 0;

    std::shared_ptr<void> result = nullptr;
    std::shared_ptr<void> exception = nullptr;
    AppExecFwk::InnerEvent::Pointer userResponse = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    DiallingNumberLoadRequest(int serialId, const AppExecFwk::InnerEvent::Pointer &pointer)
    {
        loadId = serialId;
        userResponse = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(pointer));
    }
};

class SimDiallingNumbersHandler : public AppExecFwk::EventHandler {
public:
    SimDiallingNumbersHandler(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<IccFileController> fh);
    ~SimDiallingNumbersHandler();
    void LoadFromEF(int ef, int extensionEF, int recordNumber, AppExecFwk::InnerEvent::Pointer &response);
    void GetAllDiallingNumbers(int ef, int extensionEF, AppExecFwk::InnerEvent::Pointer &response);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void UpdateEF(std::shared_ptr<DiallingNumbersInfo> diallingNumber, int ef, int extensionEF, int recordNumber,
        std::string pin2, AppExecFwk::InnerEvent::Pointer &response);
    static int GetNextSerialId()
    {
        return nextSerialId_++;
    }
    static std::atomic_int nextSerialId_;
    static std::unordered_map<int, std::shared_ptr<DiallingNumberLoadRequest>> requestMap_;
    static std::shared_ptr<DiallingNumberLoadRequest> FindLoadRequest(int serial);
    static void ClearLoadRequest(int serial);
    static std::shared_ptr<DiallingNumberLoadRequest> CreateLoadRequest(
        const AppExecFwk::InnerEvent::Pointer &result);

protected:
    std::shared_ptr<IccFileController> fileController_;
    std::string GetEFPath(int efid);
    // 3GPP TS 51.011 V4.1.0 section 10.7 files of gsm
    const std::string MASTER_FILE_SIM = "3F00";
    const std::string DEDICATED_FILE_TELECOM = "7F10";

private:
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventId, int loadId);
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventId, std::shared_ptr<void> pobj, int loadId);
    void ProcessDiallingNumberAllLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessDiallingNumberLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessExtRecordLoadDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessLinearSizeDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    void ProcessUpdateRecordDone(const AppExecFwk::InnerEvent::Pointer &event, int &id);
    bool SendBackResult(int loadId);
    void FetchDiallingNumberContent(
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, const std::string &recordData);
    void AppendExtRecord(const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, const std::string &recordData);
    std::shared_ptr<unsigned char> CreateSavingSequence(
        const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int recordSize);
    std::shared_ptr<unsigned char> CreateNameSequence(const std::u16string &name, int &seqLength);
    std::shared_ptr<HRilRadioResponseInfo> MakeExceptionResult(int code);
    void FillNumberFiledForDiallingNumber(
        std::shared_ptr<unsigned char> diallingNumber, const std::string &number, int recordSize);
    const int RECORD_LENGTH = 28;
    const int SIZE_POS = 2;
    const int LENGTH_RATE = 2;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_DIALLING_NUMBERS_HANDLER_H
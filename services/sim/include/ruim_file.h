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

#ifndef OHOS_RUIM_FILE_H
#define OHOS_RUIM_FILE_H

#include "icc_file.h"

namespace OHOS {
namespace Telephony {
class RuimFile : public IccFile {
public:
    explicit RuimFile(std::shared_ptr<SimStateManager> simStateManager);
    void StartLoad();
    std::string ObtainSimOperator();
    std::string ObtainIsoCountryCode();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    ~RuimFile();
    bool ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event);
    std::string ObtainMdnNumber();
    std::string ObtainCdmaMin();
    std::string ObtainPrlVersion();
    std::string ObtainNAI();
    std::string ObtainMdn();
    std::string ObtainMin();
    std::string ObtainSid();
    std::string ObtainNid();
    bool ObtainCsimSpnDisplayCondition();
    int ObtainSpnCondition(bool roaming, const std::string &operatorNum);
    bool UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber);
    bool SetVoiceMailCount(int32_t voiceMailCount);
    void ProcessIccRefresh(int msgId);
    bool SetVoiceCallForwarding(bool enable, const std::string &number);
    std::string GetVoiceMailNumber();
    void SetVoiceMailNumber(const std::string mailNumber);

protected:
    void ProcessFileLoaded(bool response);
    void OnAllFilesFetched();
    void LoadRuimFiles();
    bool ProcessIccLocked(const AppExecFwk::InnerEvent::Pointer &event);

private:
    using RecordProcessFunc = bool (RuimFile::*)(const AppExecFwk::InnerEvent::Pointer &event);
    std::map<int, RecordProcessFunc> memberFuncMap_;
    void InitMemberFunc();
    void ProcessLockedAllFilesFetched();
    bool ProcessGetImsiDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetIccidDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSubscriptionDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSpnDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ParseSpnName(int encodeType, const unsigned char* spnData, int dataLen);
    const size_t MCC_LEN = 3;
    const int LOAD_STEP = 1;
    const int SPN_FLAG = 0x01;
    const int ENCODING_POS = 1;
    const int LANG_POS = 2;
    static const int BUFFER_SIZE = 50;
    const int FLAG_NUM = 3;
    const int MAX_DATA_BYTE = 32;
    const uint8_t BYTE_NUM = 0xFF;
    std::string phoneNumber_ = "";
    // C.S0005 section 2.3.1
    std::string min2And1_ = "";
    // C.S0065 section 5.2.2
    std::string prlVersion_ = "";
    bool displayConditionOfCsimSpn_ = false;
    std::string mdn_ = "";
    std::string min_ = "";
    std::string systemId_ = "";
    std::string networkId_ = "";
    std::string nai_ = "";
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_RUIM_FILE_H
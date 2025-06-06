/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_SIM_FILE_H
#define OHOS_SIM_FILE_H

#include "icc_file.h"

namespace OHOS {
namespace Telephony {
class SimFileInit;
class SimFileParse;
class SimFile : public IccFile {
public:
    explicit SimFile(std::shared_ptr<SimStateManager> simStateManager);
    void StartLoad();
    std::string ObtainMsisdnNumber();
    std::string ObtainSimOperator();
    std::string ObtainMCC();
    std::string ObtainMNC();
    std::string ObtainIsoCountryCode();
    int ObtainSpnCondition(bool roaming, const std::string &operatorNum);
    int ObtainCallForwardStatus();
    std::shared_ptr<UsimFunctionHandle> ObtainUsimFunctionHandle();
    bool UpdateMsisdnNumber(
        const std::string &alphaTag, const std::string &number);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    ~SimFile() = default;
    bool ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event);
    bool UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber);
    bool SetVoiceMailCount(int32_t voiceMailCount);
    bool SetVoiceCallForwarding(bool enable, const std::string &number);
    void ProcessIccRefresh(int msgId);
    std::string GetVoiceMailNumber();
    void SetVoiceMailNumber(const std::string mailNumber);
    void ClearData();
    static std::vector<std::string> indiaMcc_;

public:
    enum {
        RELOAD_ICCID_EVENT = 0,
        RELOAD_IMSI_EVENT = 1,
    };

protected:
    enum SpnStatus {
        OBTAIN_SPN_NONE,
        OBTAIN_SPN_START,
        OBTAIN_SPN_GENERAL,
        OBTAIN_OPERATOR_NAMESTRING,
        OBTAIN_OPERATOR_NAME_SHORTFORM
    };
    void ProcessFileLoaded(bool response);
    void OnAllFilesFetched();
    void LoadSimFiles();
    bool ProcessIccLocked(const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainCallForwardFiles();
    void UpdateSimLanguage();
    int callForwardStatus_ = 0;
    std::string cphsInfo_ = IccFileController::NULLSTR;
    bool cspPlmnOn_ = false;
    unsigned char *efMWIS_ = nullptr;
    unsigned char *efCphsMwi_ = nullptr;
    unsigned char *efCff_ = nullptr;
    unsigned char *efCfis_ = nullptr;
    std::string efMWISStr_;
    std::string efCphsMwisStr_;
    std::string efCffStr_;
    std::string efCfisStr_;
    std::string efLi_ = IccFileController::NULLSTR;
    std::string efPl_ = IccFileController::NULLSTR;
    SpnStatus spnStatus_ = OBTAIN_SPN_NONE;
    int displayConditionOfSpn_ = 0;
    std::vector<std::string> spdiNetworks_;
    std::shared_ptr<UsimFunctionHandle> UsimFunctionHandle_ = nullptr;

private:
    using FileProcessFunc = std::function<bool(const AppExecFwk::InnerEvent::Pointer &event)>;
    std::map<int, FileProcessFunc> memberFuncMap_;
    void ObtainSpnPhase(bool start, const AppExecFwk::InnerEvent::Pointer &event);
    std::string AnalysisBcdPlmn(std::string data, std::string description);
    void ProcessElementaryFileCsp(std::string data);
    void ProcessSmses(std::string messages);
    void ProcessSms(std::string data);

    void ProcessSpnGeneral(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSpnCphs(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSpnShortCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetAdDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessVoiceMailCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMwisDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMbdnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCphsMailBoxDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMbiDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCfisDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCffDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainIMSIDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetIccIdDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetPlmnActDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetOplmnActDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSpdiDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainGid1Done(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainGid2Done(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSmsOnSim(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCspCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetInfoCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSstDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSmsDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetAllSmsDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetHplmActDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetEhplmnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetPnnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetOplDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetOpl5gDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetCphsMailbox(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetFplmnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetMbdn(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessMarkSms(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainSpnPhase(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainLiLanguage(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainPlLanguage(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessReloadIccid(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessReloadImsi(const AppExecFwk::InnerEvent::Pointer &event);
    void DelayGetImsi();
    bool ProcessGetSpnCphsDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSpnShortCphsDone(const AppExecFwk::InnerEvent::Pointer &event);
    void StartObtainSpn();
    void LoadSimOtherFile();
    void LoadSimOtherFileExt();

    void CheckMncLengthForAdDone();
    void CheckMncLengthForImsiDone();
    bool CheckMncLen(std::string imsi, int imsiSize, int mncLen, int mccmncLen, bool isCheckUninitMnc);
    bool IsIndiaMcc(std::string mccCode);
    void OnMccMncLoaded(std::string imsi);
    bool IsContinueGetSpn(bool start, SpnStatus curStatus, SpnStatus &newStatus);
    std::atomic<int32_t> reloadIccidCount_ = 3;
    const int MNC_INDEX = 7;
    const int MCC_LEN = 3;
    const int MNC_LONG_LEN = 3;
    const int MNC_LEN = 2;
    const int MCCMNC_LEN = 6;
    const int MCCMNC_SHORT_LEN = 5;
    const int LOAD_STEP = 1;
    const int INVALID_BYTES_NUM = 1;
    const int SPN_CHAR_POS = 0;
    const int MAIL_DELAY_TIME = 50 * 1000;
    const int RELOAD_ICCID_COUNT = 3;
    bool hasRetryGetImsi_ = false;
    static const uint8_t CPHS_VOICE_MAIL_MASK = 0x30;
    static const uint8_t CPHS_VOICE_MAIL_EXSIT = 0x30;
    static const int CFIS_BCD_NUMBER_LENGTH_OFFSET = 2;
    static const int CFIS_TON_NPI_OFFSET = 3;
    static const int CFIS_ADN_CAPABILITY_ID_OFFSET = 14;
    static const int CFIS_ADN_EXTENSION_ID_OFFSET = 15;
    int ObtainExtensionElementaryFile(int ef);
    bool CphsVoiceMailAvailable();
    bool EfCfisAvailable(int32_t size);
    void GetCphsMailBox();
    bool FillNumber(std::shared_ptr<unsigned char> efCfisData, int32_t efCfisSize, const std::string &number);
    bool VoiceMailNotEditToSim();
    bool IsAvailable(uint8_t offset, uint8_t mask);
    bool IsSimServiceAvailable(UsimService service);
    bool IsUsimServiceAvailable(UsimService service);
    bool IsServiceAvailable(UsimService service);
    friend class SimFileInit;
    std::shared_ptr<SimFileInit> simFileInit_;
    friend class SimFileParse;
    std::shared_ptr<SimFileParse> simFileParse_;
    std::string serviceTable_;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_FILE_H

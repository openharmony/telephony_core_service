/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ESIM_FILE_H
#define OHOS_ESIM_FILE_H

#include "apdu_command.h"
#include "asn1_builder.h"
#include "asn1_decoder.h"
#include "asn1_node.h"
#include "asn1_utils.h"
#include "esim_service.h"
#include "esim_state_type.h"
#include "icc_file.h"
#include "request_apdu_build.h"
#include "reset_response.h"
#include "tel_ril_sim_parcel.h"

namespace OHOS {
namespace Telephony {
constexpr static const int32_t NUMBER_ZERO = 0;
constexpr static const int32_t NUMBER_ONE = 1;
constexpr static const int32_t NUMBER_TWO = 2;
constexpr static const int32_t NUMBER_THREE = 3;
constexpr static const int32_t NUMBER_FOUR = 4;
constexpr static const int32_t NUMBER_FIVE = 5;
constexpr static const int32_t NUMBER_ELEVEN = 11;
constexpr static const int32_t PARAMETER_TWO = -1;
constexpr static const int32_t PROFILE_DEFAULT_NUMBER = 256;
constexpr static const int32_t WAIT_TIME_LONG_SECOND_FOR_ESIM = 20;
constexpr static const int32_t SW1_MORE_RESPONSE = 0x61;
constexpr static const int32_t INS_GET_MORE_RESPONSE = 0xC0;
constexpr static const int32_t SW1_VALUE_90 = 0x90;
constexpr static const int32_t SW2_VALUE_00 = 0x00;
static std::string ISDR_AID = "A0000005591010FFFFFFFF8900000100";
constexpr static const int32_t ATR_LENGTH = 47;
class EsimFile : public IccFile {
public:
    explicit EsimFile(std::shared_ptr<SimStateManager> simStateManager);
    int32_t ObtainSpnCondition(bool roaming, const std::string &operatorNum);
    bool ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event);
    bool UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber);
    bool SetVoiceMailCount(int32_t voiceMailCount);
    bool SetVoiceCallForwarding(bool enable, const std::string &number);
    std::string GetVoiceMailNumber();
    void SetVoiceMailNumber(const std::string mailNumber);
    void ProcessIccRefresh(int msgId);
    void ProcessFileLoaded(bool response);
    void OnAllFilesFetched();
    void StartLoad();
    ~EsimFile() = default;
    std::string ObtainEid();
    GetEuiccProfileInfoListResult GetEuiccProfileInfoList();
    EuiccInfo GetEuiccInfo();
    ResultState DisableProfile(int32_t portIndex, const std::u16string &iccId);
    std::string ObtainSmdsAddress(int32_t portIndex);
    EuiccRulesAuthTable ObtainRulesAuthTable(int32_t portIndex);
    ResponseEsimResult ObtainEuiccChallenge(int32_t portIndex);
    bool ProcessObtainEuiccChallenge(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainEuiccChallengeDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessDisableProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessDisableProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainSmdsAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainSmdsAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessRequestRulesAuthTable(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRequestRulesAuthTableDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RequestRulesAuthTableParseTagCtxComp0(std::shared_ptr<Asn1Node> &root);
    std::string ObtainDefaultSmdpAddress();
    ResponseEsimResult CancelSession(const std::u16string &transactionId, CancelReason cancelReason);
    EuiccProfile ObtainProfile(int32_t portIndex, const std::u16string &iccId);
    ResultState ResetMemory(ResetOption resetOption);
    ResultState SetDefaultSmdpAddress(const std::u16string &defaultSmdpAddress);
    bool IsEsimSupported();
    ResponseEsimResult SendApduData(const std::u16string &aid, const std::u16string &apduData);

private:
    using FileProcessFunc = std::function<bool(const AppExecFwk::InnerEvent::Pointer &event)>;
    void InitMemberFunc();
    void SyncCloseChannel();
    bool IsLogicChannelOpen();
    void ProcessEsimOpenChannel(const std::u16string &aid);
    bool ProcessEsimOpenChannelDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessEsimCloseChannel();
    bool ProcessEsimCloseChannelDone(const AppExecFwk::InnerEvent::Pointer &event);
    void SyncOpenChannel();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void SyncOpenChannel(const std::u16string &aid);
    void CopyApdCmdToReqInfo(ApduSimIORequestInfo *pReqInfo, ApduCommand *apdCmd);
    void CommBuildOneApduReqInfo(ApduSimIORequestInfo &reqInfo, std::shared_ptr<Asn1Builder> &builder);
    bool ProcessObtainEid(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainEidDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainEuiccInfo1(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainEuiccInfo1Done(const AppExecFwk::InnerEvent::Pointer &event);
    bool ObtainEuiccInfo1ParseTagCtx2(std::shared_ptr<Asn1Node> &root);
    bool ProcessRequestAllProfiles(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRequestAllProfilesDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RequestAllProfilesParseProfileInfo(std::shared_ptr<Asn1Node> &root);
    bool SplitMccAndMnc(const std::string mccMnc, std::string &mcc, std::string &mnc);
    void BuildBasicProfileInfo(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &profileNode);
    void BuildAdvancedProfileInfo(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &profileNode);
    void BuildOperatorId(EuiccProfileInfo *eProfileInfo, std::shared_ptr<Asn1Node> &operatorIdNode);
    void ConvertProfileInfoToApiStruct(EuiccProfile &dst, EuiccProfileInfo &src);
    std::shared_ptr<Asn1Node> ParseEvent(const AppExecFwk::InnerEvent::Pointer &event);
    std::string MakeVersionString(std::vector<uint8_t> &versionRaw);
    std::shared_ptr<Asn1Node> Asn1ParseResponse(const std::vector<uint8_t> &response, uint32_t respLength);
    bool ProcessObtainDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessCancelSession(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessCancelSessionDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    std::vector<uint8_t> GetProfileTagList();
    bool ProcessGetProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool GetProfileDoneParseProfileInfo(std::shared_ptr<Asn1Node> &root);
    bool ProcessResetMemory(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessResetMemoryDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool setDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool setDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSendApduData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessSendApduDataDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessEstablishDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessEstablishDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);

private:
    std::map<int32_t, FileProcessFunc> memberFuncMap_;
    int32_t nextSerialId_ = 0;
    int32_t currentChannelId_ = -1;
    int32_t slotId_ = 0;
    EsimProfile esimProfile_;
    std::string eid_ = "";
    std::string defaultDpAddress_ = "";
    ResultState delProfile_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState setDpAddressResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState switchResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState updateNicknameResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState resetResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState disableProfileResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState factoryResetResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState removeNotifResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    GetEuiccProfileInfoListResult euiccProfileInfoList_;
    EuiccInfo eUiccInfo_;
    EuiccProfile eUiccProfile_;
    std::string smdsAddress_ = "";
    EuiccRulesAuthTable eUiccRulesAuthTable_;
    ResponseEsimResult responseChallengeResult_;
    ResponseEsimResult responseInfo2Result_;
    ResponseEsimResult responseAuthenticateResult_;
    ResponseEsimResult preDownloadResult_;
    ResponseEsimBppResult loadBPPResult_;
    ResponseEsimResult cancelSessionResult_;
    EuiccNotification notification_;
    EuiccNotificationList eUiccNotificationList_;
    EuiccNotificationList retrieveNotificationList_;
    ResponseEsimResult transApduDataResponse_;
    bool isSupported_ = false;

    std::mutex closeChannelMutex_;
    std::condition_variable closeChannelCv_;

    std::mutex openChannelMutex_;
    std::condition_variable openChannelCv_;

    std::mutex getEidMutex_;
    std::condition_variable getEidCv_;
    bool isEidReady_ = false;

    std::mutex allProfileInfoMutex_;
    std::condition_variable allProfileInfoCv_;
    bool isAllProfileInfoReady_ = false;

    std::mutex euiccInfo1Mutex_;
    std::condition_variable euiccInfo1Cv_;
    bool isEuiccInfo1Ready_ = false;

    std::mutex disableProfileMutex_;
    std::condition_variable disableProfileCv_;
    bool isDisableProfileReady_ = false;

    std::mutex smdsAddressMutex_;
    std::condition_variable smdsAddressCv_;
    bool isSmdsAddressReady_ = false;

    std::mutex rulesAuthTableMutex_;
    std::condition_variable rulesAuthTableCv_;
    bool isRulesAuthTableReady_ = false;

    std::mutex euiccChallengeMutex_;
    std::condition_variable euiccChallengeCv_;
    bool isEuiccChallengeReady_ = false;

    std::mutex obtainDefaultSmdpAddressMutex_;
    std::condition_variable obtainDefaultSmdpAddressCv_;
    bool isObtainDefaultSmdpAddressReady_ = false;

    std::mutex cancelSessionMutex_;
    std::condition_variable cancelSessionCv_;
    bool isCancelSessionReady_ = false;

    std::mutex obtainProfileMutex_;
    std::condition_variable obtainProfileCv_;
    bool isObtainProfileReady_ = false;

    std::mutex resetMemoryMutex_;
    std::condition_variable resetMemoryCv_;
    bool isResetMemoryReady_ = false;

    std::mutex setDefaultSmdpAddressMutex_;
    std::condition_variable setDefaultSmdpAddressCv_;
    bool isSetDefaultSmdpAddressReady_ = false;

    std::mutex sendApduDataMutex_;
    std::condition_variable sendApduDataCv_;
    bool isSendApduDataReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H

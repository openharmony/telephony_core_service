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
#include "asn1_constants.h"
#include "download_profile_config_info_parcel.h"
#include "download_profile_result_parcel.h"
#include "downloadable_profile_parcel.h"
#include "esim_state_type.h"
#include "euicc_info_parcel.h"
#include "esim_service.h"
#include "get_downloadable_profiles_result_parcel.h"
#include "profile_info_list_parcel.h"
#include "profile_metadata_result_parcel.h"
#include "icc_file.h"
#include "request_apdu_build.h"
#include "reset_response.h"
#include "response_esim_result.h"
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
constexpr static const uint32_t OFFSET_FOUR_BIT = 4;
constexpr static const uint32_t VERSION_NUMBER = 11;
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
    ResponseEsimResult ObtainPrepareDownload(const DownLoadConfigInfo &downLoadConfigInfo);
    ResponseEsimBppResult ObtainLoadBoundProfilePackage(int32_t portIndex, const std::u16string boundProfilePackage);
    EuiccNotificationList ListNotifications(int32_t portIndex, Event events);
    EuiccNotificationList RetrieveNotificationList(int32_t portIndex, Event events);
    EuiccNotification ObtainRetrieveNotification(int32_t portIndex, int32_t seqNumber);
    ResultState RemoveNotificationFromList(int32_t portIndex, int32_t seqNumber);
    ResultState DeleteProfile(const std::u16string &iccId);
    ResultState SwitchToProfile(int32_t portIndex, const std::u16string &iccId, bool forceDisableProfile);
    ResultState SetProfileNickname(const std::u16string &iccId, const std::u16string &nickname);
    ResponseEsimResult ObtainEuiccInfo2(int32_t portIndex);
    ResponseEsimResult AuthenticateServer(const AuthenticateConfigInfo &authenticateConfigInfo);

private:
    using FileProcessFunc = std::function<bool(const AppExecFwk::InnerEvent::Pointer &event)>;
    void InitMemberFunc();
    void InitChanneMemberFunc();
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
    void Asn1AddChildAsBase64(std::shared_ptr<Asn1Builder> &builder, std::string &base64Src);
    bool ProcessPrepareDownload(int32_t slotId);
    bool ProcessPrepareDownloadDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool DecodeBoundProfilePackage(const std::string &boundProfilePackageStr, std::shared_ptr<Asn1Node> &bppNode);
    void BuildApduForInitSecureChannel(
        RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &initSecureChannelReq);
    void BuildApduForFirstSequenceOf87(RequestApduBuild &codec, std::shared_ptr<Asn1Node> &firstSequenceOf87);
    void BuildApduForSequenceOf88(RequestApduBuild &codec, std::shared_ptr<Asn1Node> &sequenceOf88);
    void BuildApduForSequenceOf86(RequestApduBuild &codec, std::shared_ptr<Asn1Node> &bppNode,
        std::shared_ptr<Asn1Node> &sequenceOf86);
    bool ProcessLoadBoundProfilePackage(int32_t slotId);
    bool ProcessLoadBoundProfilePackageDone(const AppExecFwk::InnerEvent::Pointer &event);
    std::shared_ptr<Asn1Node> LoadBoundProfilePackageParseProfileInstallResult(std::shared_ptr<Asn1Node> &root);
    bool LoadBoundProfilePackageParseNotificationMetadata(std::shared_ptr<Asn1Node> &notificationMetadata);
    bool RealProcessLoadBoundProfilePackageDone(std::string combineHexStr);
    bool ProcessListNotifications(
        int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessListNotificationsDone(const AppExecFwk::InnerEvent::Pointer &event);
    void createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification &euicc);
    bool ProcessListNotificationsAsn1Response(std::shared_ptr<Asn1Node> &root);
    void SplitSendLongData(int32_t slotId, std::string hexStr, int32_t esimMessageId);
    bool MergeRecvLongDataComplete(IccFileData &fileData, int32_t eventId);
    void ConvertPreDownloadParaFromApiStru(PrepareDownloadResp& dst, EsimProfile& src);
    bool CombineResponseDataFinish(IccFileData &fileData);
    void ProcessIfNeedMoreResponse(IccFileData &fileData, int32_t eventId);
    bool ProcessRetrieveNotificationList(
        int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRetrieveNotificationListDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RetrieveNotificationParseCompTag(std::shared_ptr<Asn1Node> &root);
    bool ProcessRetrieveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRetrieveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RetrieveNotificatioParseTagCtxComp0(std::shared_ptr<Asn1Node> &root);
    bool ProcessRemoveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRemoveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessDeleteProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessDeleteProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSwitchToProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessSwitchToProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetNickname(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessSetNicknameDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainEuiccInfo2(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainEuiccInfo2Done(const AppExecFwk::InnerEvent::Pointer &event);
    void EuiccInfo2ParseProfileVersion(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseSvn(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccFirmwareVer(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseExtCardResource(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseUiccCapability(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseTs102241Version(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseGlobalPlatformVersion(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseRspCapability(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccCiPKIdListForVerification(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccCiPKIdListForSigning(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccCategory(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParsePpVersion(EuiccInfo2 &euiccInfo2, std::shared_ptr<Asn1Node> &root);
    bool ProcessAuthenticateServer(int32_t slotId);
    bool ProcessAuthenticateServerDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RealProcsessAuthenticateServerDone(std::string combineHexStr);
    void AddDeviceCapability(std::shared_ptr<Asn1Builder> &devCapsBuilder);
    void AddCtxParams1(std::shared_ptr<Asn1Builder> &ctxParams1Builder, Es9PlusInitAuthResp &pbytes);
    void GetImeiBytes(std::vector<uint8_t> &imeiBytes, const std::string &imei);
    void CovertAuthToApiStruct(ResponseEsimResult &dst, AuthServerResponse &src);
    void ConvertAuthInputParaFromApiStru(Es9PlusInitAuthResp &dst, EsimProfile &src);

private:
    std::map<int32_t, FileProcessFunc> memberFuncMap_;
    std::atomic_int nextSerialId_ = 0;
    int32_t currentChannelId_ = -1;
    int32_t slotId_ = 0;
    EsimProfile esimProfile_;
    std::string eid_ = "";
    std::string defaultDpAddress_ = "";
    ResultState delProfile_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState setDpAddressResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState switchResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState setNicknameResult_ = ResultState::RESULT_UNDEFINED_ERROR;
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
    std::string recvCombineStr_ = "";

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

    std::mutex prepareDownloadMutex_;
    std::condition_variable prepareDownloadCv_;
    bool isPrepareDownloadReady_ = false;

    std::mutex loadBppMutex_;
    std::condition_variable loadBppCv_;
    bool isLoadBppReady_ = false;

    std::mutex listNotificationsMutex_;
    std::condition_variable listNotificationsCv_;
    bool isListNotificationsReady_ = false;

    std::mutex retrieveNotificationListMutex_;
    std::condition_variable retrieveNotificationListCv_;
    bool isRetrieveNotificationListReady_ = false;

    std::mutex retrieveNotificationMutex_;
    std::condition_variable retrieveNotificationCv_;
    bool isRetrieveNotificationReady_ = false;

    std::mutex removeNotificationMutex_;
    std::condition_variable removeNotificationCv_;
    bool isRemoveNotificationReady_ = false;

    std::mutex deleteProfileMutex_;
    std::condition_variable deleteProfileCv_;
    bool isDeleteProfileReady_ = false;

    std::mutex switchToProfileMutex_;
    std::condition_variable switchToProfileCv_;
    bool isSwitchToProfileReady_ = false;

    std::mutex setNicknameMutex_;
    std::condition_variable setNicknameCv_;
    bool isSetNicknameReady_ = false;

    std::mutex euiccInfo2Mutex_;
    std::condition_variable euiccInfo2Cv_;
    bool isEuiccInfo2Ready_ = false;

    std::mutex authenticateServerMutex_;
    std::condition_variable authenticateServerCv_;
    bool isAuthenticateServerReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H

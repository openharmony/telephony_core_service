/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef TEL_RIL_CALLBACK_H
#define TEL_RIL_CALLBACK_H

#include <v1_0/iril_interface.h>

#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
class TelRilCallback : public HDI::Ril::V1_0::IRilCallback {
public:
    explicit TelRilCallback(std::shared_ptr<TelRilManager> telRilManager);
    ~TelRilCallback() = default;

    // Call
    int32_t CallEmergencyNotice(int32_t slotId, const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList) override;
    int32_t CallStateUpdated(int32_t slotId, int32_t type) override;
    int32_t CallRingbackVoiceNotice(int32_t slotId, const HDI::Ril::V1_0::IRingbackVoice &ringbackVoice) override;
    int32_t CallSrvccStatusNotice(int32_t slotId, const HDI::Ril::V1_0::ISrvccStatus &srvccStatus) override;
    int32_t CallUssdNotice(int32_t slotId, const HDI::Ril::V1_0::IUssdNoticeInfo &ussdNoticeInfo) override;
    int32_t CallSsNotice(int32_t slotId, const HDI::Ril::V1_0::ISsNoticeInfo &ssNoticeInfo) override;

    int32_t SetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList) override;
    int32_t GetCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICallInfoList &callList) override;
    int32_t DialResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t HangupResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t RejectResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t AnswerResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t HoldCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t UnHoldCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SwitchCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetClipResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IGetClipResult &getClipResult) override;
    int32_t SetClipResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t CombineConferenceResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SeparateConferenceResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t CallSupplementResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetCallWaitingResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICallWaitResult &callWaitResult) override;
    int32_t SetCallWaitingResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetCallTransferInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICallForwardQueryInfoList &cFQueryList) override;
    int32_t SetCallTransferInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetCallRestrictionResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICallRestrictionResult &result) override;
    int32_t SetCallRestrictionResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetClirResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IGetClirResult &getClirResult) override;
    int32_t SetClirResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t StartDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SendDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t StopDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetCallPreferenceModeResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t mode) override;
    int32_t SetCallPreferenceModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetUssdResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetUssdResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t cusd) override;
    int32_t SetMuteResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetMuteResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t mute) override;
    int32_t GetCallFailReasonResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t callFail) override;
    int32_t SetBarringPasswordResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;

    // Data
    int32_t PdpContextListUpdated(
        int32_t slotId, const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList) override;
    int32_t ActivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISetupDataCallResultInfo &setupDataCallResultInfo) override;
    int32_t DeactivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetPdpContextListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList) override;
    int32_t SetInitApnInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetLinkBandwidthReportingRuleResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetLinkBandwidthInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IDataLinkBandwidthInfo &dataLinkBandwidthInfo) override;
    int32_t SetDataPermittedResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;

    // Modem
    int32_t RadioStateUpdated(int32_t slotId, int32_t state) override;
    int32_t VoiceRadioTechUpdated(
        int32_t slotId, const HDI::Ril::V1_0::IVoiceRadioTechnology &voiceRadioTechnology) override;
    int32_t ShutDownResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetRadioStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetRadioStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t state) override;
    int32_t GetImeiResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &imei) override;
    int32_t GetMeidResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &meid) override;
    int32_t GetVoiceRadioTechnologyResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IVoiceRadioTechnology &voiceRadioTechnology) override;
    int32_t GetBasebandVersionResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &basebandVersion) override;

    // sim notice
    int32_t SimStateUpdated(int32_t slotId) override;
    int32_t SimStkSessionEndNotify(int32_t slotId) override;
    int32_t SimStkProactiveNotify(int32_t slotId, const std::string &response) override;
    int32_t SimStkAlphaNotify(int32_t slotId, const std::string &response) override;
    int32_t SimStkEventNotify(int32_t slotId, const std::string &response) override;
    int32_t SimStkCallSetupNotify(int32_t slotId) override;
    int32_t SimRefreshNotify(int32_t slotId) override;
    // sim response
    int32_t GetSimIOResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IIccIoResultInfo &result) override;
    int32_t GetSimStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICardStatusInfo &result) override;
    int32_t GetImsiResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &response) override;
    int32_t GetSimLockStatusResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t simLockStatus) override;
    int32_t SetSimLockResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;
    int32_t ChangeSimPasswordResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;
    int32_t UnlockPinResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;
    int32_t UnlockPukResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;
    int32_t UnlockPin2Response(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;
    int32_t UnlockPuk2Response(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;
    int32_t SetActiveSimResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SimStkSendTerminalResponseResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SimStkSendEnvelopeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SimStkSendCallSetupRequestResultResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SimStkIsReadyResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetRadioProtocolResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISimProtocolResponse &pSimProtocol) override;
    int32_t SimOpenLogicalChannelResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IOpenLogicalChannelResponse &pOpenLogicalChannelResponse) override;
    int32_t SimCloseLogicalChannelResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SimTransmitApduLogicalChannelResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IIccIoResultInfo &result) override;
    int32_t SimTransmitApduBasicChannelResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IIccIoResultInfo &result) override;
    int32_t SimAuthenticationResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IIccIoResultInfo &result) override;
    int32_t UnlockSimLockResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ILockStatusResp &lockStatus) override;

    // Network
    int32_t NetworkCsRegStatusUpdated(int32_t slotId, const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo) override;
    int32_t NetworkPsRegStatusUpdated(int32_t slotId, const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo) override;
    int32_t SignalStrengthUpdated(int32_t slotId, const HDI::Ril::V1_0::IRssi &rssi) override;
    int32_t NetworkTimeZoneUpdated(int32_t slotId, const  std::string &timeZoneStr) override;
    int32_t NetworkTimeUpdated(int32_t slotId, const std::string &timeStr) override;
    int32_t NetworkPhyChnlCfgUpdated(
        int32_t slotId, const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList) override;
    int32_t NetworkCurrentCellUpdated(
        int32_t slotId, const HDI::Ril::V1_0::ICellListCurrentInfo &cellListCurrentInfo) override;
    int32_t GetSignalStrengthResponse(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IRssi &rssi) override;
    int32_t GetCsRegStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo) override;
    int32_t GetPsRegStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo) override;
    int32_t GetOperatorInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IOperatorInfo &operatorInfo) override;
    int32_t GetNetworkSearchInformationResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IAvailableNetworkList &availableNetworkList) override;
    int32_t GetNetworkSelectionModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISetNetworkModeInfo &setNetworkModeInfo) override;
    int32_t SetNetworkSelectionModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetNeighboringCellInfoListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICellListNearbyInfo &cellInfoList) override;
    int32_t GetCurrentCellInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICellListCurrentInfo &cellInfoList) override;
    int32_t SetPreferredNetworkResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetPreferredNetworkResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IPreferredNetworkTypeInfo &preferredNetworkTypeInfo) override;
    int32_t GetRadioCapabilityResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IRadioCapabilityInfo &radioCapabilityInfo) override;
    int32_t GetPhysicalChannelConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList) override;
    int32_t SetLocateUpdatesResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetNotificationFilterResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetDeviceStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;

    // Sms
    int32_t NewSmsNotify(int32_t slotId, const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo) override;
    int32_t NewCdmaSmsNotify(int32_t slotId, const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo) override;
    int32_t SmsStatusReportNotify(int32_t slotId, const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo) override;
    int32_t NewSmsStoredOnSimNotify(int32_t slotId, int32_t recordNumber, int32_t indicationType) override;
    int32_t CBConfigNotify(
        int32_t slotId, const HDI::Ril::V1_0::ICBConfigReportInfo &cellBroadConfigReportInfo) override;
    int32_t SendGsmSmsResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &sendSmsResultInfo) override;
    int32_t SendCdmaSmsResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &sendSmsResultInfo) override;
    int32_t AddSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t DelSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t UpdateSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t AddCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t DelCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t UpdateCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetSmscAddrResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetSmscAddrResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IServiceCenterAddress &serviceCenterAddress) override;
    int32_t SetCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICBConfigInfo &cellBroadcastInfo) override;
    int32_t SetCdmaCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetCdmaCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICdmaCBConfigInfo &cdmaCBConfigInfo) override;
    int32_t SendSmsMoreModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &sendSmsResultInfo) override;
    int32_t SendSmsAckResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;

private:
    template<typename FuncType, typename ModuleFuncType, typename... ParamTypes>
    inline int32_t TaskSchedule(
        int32_t slotId, FuncType &&_func, ModuleFuncType _moduleFunc, ParamTypes &&... _args) const
    {
        if (telRilManager_ == nullptr || _func == nullptr || _moduleFunc == nullptr) {
            TELEPHONY_LOGE("telRilManager_  or _func or _moduleFunc is nullptr ");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return ((telRilManager_.get()->*(_func))(slotId).*(_moduleFunc))(std::forward<ParamTypes>(_args)...);
    }

private:
    std::shared_ptr<TelRilManager> telRilManager_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_CALLBACK_H

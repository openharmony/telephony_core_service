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

#include "tel_ril_manager.h"

#include "hdf_death_recipient.h"

#include "telephony_errors.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
TelRilManager::TelRilManager() : IPCObjectStub(std::u16string(u""))
{
}

TelRilManager::~TelRilManager()
{
}

int32_t TelRilManager::SetCellularRadioIndication(bool isFirst)
{
    int32_t ret = RIL_ADAPTER_ERROR;
    if (cellularRadio_ != nullptr) {
        sptr<OHOS::IPCObjectStub> callback = this;
        MessageParcel data;
        MessageParcel reply;
        /* Prevent OHOS::IPCObjectStub from getting abnormal. */
        if (isFirst) {
            telRilCallback_ = callback;
        } else {
            callback = telRilCallback_;
        }
        data.WriteRemoteObject(callback);
        OHOS::MessageOption option;
        ret = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_INDICATION, data, reply, option);
        TELEPHONY_LOGI("SetCellularRadioIndication ret:%{public}d", ret);
    }
    return ret;
}

int32_t TelRilManager::SetCellularRadioResponse(bool isFirst)
{
    int ret = RIL_ADAPTER_ERROR;
    if (cellularRadio_ != nullptr) {
        sptr<OHOS::IPCObjectStub> callback = this;
        MessageParcel data;
        MessageParcel reply;
        /* Prevent OHOS::IPCObjectStub from getting abnormal. */
        if (isFirst) {
            telRilCallback_ = callback;
        } else {
            callback = telRilCallback_;
        }
        data.WriteRemoteObject(callback);
        OHOS::MessageOption option;
        ret = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_RESPONSE, data, reply, option);
        TELEPHONY_LOGI("SetCellularRadioResponse ret:%{public}d", ret);
    }
    return ret;
}

int TelRilManager::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::MessageOption &option)
{
    TELEPHONY_LOGI("TelRilManager OnRemoteRequest code:%{public}d", code);
    if (telRilCall_ != nullptr && telRilCall_->IsCallRespOrNotify(code)) {
        telRilCall_->ProcessCallRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilSms_ != nullptr && telRilSms_->IsSmsRespOrNotify(code)) {
        telRilSms_->ProcessSmsRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilSim_ != nullptr && telRilSim_->IsSimRespOrNotify(code)) {
        telRilSim_->ProcessSimRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilNetwork_ != nullptr && telRilNetwork_->IsNetworkRespOrNotify(code)) {
        telRilNetwork_->ProcessNetworkRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilData_ != nullptr && telRilData_->IsDataRespOrNotify(code)) {
        telRilData_->ProcessDataRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    /* The common notice should be placed last. */
    if (telRilModem_ != nullptr && telRilModem_->IsCommonRespOrNotify(code)) {
        telRilModem_->ProcessCommonRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    return CORE_SERVICE_SUCCESS;
}

void TelRilManager::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    preferredNetworkType_ = preferredNetworkType;
    cdmaSubscription_ = cdmaSubscription;
    slotId_ = instanceId;
    observerHandler_ = std::make_shared<ObserverHandler>();
}

bool TelRilManager::OnInit()
{
    bool res = false;
    int i = 0;

    do {
        res = InitCellularRadio(true);
        if (!res) {
            i++;
            sleep(1);
        } else {
            InitTelInfo();
        }
    } while (!res && (i < RIL_INIT_COUNT_MAX));
    return res;
}

bool TelRilManager::InitCellularRadio(bool isFirst)
{
    int i = 0;
    cellularRadio_ = nullptr;
    auto servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    while (servMgr_ == nullptr) {
        TELEPHONY_LOGI("bind hdf error! time:%{public}d", i++);
        sleep(1);
        servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    }
    cellularRadio_ = servMgr_->GetService(RIL_ADAPTER_SERVICE_NAME);
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("bind hdf%{public}d error!", slotId_);
        return false;
    }
    sptr<IRemoteObject::DeathRecipient> death_ =
        sptr<IRemoteObject::DeathRecipient>(new HdfDeathRecipient(slotId_));
    if (death_ == nullptr) {
        TELEPHONY_LOGE("create HdfDeathRecipient object failed!");
        return false;
    }
    bool res = cellularRadio_->AddDeathRecipient(death_);
    if (!res) {
        TELEPHONY_LOGE("AddDeathRecipient hdfId:%{public}d failed!", slotId_);
        return false;
    }
    if (SetCellularRadioIndication(isFirst)) {
        TELEPHONY_LOGE("SetCellularRadioIndication error ");
        return false;
    }
    if (SetCellularRadioResponse(isFirst)) {
        TELEPHONY_LOGE("SetCellularRadioResponse error ");
        return false;
    }
    return true;
}

void TelRilManager::InitTelInfo()
{
    telRilSms_ = std::make_unique<TelRilSms>(cellularRadio_, observerHandler_);
    if (telRilSms_ == nullptr) {
        TELEPHONY_LOGE("create TelRilSms object failed!");
        return;
    }
    telRilSim_ = std::make_unique<TelRilSim>(cellularRadio_, observerHandler_);
    if (telRilSim_ == nullptr) {
        TELEPHONY_LOGE("create TelRilSim object failed!");
        return;
    }
    telRilCall_ = std::make_unique<TelRilCall>(cellularRadio_, observerHandler_);
    if (telRilCall_ == nullptr) {
        TELEPHONY_LOGE("create TelRilCall object failed!");
        return;
    }
    telRilNetwork_ = std::make_unique<TelRilNetwork>(cellularRadio_, observerHandler_);
    if (telRilNetwork_ == nullptr) {
        TELEPHONY_LOGE("create TelRilNetwork object failed!");
        return;
    }
    telRilModem_ = std::make_unique<TelRilModem>(cellularRadio_, observerHandler_);
    if (telRilModem_ == nullptr) {
        TELEPHONY_LOGE("create TelRilModem object failed!");
        return;
    }
    telRilData_ = std::make_unique<TelRilData>(cellularRadio_, observerHandler_);
    if (telRilData_ == nullptr) {
        TELEPHONY_LOGE("create TelRilData object failed!");
        return;
    }
}

void TelRilManager::RegisterCoreNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what, void *obj)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        switch (what) {
            case ObserverHandler::RADIO_ICC_STATUS_CHANGED:
                observerHandler_->RegObserver(what, observerCallBack);
                observerHandler_->NotifyObserver(ObserverHandler::RADIO_ICC_STATUS_CHANGED);
                break;
            case ObserverHandler::RADIO_OFF:
                observerHandler_->RegObserver(what, observerCallBack);
                if (telRilModem_->radioState_ == CORE_SERVICE_POWER_OFF ||
                    CORE_SERVICE_POWER_NOT_AVAILABLE == telRilModem_->radioState_) {
                    observerHandler_->NotifyObserver(what);
                }
                break;
            default:
                TELEPHONY_LOGI("RegisterCoreNotify default what:%{public}d", what);
                observerHandler_->RegObserver(what, observerCallBack);
                break;
        }
    }
}

void TelRilManager::UnRegisterCoreNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        observerHandler_->Remove(what, observerCallBack);
    } else {
        TELEPHONY_LOGE("observerHandler_ is null");
    }
}

void TelRilManager::PrintErrorLog(const char *moduleName, const uint8_t *objPtr, const char *errStr) const
{
    TELEPHONY_LOGE("%{public}s - this %{public}p: %{public}s", moduleName, objPtr, errStr);
}

void TelRilManager::SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilModem", telRilModem_, &TelRilModem::SetRadioState, fun, rst);
}

void TelRilManager::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilModem", telRilModem_, &TelRilModem::GetRadioState);
}

void TelRilManager::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilModem", telRilModem_, &TelRilModem::ShutDown);
}

void TelRilManager::GetImei(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilModem", telRilModem_, &TelRilModem::GetImei);
}

void TelRilManager::GetMeid(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilModem", telRilModem_, &TelRilModem::GetMeid);
}

void TelRilManager::GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilModem", telRilModem_, &TelRilModem::GetVoiceRadioTechnology);
}

void TelRilManager::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::Dial, address, clirMode);
}

void TelRilManager::Reject(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::Reject);
}

void TelRilManager::HoldCall(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::HoldCall);
}

void TelRilManager::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::UnHoldCall);
}

void TelRilManager::SwitchCall(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SwitchCall);
}

void TelRilManager::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::Hangup, gsmIndex);
}

void TelRilManager::Answer(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::Answer);
}

void TelRilManager::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::CombineConference, callType);
}

void TelRilManager::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SeparateConference, callIndex, callType);
}

void TelRilManager::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::CallSupplement, type);
}

void TelRilManager::GetCallList(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetCallList);
}

void TelRilManager::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetCallWaiting);
}

void TelRilManager::SetCallWaiting(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetCallWaiting, activate);
}

void TelRilManager::GetCallTransferInfo(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetCallTransferInfo, reason);
}

void TelRilManager::SetCallTransferInfo(const int32_t reason, const int32_t mode, std::string number,
    const int32_t classx, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(
        response, "TelRilCall", telRilCall_, &TelRilCall::SetCallTransferInfo, reason, mode, number, classx);
}

void TelRilManager::GetClip(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetClip);
}

void TelRilManager::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetClip, action);
}

void TelRilManager::GetClir(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetClir);
}

void TelRilManager::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetClir, action);
}

void TelRilManager::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetCallRestriction, fac);
}

void TelRilManager::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetCallRestriction, fac, mode, password);
}

void TelRilManager::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    // Define the function pointer type here, it is necessary to deal with
    // the function pointer difference caused by overloading
    typedef void (TelRilCall::*SendDtmfFunc)(
        const std::string &, int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &);
    TaskSchedule(response, "TelRilCall", telRilCall_, (SendDtmfFunc)&TelRilCall::SendDtmf, sDTMFCode, index,
        switchOn, switchOff);
}

void TelRilManager::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    // Define the function pointer type here, it is necessary to deal with
    // the function pointer difference caused by overloading
    typedef void (TelRilCall::*SendDtmfFunc)(char, int32_t, const AppExecFwk::InnerEvent::Pointer &);
    TaskSchedule(response, "TelRilCall", telRilCall_, (SendDtmfFunc)&TelRilCall::SendDtmf, cDTMFCode, index);
}

void TelRilManager::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::StartDtmf, cDTMFCode, index);
}

void TelRilManager::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::StopDtmf, index);
}

int32_t TelRilManager::SetInitApnInfo(CellularDataProfile dataProfile, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilData", telRilData_, &TelRilData::SetInitApnInfo, dataProfile);
    return TELEPHONY_SUCCESS;
}

int32_t TelRilManager::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilData", telRilData_, &TelRilData::ActivatePdpContext, radioTechnology, dataProfile,
        isRoaming, allowRoaming);
    return TELEPHONY_SUCCESS;
}

int32_t TelRilManager::DeactivatePdpContext(
    int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilData", telRilData_, &TelRilData::DeactivatePdpContext, cid, reason);
    return TELEPHONY_SUCCESS;
}

int32_t TelRilManager::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilData", telRilData_, &TelRilData::GetPdpContextList);
    return TELEPHONY_SUCCESS;
}

int32_t TelRilManager::SetLinkBandwidthReportingRule(
    LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilData", telRilData_, &TelRilData::SetLinkBandwidthReportingRule, linkBandwidth);
    return TELEPHONY_SUCCESS;
}

int32_t TelRilManager::GetLinkBandwidthInfo(
    const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilData", telRilData_, &TelRilData::GetLinkBandwidthInfo, cid);
    return TELEPHONY_SUCCESS;
}

void TelRilManager::GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetImsRegStatus);
}

void TelRilManager::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetSignalStrength);
}

void TelRilManager::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetCsRegStatus);
}

void TelRilManager::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetPsRegStatus);
}

void TelRilManager::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetOperatorInfo);
}

void TelRilManager::SetPsAttachStatus(int32_t psAttachStatus, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::SetPsAttachStatus, psAttachStatus);
}

void TelRilManager::GetPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetPsAttachStatus);
}

void TelRilManager::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetNetworkSearchInformation);
}

void TelRilManager::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetNetworkSelectionMode);
}

void TelRilManager::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(
        response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::SetNetworkSelectionMode, automaticFlag, oper);
}

void TelRilManager::GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetPreferredNetwork);
}

void TelRilManager::SetPreferredNetwork(
    int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(
        response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::SetPreferredNetwork, preferredNetworkType);
}

void TelRilManager::GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetCellInfoList);
}

void TelRilManager::GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetCurrentCellInfo);
}
void TelRilManager::GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetRadioCapability);
}

void TelRilManager::SetRadioCapability(
    RadioCapabilityInfo &radioCapabilityInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::SetRadioCapability, radioCapabilityInfo);
}

void TelRilManager::GetPhysicalChannelConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::GetPhysicalChannelConfig);
}

void TelRilManager::SetLocateUpdates(HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilNetwork", telRilNetwork_, &TelRilNetwork::SetLocateUpdates, mode);
}

void TelRilManager::SendGsmSms(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SendGsmSms, smscPdu, pdu);
}

void TelRilManager::SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SendCdmaSms, pdu);
}

void TelRilManager::AddSimMessage(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::AddSimMessage, status, smscPdu, pdu);
}

void TelRilManager::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::DelSimMessage, gsmIndex);
}

void TelRilManager::UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::UpdateSimMessage, gsmIndex, state, smscPdu, pdu);
}

void TelRilManager::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::GetSmscAddr);
}

void TelRilManager::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::GetCdmaCBConfig);
}

void TelRilManager::SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SetSmscAddr, tosca, address);
}

void TelRilManager::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SetCBConfig, mode, idList, dcsList);
}

void TelRilManager::SetCdmaCBConfig(
    CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SetCdmaCBConfig, cdmaCBConfigInfoList);
}

void TelRilManager::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::GetCBConfig);
}

void TelRilManager::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SendSmsMoreMode, smscPdu, pdu);
}

void TelRilManager::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::SendSmsAck, success, cause);
}

void TelRilManager::AddCdmaSimMessage(
    int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::AddCdmaSimMessage, status, pdu);
}

void TelRilManager::DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::DelCdmaSimMessage, cdmaIndex);
}

void TelRilManager::UpdateCdmaSimMessage(
    int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSms", telRilSms_, &TelRilSms::UpdateCdmaSimMessage, cdmaIndex, state, pdu);
}

void TelRilManager::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::GetSimStatus);
}

void TelRilManager::GetSimIO(SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::GetSimIO, data);
}

void TelRilManager::GetImsi(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::GetImsi);
}

void TelRilManager::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::GetSimLockStatus, fac);
}

void TelRilManager::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::SetSimLock, fac, mode, passwd);
}

void TelRilManager::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::ChangeSimPassword, fac, oldPassword, newPassword,
        passwordLength);
}

void TelRilManager::UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::UnlockPin, pin);
}

void TelRilManager::UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::UnlockPuk, puk, pin);
}

void TelRilManager::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::GetSimPinInputTimes);
}
void TelRilManager::UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::UnlockPin2, pin2);
}

void TelRilManager::UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::UnlockPuk2, puk2, pin2);
}

void TelRilManager::GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::GetSimPin2InputTimes);
}

void TelRilManager::SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::SetActiveSim, index, enable);
}

void TelRilManager::SendTerminalResponseCmd(
    const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::SendTerminalResponseCmd, strCmd);
}

void TelRilManager::SendEnvelopeCmd(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::SendEnvelopeCmd, strCmd);
}

void TelRilManager::StkControllerIsReady(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::StkControllerIsReady);
}

void TelRilManager::StkCmdCallSetup(int32_t flagAccept, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::StkCmdCallSetup, flagAccept);
}

void TelRilManager::OpenLogicalSimIO(
    const std::string &appID, const int32_t p2, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::OpenLogicalSimIO, appID.substr(0), p2);
}

void TelRilManager::CloseLogicalSimIO(const int32_t chanID, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::CloseLogicalSimIO, chanID);
}

void TelRilManager::TransmitApduSimIO(ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::TransmitApduSimIO, reqInfo);
}

void TelRilManager::UnlockSimLock(int32_t lockType, std::string password,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::UnlockSimLock, lockType, password);
}

void TelRilManager::GetImsCallList(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetImsCallList);
}

void TelRilManager::SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetCallPreferenceMode, mode);
}

void TelRilManager::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetCallPreferenceMode);
}

void TelRilManager::SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetLteImsSwitchStatus, active);
}

void TelRilManager::GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetLteImsSwitchStatus);
}

void TelRilManager::SetRadioProtocol(SimProtocolRequest data, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilSim", telRilSim_, &TelRilSim::SetRadioProtocol, data);
}

void TelRilManager::SetUssdCusd(const std::string str, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetUssdCusd, str);
}

void TelRilManager::GetUssdCusd(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetUssdCusd);
}

void TelRilManager::SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::SetMute, mute);
}

void TelRilManager::GetMute(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetMute);
}

void TelRilManager::GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetEmergencyCallList);
}

void TelRilManager::GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &response)
{
    TaskSchedule(response, "TelRilCall", telRilCall_, &TelRilCall::GetCallFailReason);
}
} // namespace Telephony
} // namespace OHOS

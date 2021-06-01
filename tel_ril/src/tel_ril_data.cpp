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
#include "tel_ril_data.h"
#include "hril_call_parcel.h"
#include "hril_modem_parcel.h"

namespace OHOS {
void TelRilData::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_DATA_PDP_CONTEXT_LIST_UPDATED] = &TelRilData::PdpContextListUpdated;
    // response
    memberFuncMap_[HREQ_DATA_ACTIVATE_PDP_CONTEXT] = &TelRilData::ActivatePdpContextResponse;
    memberFuncMap_[HREQ_DATA_DEACTIVATE_PDP_CONTEXT] = &TelRilData::DeactivatePdpContextResponse;
}

TelRilData::TelRilData(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilData::IsDataResponse(uint32_t code)
{
    return code >= HREQ_DATA_BASE && code < HREQ_NETWORK_BASE;
}

bool TelRilData::IsDataNotification(uint32_t code)
{
    return code >= HNOTI_DATA_BASE && code < HNOTI_NETWORK_BASE;
}

bool TelRilData::IsDataRespOrNotify(uint32_t code)
{
    return IsDataResponse(code) || IsDataNotification(code);
}

void TelRilData::ProcessDataRespOrNotify(uint32_t code, OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG(
        "TelRilData ProcessDataRespOrNotify code:%{public}d, GetDataSize:%{public}d", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

DataProfileDataInfo TelRilData::ChangeDPToHalDataProfile(CellularDataProfile dataProfile)
{
    DataProfileDataInfo dataProfileInfo;
    dataProfileInfo.profileId = dataProfile.profileId;
    dataProfileInfo.password = dataProfile.password;
    dataProfileInfo.verType = dataProfile.verType;
    dataProfileInfo.userName = dataProfile.userName;
    dataProfileInfo.apn = dataProfile.apn;
    dataProfileInfo.protocol = dataProfile.protocol;
    dataProfileInfo.roamingProtocol = dataProfile.roamingProtocol;
    return dataProfileInfo;
}

void TelRilData::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManagerBase::DeactivatePdpContext -->");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("RilManager DeactivatePdpContext:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG(
            "DeactivatePdpContext --> telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
        UniInfo uniInfo;
        uniInfo.serial = telRilRequest->serialId_;
        uniInfo.gsmIndex = cid;
        uniInfo.arg1 = reason;
        OHOS::MessageParcel wData;
        uniInfo.Marshalling(wData);
        int ret = SendBufferEvent(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, wData);
        TELEPHONY_INFO_LOG(
            "DeactivatePdpContext --> SendBufferEvent(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, "
            "wData) "
            "return ID: %{public}d",
            ret);
    } else {
        TELEPHONY_ERR_LOG("ERROR : DeactivatePdpContext --> cellularRadio_ == nullptr");
    }
}

void TelRilData::DeactivatePdpContextResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilData::DeactivatePdpContextResponse --> ");
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("DeactivatePdpContextResponse --> ReadBuffer(data) failed !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "DeactivatePdpContextResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : DeactivatePdpContextResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            uint64_t param = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, param, 0);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilData::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilData::ActivatePdpContext -->");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilData ActivatePdpContext:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("ActivatePdpContext --> telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
        DataCallInfo dataCallInfo;
        dataCallInfo.serial = telRilRequest->serialId_;
        dataCallInfo.radioTechnology = radioTechnology;
        dataCallInfo.dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
        dataCallInfo.roamingAllowed = allowRoaming;
        dataCallInfo.isRoaming = isRoaming;
        OHOS::MessageParcel wData;
        dataCallInfo.Marshalling(wData);
        OHOS::MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, wData, reply, option);
        TELEPHONY_INFO_LOG(
            "ActivatePdpContext --> SendBufferEvent(HREQ_DATA_ACTIVATE_PDP_CONTEXT, wData) return "
            "ID: %{public}d",
            ret);
    } else {
        TELEPHONY_ERR_LOG("ERROR : ActivatePdpContext --> cellularRadio_ == nullptr");
    }
}

void TelRilData::ActivatePdpContextResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilData::ActivatePdpContextResponse --> ");
    std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
    if (setupDataCallResultInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : ActivatePdpContextResponse --> setupDataCallResultInfo == nullptr failed !!!");
        return;
    }
    setupDataCallResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : ActivatePdpContextResponse --> spBuffer == nullptr !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "ActivatePdpContextResponse -->  radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : ActivatePdpContextResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
            TELEPHONY_DEBUG_LOG("ActivatePdpContextResponse -->  setupDataCallResultInfo->flag:%{public}d",
                setupDataCallResultInfo->flag);
            handler->SendEvent(eventId, setupDataCallResultInfo);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    } else {
        TELEPHONY_ERR_LOG(
            "ERROR : ActivatePdpContextResponse --> "
            "telRilRequest == nullptr || radioResponseInfo error !");
    }
}

void TelRilData::PdpContextListUpdated(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilData::PdpContextListUpdated --> ");
    std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
    if (setupDataCallResultInfo == nullptr) {
        TELEPHONY_ERR_LOG("PdpContextListUpdated setupDataCallResultInfo is nullptr");
        return;
    }
    setupDataCallResultInfo->ReadFromParcel(data);
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        RilProcessIndication(indicationType);
        TELEPHONY_DEBUG_LOG("TelRilData::PdpContextListUpdated indicationType:%{public}d", indicationType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_DATA_CALL_LIST_CHANGED, setupDataCallResultInfo);
    }
}
} // namespace OHOS

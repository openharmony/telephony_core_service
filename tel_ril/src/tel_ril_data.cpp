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
#include "hril_modem_parcel.h"

namespace OHOS {
namespace Telephony {
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
    return ((code >= HREQ_DATA_BASE) && (code < HREQ_NETWORK_BASE));
}

bool TelRilData::IsDataNotification(uint32_t code)
{
    return ((code >= HNOTI_DATA_BASE) && (code < HNOTI_NETWORK_BASE));
}

bool TelRilData::IsDataRespOrNotify(uint32_t code)
{
    return IsDataResponse(code) || IsDataNotification(code);
}

void TelRilData::ProcessDataRespOrNotify(uint32_t code, MessageParcel &data)
{
    TELEPHONY_LOGD("code:%{public}d, GetDataSize:%{public}zu", code, data.GetDataSize());
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
    dataProfileInfo.profileId = dataProfile.profileId_;
    dataProfileInfo.password = dataProfile.password_;
    dataProfileInfo.verType = dataProfile.verType_;
    dataProfileInfo.userName = dataProfile.userName_;
    dataProfileInfo.apn = dataProfile.apn_;
    dataProfileInfo.protocol = dataProfile.protocol_;
    dataProfileInfo.roamingProtocol = dataProfile.roamingProtocol_;
    return dataProfileInfo;
}

void TelRilData::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
        UniInfo uniInfo;
        uniInfo.serial = telRilRequest->serialId_;
        uniInfo.gsmIndex = cid;
        uniInfo.arg1 = reason;
        MessageParcel wData;
        uniInfo.Marshalling(wData);
        int ret = SendBufferEvent(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, wData);
        TELEPHONY_LOGD("SendBufferEvent HREQ_DATA_DEACTIVATE_PDP_CONTEXT return: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : cellularRadio_ is nullptr");
    }
}

void TelRilData::DeactivatePdpContextResponse(MessageParcel &data)
{
    std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
    setupDataCallResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
            TELEPHONY_LOGD("setupDataCallResultInfo->flag:%{public}d", setupDataCallResultInfo->flag);
            handler->SendEvent(eventId, setupDataCallResultInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilData::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD(" telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
        DataCallInfo dataCallInfo;
        dataCallInfo.serial = telRilRequest->serialId_;
        dataCallInfo.radioTechnology = radioTechnology;
        dataCallInfo.dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
        dataCallInfo.roamingAllowed = allowRoaming;
        dataCallInfo.isRoaming = isRoaming;
        MessageParcel wData;
        dataCallInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, wData, reply, option);
        TELEPHONY_LOGD("SendBufferEvent HREQ_DATA_ACTIVATE_PDP_CONTEXT return: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : cellularRadio_ == nullptr");
    }
}

void TelRilData::ActivatePdpContextResponse(MessageParcel &data)
{
    std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
    setupDataCallResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
            TELEPHONY_LOGD("setupDataCallResultInfo->flag:%{public}d", setupDataCallResultInfo->flag);
            handler->SendEvent(eventId, setupDataCallResultInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilData::PdpContextListUpdated(MessageParcel &data)
{
    std::shared_ptr<DataCallResultList> dataCallResultList = std::make_shared<DataCallResultList>();
    dataCallResultList->ReadFromParcel(data);
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGD("indicationType:%{public}d", indicationType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_DATA_CALL_LIST_CHANGED, dataCallResultList);
    }
}
} // namespace Telephony
} // namespace OHOS

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
#include "tel_ril_sim.h"
#include "sim_data_type.h"
#include "hril_modem_parcel.h"
#include "hdf_death_recipient.h"
#include "hril_sim_parcel.h"

namespace OHOS {
void TelRilSim::AddHandlerToMap()
{
    // response
    memberFuncMap_[HREQ_SIM_READ_ICC_FILE] = &TelRilSim::ReadIccFileResponse;
    memberFuncMap_[HREQ_SIM_GET_SIM_STATUS] = &TelRilSim::GetSimStatusResponse;
    memberFuncMap_[HREQ_SIM_GET_IMSI] = &TelRilSim::GetImsiResponse;
}

TelRilSim::TelRilSim(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilSim::IsSimResponse(uint32_t code)
{
    return code >= HREQ_SIM_BASE && code < HREQ_DATA_BASE;
}

bool TelRilSim::IsSimNotification(uint32_t code)
{
    return code >= HNOTI_SIM_BASE && code < HNOTI_DATA_BASE;
}

bool TelRilSim::IsSimRespOrNotify(uint32_t code)
{
    return IsSimResponse(code) || IsSimNotification(code);
}

void TelRilSim::ProcessSimRespOrNotify(uint32_t code, OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG(
        "TelRilSim ProcessSimRespOrNotify code:%{public}d, GetDataSize:%{public}d", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

// response
void TelRilSim::ReadIccFileResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilSim::ReadIccFileResponse --> ");
    std::shared_ptr<IccIoResultInfo> iccIoResult = std::make_shared<IccIoResultInfo>();
    if (iccIoResult == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : ReadIccFileResponse --> iccIoResult == nullptr !!!");
        return;
    }
    iccIoResult->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : ReadIccFileResponse --> read spBuffer(HRilRadioResponseInfo) failed !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "ReadIccFileResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d, radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            ProcessIccioInfo(telRilRequest, iccIoResult);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    } else {
        TELEPHONY_ERR_LOG(
            "ERROR : ReadIccFileResponse --> telRilRequest == nullptr || radioResponseInfo  error  !!!");
    }
}

void TelRilSim::ProcessIccioInfo(
    std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult)
{
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : ReadIccFileResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::unique_ptr<SIM::IccToRilMsg> toMsg = telRilRequest->pointer_->GetUniqueObject<SIM::IccToRilMsg>();
    if (toMsg == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : ReadIccFileResponse --> GetUniqueObject<SIM::IccToRilMsg>() failed !!!");
        return;
    }
    std::unique_ptr<SIM::IccFromRilMsg> object = std::make_unique<SIM::IccFromRilMsg>(toMsg->controlHolder);
    object->fileData.resultData = iccIoResult->response;
    object->fileData.sw1 = iccIoResult->sw1;
    object->fileData.sw2 = iccIoResult->sw2;
    object->controlHolder = toMsg->controlHolder;
    object->arg1 = toMsg->arg1;
    handler->SendEvent(eventId, object);
}

void TelRilSim::GetSimStatusResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("OHOS::TelRilSim::GetSimStatusResponse --> ");
    std::shared_ptr<CardStatusInfo> cardStatusInfo = std::make_unique<CardStatusInfo>();
    if (cardStatusInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetSimStatusResponse --> cardStatusInfo == nullptr !!!");
        return;
    }
    cardStatusInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetSimStatusResponse --> spBuffer == nullptr !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "GetSimStatusResponse -->  radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : GetSimStatusResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cardStatusInfo);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    } else {
        TELEPHONY_ERR_LOG(
            "ERROR : GetSimStatusResponse --> telRilRequest == nullptr || radioResponseInfo error "
            "!!!");
    }
}

void TelRilSim::GetImsiResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilSim::GetImsiResponse --> ");
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> imsi = std::make_shared<std::string>(buffer);
    if (buffer == nullptr || imsi == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetImsiResponse --> buffer == nullptr || imsi == nullptr !!!");
        return;
    }
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetImsiResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "GetImsiResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            TELEPHONY_DEBUG_LOG("GetImsiResponse --> data.ReadCString() success");
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : GetImsiResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, imsi);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    } else {
        TELEPHONY_ERR_LOG(
            "ERROR : GetImsiResponse --> telRilRequest == nullptr || radioResponseInfo error "
            "!!!");
    }
}

// request
void TelRilSim::GetImsi(std::string aid, const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilSim::GetImsi -->");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_IMSI, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilSim GetImsi:telRilRequest is nullptr");
            return;
        }
        UniInfo imsi;
        imsi.serial = telRilRequest->serialId_;
        imsi.strTmp = ChangeNullToEmptyString(aid);
        OHOS::MessageParcel wData;
        imsi.Marshalling(wData);
        TELEPHONY_DEBUG_LOG("GetImsi --> imsi.serial = %{public}d", imsi.serial);
        int32_t ret = SendBufferEvent(HREQ_SIM_GET_IMSI, wData);
        TELEPHONY_INFO_LOG("GetImsi --> SendBufferEvent(HREQ_SIM_GET_IMSI, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_ERR_LOG("ERROR : GetImsi --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::ReadIccFile(int32_t command, int32_t fileId, std::string path, int32_t p1, int32_t p2, int32_t p3,
    std::string data, std::string pin2, std::string aid, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilSim::ReadIccFile --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_READ_ICC_FILE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilSim ReadIccFile:telRilRequest is nullptr");
            return;
        }
        OHOS::MessageParcel wData;
        IccIoRequestInfo iccIoRequestInfo;
        iccIoRequestInfo.serial = telRilRequest->serialId_;
        iccIoRequestInfo.cmd = command;
        iccIoRequestInfo.fileId = fileId;
        iccIoRequestInfo.path = ChangeNullToEmptyString(path);
        iccIoRequestInfo.p1 = p1;
        iccIoRequestInfo.p2 = p2;
        iccIoRequestInfo.p3 = p3;
        iccIoRequestInfo.data = ChangeNullToEmptyString(data);
        iccIoRequestInfo.pin2 = ChangeNullToEmptyString(pin2);
        iccIoRequestInfo.aid = ChangeNullToEmptyString(aid);
        iccIoRequestInfo.Marshalling(wData);
        TELEPHONY_DEBUG_LOG(
            "TelRilSim::ReadIccFile --serial:%{public}d, command:%{public}d, "
            "fileId:%{public}d,"
            " path:%{public}s, p1:%{public}d, p2:%{public}d, p3:%{public}d, data:%{public}s,"
            " pin2:%{public}s, aid:%{public}s",
            iccIoRequestInfo.serial, iccIoRequestInfo.cmd, iccIoRequestInfo.fileId, iccIoRequestInfo.path.c_str(),
            p1, p2, p3, iccIoRequestInfo.data.c_str(), iccIoRequestInfo.pin2.c_str(), iccIoRequestInfo.aid.c_str());
        OHOS::MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_READ_ICC_FILE, wData, reply, option);
        TELEPHONY_INFO_LOG(
            "ReadIccFile --> SendBufferEvent(HREQ_SIM_READ_ICC_FILE, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_ERR_LOG("ERROR : ReadIccFile --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilSim::GetSimStatus -->");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_STATUS, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilSim GetSimStatus:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("GetSimStatus --> telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
        int32_t ret = SendInt32Event(HREQ_SIM_GET_SIM_STATUS, telRilRequest->serialId_);
        TELEPHONY_INFO_LOG("GetSimStatus --> HREQ_SIM_GET_SIM_STATUS ret = %{public}d", ret);
    } else {
        TELEPHONY_ERR_LOG("ERROR : GetSimStatus --> cellularRadio_ == nullptr !!!");
    }
}

std::string TelRilSim::ChangeNullToEmptyString(std::string str)
{
    return !str.empty() ? str : "";
}
} // namespace OHOS

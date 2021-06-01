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
#include "core_service_stub.h"
#include "telephony_log.h"

namespace OHOS {
CoreServiceStub::CoreServiceStub()
{
    memberFuncMap_[GET_PS_RADIO_TECH] = &CoreServiceStub::OnGetPsRadioTech;
    memberFuncMap_[GET_CS_RADIO_TECH] = &CoreServiceStub::OnGetCsRadioTech;
    memberFuncMap_[GET_OPERATOR_NUMERIC] = &CoreServiceStub::OnGetOperatorNumeric;
    memberFuncMap_[GET_OPERATOR_NAME] = &CoreServiceStub::OnGetOperatorName;
    memberFuncMap_[GET_SIGNAL_INFO_LIST] = &CoreServiceStub::OnGetSignalInfoList;
    memberFuncMap_[GET_NETWORK_STATE] = &CoreServiceStub::OnGetNetworkState;
    memberFuncMap_[SET_RADIO_STATE] = &CoreServiceStub::OnSetHRilRadioState;
    memberFuncMap_[GET_RADIO_STATE] = &CoreServiceStub::OnGetHRilRadioState;

    memberFuncMap_[HAS_SIM_CARD] = &CoreServiceStub::OnHasSimCard;
    memberFuncMap_[GET_SIM_STATE] = &CoreServiceStub::OnGetSimState;
    memberFuncMap_[GET_ISO_COUNTRY_CODE] = &CoreServiceStub::OnGetIsoCountryCode;
    memberFuncMap_[GET_SPN] = &CoreServiceStub::OnGetSpn;
    memberFuncMap_[GET_ICCID] = &CoreServiceStub::OnGetIccId;
    memberFuncMap_[GET_SIM_OPERATOR_NUMERIC] = &CoreServiceStub::OnGetSimOperator;
    memberFuncMap_[GET_IMSI] = &CoreServiceStub::OnGetIMSI;
    memberFuncMap_[IS_SIM_ACTIVE] = &CoreServiceStub::OnIsSimActive;
}

int32_t CoreServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest code %{public}u", code);

    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t CoreServiceStub::OnGetPsRadioTech(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_PS_RADIO_TECH slotId %{public}d", slotId);

    int32_t result = GetPsRadioTech(slotId);
    reply.WriteInt32(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCsRadioTech(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_CS_RADIO_TECH slotId %{public}d", slotId);

    int32_t result = GetCsRadioTech(slotId);
    reply.WriteInt32(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorNumeric(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_OPERATOR_NUMERIC slotId %{public}d", slotId);

    std::u16string result = GetOperatorNumeric(slotId);
    reply.WriteString16(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorName(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_OPERATOR_NAME slotId %{public}d", slotId);

    std::u16string result = GetOperatorName(slotId);
    reply.WriteString16(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSignalInfoList(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_SIGNAL_INFO_LIST %{public}d", slotId);

    auto result = GetSignalInfoList(slotId);
    reply.WriteInt32(static_cast<int32_t>(result.size()));
    for (const auto &v : result) {
        v->Marshalling(reply);
    }

    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkState(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_NETWORK_STATE slotId %{public}d", slotId);

    sptr<NetworkState> result = GetNetworkStatus(slotId);
    result->Marshalling(reply);

    TELEPHONY_INFO_LOG("OnRemoteRequest GET_NETWORK_STATE");
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetHRilRadioState(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    bool isOn = data.ReadBool();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest SET_RADIO_STATE slotId %{public}d", slotId);

    SetHRilRadioState(slotId, isOn);

    TELEPHONY_INFO_LOG("OnRemoteRequest SET_RADIO_STATE");
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetHRilRadioState(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_RADIO_STATE slotId %{public}d", slotId);

    int32_t result = GetRadioState(slotId);
    reply.WriteInt32(result);
    TELEPHONY_INFO_LOG("OnRemoteRequest GET_RADIO_STATE");
    return NO_ERROR;
}

int32_t CoreServiceStub::OnHasSimCard(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest::HAS_SIM_CARD slotId is %{public}d", slotId);

    bool result = HasSimCard(slotId);
    TELEPHONY_INFO_LOG("OnRemoteRequest::HasSimCardInner result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::HasSimCardInner write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest::GET_SIM_STATE slotId is %{public}d", slotId);

    int32_t result = GetSimState(slotId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::GET_SIM_STATE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIsoCountryCode(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_ISO_COUNTRY_CODE slotId %{public}d", slotId);
    std::u16string result = GetIsoCountryCode(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::GET_ISO_COUNTRY_CODE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSpn(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest::GET_SPN slotId is %{public}d", slotId);

    std::u16string result = GetSpn(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::GET_SPN write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIccId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();

    std::u16string result = GetIccId(slotId);
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest::GET_ICCID slotId is %{public}d", slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::GET_ICCID write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimOperator(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();

    std::u16string result = GetSimOperator(slotId);
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest::GET_SIM_OPERATOR_NUMERIC slotId is %{public}d", slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::GET_SIM_OPERATOR_NUMERIC write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIMSI(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_INFO_LOG("CoreServiceStub OnRemoteRequest GET_IMSI slotId %{public}d", slotId);

    std::u16string result = GetIMSI(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::GET_IMSI write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsSimActive(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();

    bool result = IsSimActive(slotId);
    TELEPHONY_INFO_LOG("OnRemoteRequest::IsSimActive result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_INFO_LOG("OnRemoteRequest::IsSimActive write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}
} // namespace OHOS
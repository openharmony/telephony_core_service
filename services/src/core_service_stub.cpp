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
#include "string_ex.h"
#include "telephony_log_wrapper.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
CoreServiceStub::CoreServiceStub()
{
    memberFuncMap_[GET_PS_RADIO_TECH] = &CoreServiceStub::OnGetPsRadioTech;
    memberFuncMap_[GET_CS_RADIO_TECH] = &CoreServiceStub::OnGetCsRadioTech;
    memberFuncMap_[GET_OPERATOR_NUMERIC] = &CoreServiceStub::OnGetOperatorNumeric;
    memberFuncMap_[GET_OPERATOR_NAME] = &CoreServiceStub::OnGetOperatorName;
    memberFuncMap_[GET_SIGNAL_INFO_LIST] = &CoreServiceStub::OnGetSignalInfoList;
    memberFuncMap_[GET_NETWORK_STATE] = &CoreServiceStub::OnGetNetworkState;
    memberFuncMap_[SET_RADIO_STATE] = &CoreServiceStub::OnSetRadioState;
    memberFuncMap_[GET_RADIO_STATE] = &CoreServiceStub::OnGetRadioState;
    memberFuncMap_[GET_NETWORK_SEARCH_RESULT] = &CoreServiceStub::OnGetNetworkSearchResult;
    memberFuncMap_[GET_NETWORK_SELECTION_MODE] = &CoreServiceStub::OnGetNetworkSelectionMode;
    memberFuncMap_[SET_NETWORK_SELECTION_MODE] = &CoreServiceStub::OnSetNetworkSelectionMode;
    memberFuncMap_[GET_ISO_COUNTRY_CODE_FOR_NETWORK] = &CoreServiceStub::OnGetIsoCountryCodeForNetwork;

    memberFuncMap_[HAS_SIM_CARD] = &CoreServiceStub::OnHasSimCard;
    memberFuncMap_[GET_SIM_STATE] = &CoreServiceStub::OnGetSimState;
    memberFuncMap_[GET_ISO_COUNTRY_CODE] = &CoreServiceStub::OnGetIsoCountryCodeForSim;
    memberFuncMap_[GET_SPN] = &CoreServiceStub::OnGetSimSpn;
    memberFuncMap_[GET_ICCID] = &CoreServiceStub::OnGetSimIccId;
    memberFuncMap_[GET_SIM_OPERATOR_NUMERIC] = &CoreServiceStub::OnGetSimOperatorNumeric;
    memberFuncMap_[GET_IMSI] = &CoreServiceStub::OnGetIMSI;
    memberFuncMap_[IS_SIM_ACTIVE] = &CoreServiceStub::OnIsSimActive;
    memberFuncMap_[GET_SIM_LANGUAGE] = &CoreServiceStub::OnGetLocaleFromDefaultSim;
    memberFuncMap_[GET_SIM_GID1] = &CoreServiceStub::OnGetSimGid1;

    memberFuncMap_[GET_SIM_ACCOUNT_INFO] = &CoreServiceStub::OnGetSimAccountInfo;
    memberFuncMap_[SET_DEFAULT_VOICE_SLOTID] = &CoreServiceStub::OnSetDefaultVoiceSlotId;
    memberFuncMap_[GET_DEFAULT_VOICE_SLOTID] = &CoreServiceStub::OnGetDefaultVoiceSlotId;
    memberFuncMap_[UNLOCK_PIN] = &CoreServiceStub::OnUnlockPin;
    memberFuncMap_[UNLOCK_PUK] = &CoreServiceStub::OnUnlockPuk;
    memberFuncMap_[ALTER_PIN] = &CoreServiceStub::OnAlterPin;
    memberFuncMap_[CHECK_PIN] = &CoreServiceStub::OnGetLockState;
    memberFuncMap_[SWITCH_PIN] = &CoreServiceStub::OnSetLockState;
    memberFuncMap_[REFRESH_SIM_STATE] = &CoreServiceStub::OnRefreshSimState;
}

int32_t CoreServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_LOGD("CoreServiceStub OnRemoteRequest code %{public}u", code);
    std::u16string myDescripter = CoreServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        TELEPHONY_LOGE("descriptor checked fail");
        return TELEPHONY_ERROR;
    }
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
    int32_t result = GetPsRadioTech(slotId);
    reply.WriteInt32(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCsRadioTech(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    int32_t result = GetCsRadioTech(slotId);
    reply.WriteInt32(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorNumeric(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::u16string result = GetOperatorNumeric(slotId);
    reply.WriteString16(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorName(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::u16string result = GetOperatorName(slotId);
    reply.WriteString16(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSignalInfoList(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    auto result = GetSignalInfoList(slotId);
    reply.WriteInt32(static_cast<int32_t>(result.size()));
    for (const auto &v : result) {
        if (v != nullptr) {
            v->Marshalling(reply);
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkState(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("CoreServiceStub::OnGetNetworkState OnRemoteRequest GET_NETWORK_STATE");
    auto slotId = data.ReadInt32();
    sptr<NetworkState> result = GetNetworkState(slotId);
    if (result != nullptr) {
        result->Marshalling(reply);
    }

    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetRadioState(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("CoreServiceStub::OnSetRadioState OnRemoteRequest SET_RADIO_STATE");
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool isOn = data.ReadBool();

    bool result = false;
    if (callback != nullptr) {
        TELEPHONY_LOGD("CoreServiceStub::OnSetRadioState isOn:%{public}d, ", isOn);
        result = SetRadioState(isOn, callback);
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetRadioState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetRadioState(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("CoreServiceStub::OnGetRadioState  GET_RADIO_STATE");
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool result = false;
    if (callback != nullptr) {
        result = GetRadioState(callback);
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetRadioState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    TELEPHONY_LOGD("CoreServiceStub::OnGetRadioState  result:%{public}d,", result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIsoCountryCodeForNetwork(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetIsoCountryCodeForNetwork(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_ISO_COUNTRY_CODE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnHasSimCard(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = HasSimCard(slotId);
    TELEPHONY_LOGD("OnRemoteRequest::OnHasSimCard result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnHasSimCard write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = GetSimState(slotId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_SIM_STATE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIsoCountryCodeForSim(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetIsoCountryCodeForSim(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_ISO_COUNTRY_CODE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimSpn(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimSpn(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_SPN write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimIccId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimIccId(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_ICCID write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimOperatorNumeric(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimOperatorNumeric(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_SIM_OPERATOR_NUMERIC write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIMSI(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetIMSI(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_IMSI write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsSimActive(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = IsSimActive(slotId);
    TELEPHONY_LOGD("OnRemoteRequest::IsSimActive result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::IsSimActive write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkSearchResult(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("OnRemoteRequest OnGetNetworkSearchResult");
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool result = false;
    if (callback != nullptr) {
        result = GetNetworkSearchResult(slotId, callback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSearchResult callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSearchResult write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("CoreServiceStub::OnGetNetworkSelectionMode");
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        TELEPHONY_LOGD("CoreServiceStub::OnGetNetworkSelectionMode remote callback is not null.");
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool result = false;
    if (callback != nullptr) {
        result = GetNetworkSelectionMode(slotId, callback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSelectionMode callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSelectionMode write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("CoreServiceStub::OnSetNetworkSelectionMode");
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    int32_t selectMode = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnSetNetworkSelectionMode selectMode:%{public}d", selectMode);
    bool resumeSelection = data.ReadBool();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnSetNetworkSelectionMode remoteCallback is null");
    }
    sptr<NetworkInformation> networkState = NetworkInformation::Unmarshalling(data);
    bool result = false;
    if (callback != nullptr) {
        result = SetNetworkSelectionMode(slotId, selectMode, networkState, resumeSelection, callback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnSetNetworkSelectionMode callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetNetworkSelectionMode write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}
int32_t CoreServiceStub::OnGetLocaleFromDefaultSim(MessageParcel &data, MessageParcel &reply)
{
    std::u16string result = GetLocaleFromDefaultSim();
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GetLocaleFromDefaultSim write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimGid1(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();

    std::u16string result = GetSimGid1(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GetSimGid1 write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGD("OnGetSimAccountInfo IccAccountInfo ");
    int32_t subId = data.ReadInt32();
    IccAccountInfo iccAccountInfo;

    bool result = GetSimAccountInfo(subId, iccAccountInfo);

    bool ret = reply.WriteBool(result);
    if (!iccAccountInfo.Marshalling(reply)) {
        TELEPHONY_LOGE("OnGetSimAccountInfo IccAccountInfo reply Marshalling is false");
        return TRANSACTION_ERR;
    }
    if (!ret) {
        TELEPHONY_LOGE("OnGetSimAccountInfo write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t subId = data.ReadInt32();
    bool result = SetDefaultVoiceSlotId(subId);

    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetDefaultVoiceSlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply)
{
    int result = GetDefaultVoiceSlotId();

    int32_t ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetDefaultVoiceSlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPin(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = 0;
    LockStatusResponse response = {0};
    std::u16string pin = data.ReadString16();
    int32_t phoneId = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnUnlockPin(), phoneId = %{public}d", phoneId);
    bool result = UnlockPin(pin, response, phoneId);
    ret = reply.WriteBool(result);
    ret = reply.WriteInt32(response.result);
    ret = reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPin write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPuk(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = 0;
    LockStatusResponse response = {0};
    std::u16string newPin = data.ReadString16();
    std::u16string puk = data.ReadString16();
    int32_t phoneId = data.ReadInt32();
    bool result = UnlockPuk(newPin, puk, response, phoneId);
    ret = reply.WriteBool(result);
    ret = reply.WriteInt32(response.result);
    ret = reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPuk write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAlterPin(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = 0;
    LockStatusResponse response = {0};
    std::u16string newPin = data.ReadString16();
    std::u16string oldPin = data.ReadString16();
    int32_t phoneId = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnAlterPin(), phoneId = %{public}d", phoneId);
    bool result = AlterPin(newPin, oldPin, response, phoneId);
    ret = reply.WriteBool(result);
    ret = reply.WriteInt32(response.result);
    ret = reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnAlterPin write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetLockState(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = 0;
    LockStatusResponse response = {0};
    std::u16string pin = data.ReadString16();
    int32_t mode = data.ReadInt32();
    int32_t phoneId = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnSetLockState(), mode = %{public}d, phoneId = %{public}d", mode, phoneId);
    bool result = SetLockState(pin, mode, response, phoneId);
    ret = reply.WriteBool(result);
    ret = reply.WriteInt32(response.result);
    ret = reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetLockState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetLockState(MessageParcel &data, MessageParcel &reply)
{
    int32_t phoneId = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnGetLockState(), phoneId = %{public}d", phoneId);
    int32_t result = GetLockState(phoneId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetLockState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnRefreshSimState(MessageParcel &data, MessageParcel &reply)
{
    int32_t phoneId = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnRefreshSimState(), phoneId = %{public}d", phoneId);
    int32_t result = RefreshSimState(phoneId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnRefreshSimState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}
} // namespace Telephony
} // namespace OHOS

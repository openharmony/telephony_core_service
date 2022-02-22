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
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
CoreServiceStub::CoreServiceStub()
{
    AddHandlerNetWorkToMap();
    AddHandlerSimToMap();
}

void CoreServiceStub::AddHandlerNetWorkToMap()
{
    memberFuncMap_[uint32_t(InterfaceID::GET_PS_RADIO_TECH)] = &CoreServiceStub::OnGetPsRadioTech;
    memberFuncMap_[uint32_t(InterfaceID::GET_CS_RADIO_TECH)] = &CoreServiceStub::OnGetCsRadioTech;
    memberFuncMap_[uint32_t(InterfaceID::GET_OPERATOR_NUMERIC)] = &CoreServiceStub::OnGetOperatorNumeric;
    memberFuncMap_[uint32_t(InterfaceID::GET_OPERATOR_NAME)] = &CoreServiceStub::OnGetOperatorName;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIGNAL_INFO_LIST)] = &CoreServiceStub::OnGetSignalInfoList;
    memberFuncMap_[uint32_t(InterfaceID::GET_NETWORK_STATE)] = &CoreServiceStub::OnGetNetworkState;
    memberFuncMap_[uint32_t(InterfaceID::SET_RADIO_STATE)] = &CoreServiceStub::OnSetRadioState;
    memberFuncMap_[uint32_t(InterfaceID::GET_RADIO_STATE)] = &CoreServiceStub::OnGetRadioState;
    memberFuncMap_[uint32_t(InterfaceID::GET_NETWORK_SEARCH_RESULT)] = &CoreServiceStub::OnGetNetworkSearchInformation;
    memberFuncMap_[uint32_t(InterfaceID::GET_NETWORK_SELECTION_MODE)] = &CoreServiceStub::OnGetNetworkSelectionMode;
    memberFuncMap_[uint32_t(InterfaceID::SET_NETWORK_SELECTION_MODE)] = &CoreServiceStub::OnSetNetworkSelectionMode;
    memberFuncMap_[uint32_t(InterfaceID::GET_ISO_COUNTRY_CODE_FOR_NETWORK)] =
        &CoreServiceStub::OnGetIsoCountryCodeForNetwork;
    memberFuncMap_[uint32_t(InterfaceID::GET_IMEI)] = &CoreServiceStub::OnGetImei;
    memberFuncMap_[uint32_t(InterfaceID::GET_MEID)] = &CoreServiceStub::OnGetMeid;
    memberFuncMap_[uint32_t(InterfaceID::GET_UNIQUE_DEVICE_ID)] = &CoreServiceStub::OnGetUniqueDeviceId;
    memberFuncMap_[uint32_t(InterfaceID::GET_IMS_REG_STATUS)] = &CoreServiceStub::OnGetImsRegStatus;
    memberFuncMap_[uint32_t(InterfaceID::GET_CELL_INFO_LIST)] = &CoreServiceStub::OnGetCellInfoList;
    memberFuncMap_[uint32_t(InterfaceID::GET_CELL_LOCATION)] = &CoreServiceStub::OnGetCellLocation;
    memberFuncMap_[uint32_t(InterfaceID::GET_PREFERRED_NETWORK_MODE)] = &CoreServiceStub::OnGetPreferredNetwork;
    memberFuncMap_[uint32_t(InterfaceID::SET_PREFERRED_NETWORK_MODE)] = &CoreServiceStub::OnSetPreferredNetwork;
    memberFuncMap_[uint32_t(InterfaceID::GET_NR_OPTION_MODE)] = &CoreServiceStub::OnGetNrOptionMode;
}

void CoreServiceStub::AddHandlerSimToMap()
{
    memberFuncMap_[uint32_t(InterfaceID::HAS_SIM_CARD)] = &CoreServiceStub::OnHasSimCard;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_STATE)] = &CoreServiceStub::OnGetSimState;
    memberFuncMap_[uint32_t(InterfaceID::GET_ISO_COUNTRY_CODE)] = &CoreServiceStub::OnGetISOCountryCodeForSim;
    memberFuncMap_[uint32_t(InterfaceID::GET_SPN)] = &CoreServiceStub::OnGetSimSpn;
    memberFuncMap_[uint32_t(InterfaceID::GET_ICCID)] = &CoreServiceStub::OnGetSimIccId;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_OPERATOR_NUMERIC)] = &CoreServiceStub::OnGetSimOperatorNumeric;
    memberFuncMap_[uint32_t(InterfaceID::GET_IMSI)] = &CoreServiceStub::OnGetIMSI;
    memberFuncMap_[uint32_t(InterfaceID::IS_SIM_ACTIVE)] = &CoreServiceStub::OnIsSimActive;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_LANGUAGE)] = &CoreServiceStub::OnGetLocaleFromDefaultSim;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_GID1)] = &CoreServiceStub::OnGetSimGid1;

    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_SUB_INFO)] = &CoreServiceStub::OnGetSimSubscriptionInfo;
    memberFuncMap_[uint32_t(InterfaceID::SET_DEFAULT_VOICE_SLOTID)] = &CoreServiceStub::OnSetDefaultVoiceSlotId;
    memberFuncMap_[uint32_t(InterfaceID::GET_DEFAULT_VOICE_SLOTID)] = &CoreServiceStub::OnGetDefaultVoiceSlotId;
    memberFuncMap_[uint32_t(InterfaceID::SET_PRIMARY_SLOTID)] = &CoreServiceStub::OnSetPrimarySlotId;
    memberFuncMap_[uint32_t(InterfaceID::GET_PRIMARY_SLOTID)] = &CoreServiceStub::OnGetPrimarySlotId;

    memberFuncMap_[uint32_t(InterfaceID::SET_SHOW_NUMBER)] = &CoreServiceStub::OnSetShowNumber;
    memberFuncMap_[uint32_t(InterfaceID::GET_SHOW_NUMBER)] = &CoreServiceStub::OnGetShowNumber;
    memberFuncMap_[uint32_t(InterfaceID::SET_SHOW_NAME)] = &CoreServiceStub::OnSetShowName;
    memberFuncMap_[uint32_t(InterfaceID::GET_SHOW_NAME)] = &CoreServiceStub::OnGetShowName;
    memberFuncMap_[uint32_t(InterfaceID::GET_ACTIVE_ACCOUNT_INFO_LIST)] =
        &CoreServiceStub::OnGetActiveSimAccountInfoList;
    memberFuncMap_[uint32_t(InterfaceID::GET_OPERATOR_CONFIG)] = &CoreServiceStub::OnGetOperatorConfig;
    memberFuncMap_[uint32_t(InterfaceID::UNLOCK_PIN)] = &CoreServiceStub::OnUnlockPin;
    memberFuncMap_[uint32_t(InterfaceID::UNLOCK_PUK)] = &CoreServiceStub::OnUnlockPuk;
    memberFuncMap_[uint32_t(InterfaceID::ALTER_PIN)] = &CoreServiceStub::OnAlterPin;
    memberFuncMap_[uint32_t(InterfaceID::CHECK_LOCK)] = &CoreServiceStub::OnGetLockState;
    memberFuncMap_[uint32_t(InterfaceID::SWITCH_LOCK)] = &CoreServiceStub::OnSetLockState;
    memberFuncMap_[uint32_t(InterfaceID::UNLOCK_PIN2)] = &CoreServiceStub::OnUnlockPin2;
    memberFuncMap_[uint32_t(InterfaceID::UNLOCK_PUK2)] = &CoreServiceStub::OnUnlockPuk2;
    memberFuncMap_[uint32_t(InterfaceID::ALTER_PIN2)] = &CoreServiceStub::OnAlterPin2;
    memberFuncMap_[uint32_t(InterfaceID::REFRESH_SIM_STATE)] = &CoreServiceStub::OnRefreshSimState;
    memberFuncMap_[uint32_t(InterfaceID::SET_SIM_ACTIVE)] = &CoreServiceStub::OnSetActiveSim;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_PHONE_NUMBER)] = &CoreServiceStub::OnGetSimPhoneNumber;
    memberFuncMap_[uint32_t(InterfaceID::GET_SIM_TELENUMBER_IDENTIFIER)] =
        &CoreServiceStub::OnGetSimTeleNumberIdentifier;
    memberFuncMap_[uint32_t(InterfaceID::GET_VOICE_MAIL_TAG)] = &CoreServiceStub::OnGetVoiceMailInfor;
    memberFuncMap_[uint32_t(InterfaceID::GET_VOICE_MAIL_NUMBER)] = &CoreServiceStub::OnGetVoiceMailNumber;
    memberFuncMap_[uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_GET)] = &CoreServiceStub::OnDiallingNumbersGet;
    memberFuncMap_[uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_INSERT)] = &CoreServiceStub::OnAddIccDiallingNumbers;
    memberFuncMap_[uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_UPDATE)] = &CoreServiceStub::OnUpdateIccDiallingNumbers;
    memberFuncMap_[uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_DELETE)] = &CoreServiceStub::OnDelIccDiallingNumbers;
    memberFuncMap_[uint32_t(InterfaceID::SET_VOICE_MAIL)] = &CoreServiceStub::OnSetVoiceMailInfo;
    memberFuncMap_[uint32_t(InterfaceID::GET_MAX_SIM_COUNT)] = &CoreServiceStub::OnGetMaxSimCount;
    memberFuncMap_[uint32_t(InterfaceID::STK_CMD_FROM_APP_ENVELOPE)] = &CoreServiceStub::OnSendEnvelopeCmd;
    memberFuncMap_[uint32_t(InterfaceID::STK_CMD_FROM_APP_TERMINAL_RESPONSE)] =
        &CoreServiceStub::OnSendTerminalResponseCmd;
    memberFuncMap_[uint32_t(InterfaceID::GET_CARD_TYPE)] = &CoreServiceStub::OnGetCardType;
    memberFuncMap_[uint32_t(InterfaceID::UNLOCK_SIMLOCK)] = &CoreServiceStub::OnUnlockSimLock;
    memberFuncMap_[uint32_t(InterfaceID::HAS_OPERATOR_PRIVILEGES)] = &CoreServiceStub::OnHasOperatorPrivileges;
    memberFuncMap_[uint32_t(InterfaceID::IS_NR_SUPPORTED)] = &CoreServiceStub::OnIsNrSupported;
}

int32_t CoreServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_LOGI("CoreServiceStub OnRemoteRequest code %{public}u", code);
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
        v->Marshalling(reply);
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkState(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    sptr<NetworkState> result = GetNetworkState(slotId);
    if (result != nullptr) {
        result->Marshalling(reply);
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetRadioState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool isOn = data.ReadBool();
    bool result = false;
    if (callback != nullptr) {
        TELEPHONY_LOGI("CoreServiceStub::OnSetRadioState isOn:%{public}d", isOn);
        result = SetRadioState(slotId, isOn, callback);
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
    int32_t slotId = data.ReadInt32();
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool result = false;
    if (callback != nullptr) {
        result = GetRadioState(slotId, callback);
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetRadioState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    TELEPHONY_LOGI("CoreServiceStub::OnGetRadioState  result:%{public}d", result);
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

int32_t CoreServiceStub::OnGetImei(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetImei(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_IMEI write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetMeid(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetMeid(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_MEID write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetUniqueDeviceId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetUniqueDeviceId(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_UNIQUE_DEVICE_ID write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsNrSupported(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = IsNrSupported(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::IS_NR_SUPPORTED write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNrOptionMode(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    NrMode nrMode = GetNrOptionMode(slotId);
    bool ret = reply.WriteInt32(static_cast<int32_t>(nrMode));
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_NR_OPTION_MODE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnHasSimCard(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = HasSimCard(slotId);
    TELEPHONY_LOGI("OnRemoteRequest::OnHasSimCard result is %{public}s", result ? "true" : "false");
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

int32_t CoreServiceStub::OnGetCardType(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = GetCardType(slotId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_CARD_TYPE write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetISOCountryCodeForSim(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetISOCountryCodeForSim(slotId);
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
    TELEPHONY_LOGI("OnRemoteRequest::IsSimActive result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::IsSimActive write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkSearchInformation(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool result = false;
    if (callback != nullptr) {
        result = GetNetworkSearchInformation(slotId, callback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSearchInformation callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSearchInformation write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
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
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    int32_t selectMode = data.ReadInt32();
    TELEPHONY_LOGI("CoreServiceStub::OnSetNetworkSelectionMode selectMode:%{public}d", selectMode);
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

int32_t CoreServiceStub::OnGetSimSubscriptionInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    IccAccountInfo iccAccountInfo;
    bool result = GetSimAccountInfo(slotId, iccAccountInfo);
    bool ret = reply.WriteBool(result);
    if (!iccAccountInfo.Marshalling(reply)) {
        TELEPHONY_LOGE("OnGetSimSubscriptionInfo IccAccountInfo reply Marshalling is false");
        return TRANSACTION_ERR;
    }
    if (!ret) {
        TELEPHONY_LOGE("OnGetSimSubscriptionInfo write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = SetDefaultVoiceSlotId(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetDefaultVoiceSlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = GetDefaultVoiceSlotId();
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetDefaultVoiceSlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetPrimarySlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = SetPrimarySlotId(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetPrimarySlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetPrimarySlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = GetPrimarySlotId();
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetPrimarySlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPin(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = {0};
    int32_t slotId = data.ReadInt32();
    std::u16string pin = data.ReadString16();
    TELEPHONY_LOGI(
        "CoreServiceStub::OnUnlockPin(), pin = %{public}s, slotId = %{public}d", Str16ToStr8(pin).c_str(), slotId);
    bool result = UnlockPin(slotId, pin, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPin write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPuk(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = {0};
    int32_t slotId = data.ReadInt32();
    std::u16string newPin = data.ReadString16();
    std::u16string puk = data.ReadString16();
    TELEPHONY_LOGI("CoreServiceStub::OnUnlockPuk(), newPin = %{public}s, puk = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin).c_str(), Str16ToStr8(puk).c_str(), slotId);
    bool result = UnlockPuk(slotId, newPin, puk, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPuk write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAlterPin(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = {0};
    int32_t slotId = data.ReadInt32();
    std::u16string newPin = data.ReadString16();
    std::u16string oldPin = data.ReadString16();
    TELEPHONY_LOGI("CoreServiceStub::OnAlterPin(), newPin = %{public}s, oldPin = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin).c_str(), Str16ToStr8(oldPin).c_str(), slotId);
    bool result = AlterPin(slotId, newPin, oldPin, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnAlterPin write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPin2(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = {0};
    int32_t slotId = data.ReadInt32();
    std::u16string pin2 = data.ReadString16();
    TELEPHONY_LOGI(
        "CoreServiceStub::OnUnlockPin2(), pin2 = %{public}s, slotId = %{public}d", Str16ToStr8(pin2).c_str(), slotId);
    bool result = UnlockPin2(slotId, pin2, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPin2 write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPuk2(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = {0};
    int32_t slotId = data.ReadInt32();
    std::u16string newPin2 = data.ReadString16();
    std::u16string puk2 = data.ReadString16();
    TELEPHONY_LOGI("CoreServiceStub::OnUnlockPuk2(), newPin2 = %{public}s, puk2 = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin2).c_str(), Str16ToStr8(puk2).c_str(), slotId);
    bool result = UnlockPuk2(slotId, newPin2, puk2, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPuk2 write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAlterPin2(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = {0};
    int32_t slotId = data.ReadInt32();
    std::u16string newPin2 = data.ReadString16();
    std::u16string oldPin2 = data.ReadString16();
    TELEPHONY_LOGI("CoreServiceStub::OnAlterPin2(), newPin2 = %{public}s, oldPin2 = %{public}s, slotId = %{public}d",
        Str16ToStr8(newPin2).c_str(), Str16ToStr8(oldPin2).c_str(), slotId);
    bool result = AlterPin2(slotId, newPin2, oldPin2, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnAlterPin2 write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetLockState(MessageParcel &data, MessageParcel &reply)
{
    LockInfo options;
    int32_t slotId = data.ReadInt32();
    options.lockType = static_cast<LockType>(data.ReadInt32());
    options.lockState = static_cast<LockState>(data.ReadInt32());
    options.password = data.ReadString16();
    LockStatusResponse response = {0};
    TELEPHONY_LOGI(
        "CoreServiceStub::OnSetLockState(), pin = %{public}s, lockType = %{public}d, lockState = %{public}d, "
        "slotId = %{public}d",
        Str16ToStr8(options.password).c_str(), options.lockType, options.lockState, slotId);
    bool result = SetLockState(slotId, options, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetLockState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetLockState(MessageParcel &data, MessageParcel &reply)
{
    LockType lockType;
    int32_t slotId = data.ReadInt32();
    lockType = static_cast<LockType>(data.ReadInt32());
    TELEPHONY_LOGI("CoreServiceStub::OnGetLockState(),lockType = %{public}d, slotId = %{public}d", lockType, slotId);
    int32_t result = GetLockState(slotId, lockType);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetLockState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnRefreshSimState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_LOGI("CoreServiceStub::OnRefreshSimState(), slotId = %{public}d", slotId);
    int32_t result = RefreshSimState(slotId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnRefreshSimState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetActiveSim(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t enable = data.ReadInt32();
    TELEPHONY_LOGI("CoreServiceStub::OnSetActiveSim(), slotId = %{public}d", slotId);
    bool result = SetActiveSim(slotId, enable);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetActiveSim write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetPreferredNetwork(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        TELEPHONY_LOGI("CoreServiceStub::OnGetPreferredNetwork remote callback is not null.");
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    bool result = false;
    if (callback != nullptr) {
        result = GetPreferredNetwork(slotId, callback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnGetPreferredNetwork callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetPreferredNetwork write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetShowNumber(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string number = data.ReadString16();
    bool result = SetShowNumber(slotId, number);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetShowNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetShowNumber(OHOS::MessageParcel &data, OHOS::MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetShowNumber(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetShowNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetShowName(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string name = data.ReadString16();
    bool result = SetShowName(slotId, name);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetShowName write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetPreferredNetwork(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    int32_t networkMode = data.ReadInt32();
    TELEPHONY_LOGI("CoreServiceStub::OnSetPreferredNetwork selectMode:%{public}d", networkMode);
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnSetPreferredNetwork remoteCallback is null");
    }
    bool result = false;
    if (callback != nullptr) {
        result = SetPreferredNetwork(slotId, networkMode, callback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnSetPreferredNetwork callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetPreferredNetwork write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetShowName(OHOS::MessageParcel &data, OHOS::MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetShowName(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetShowName write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetActiveSimAccountInfoList(MessageParcel &data, MessageParcel &reply)
{
    std::vector<IccAccountInfo> iccAccountInfoList;
    bool result = GetActiveSimAccountInfoList(iccAccountInfoList);
    int32_t size = iccAccountInfoList.size();
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(size);
    if (!ret) {
        TELEPHONY_LOGE("OnGetActiveSimAccountInfoList write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    std::vector<IccAccountInfo>::iterator it = iccAccountInfoList.begin();
    while (it != iccAccountInfoList.end()) {
        TELEPHONY_LOGI("OnGetActiveSimAccountInfoList slotIndex = %{public}d, showName = %{public}s", (*it).slotIndex,
            Str16ToStr8((*it).showName).c_str());
        if (!(*it).Marshalling(reply)) {
            TELEPHONY_LOGE("OnGetActiveSimAccountInfoList IccAccountInfo reply Marshalling is false");
            return ERR_FLATTEN_OBJECT;
        }
        it++;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorConfig(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    OperatorConfig operatorConfig;
    bool result = GetOperatorConfigs(slotId, operatorConfig);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetOperatorConfig write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    if (!operatorConfig.Marshalling(reply)) {
        TELEPHONY_LOGE("OnGetOperatorConfig operatorConfig reply Marshalling is false");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimPhoneNumber(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimTelephoneNumber(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetSimPhoneNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimTeleNumberIdentifier(MessageParcel &data, MessageParcel &reply)
{
    const int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimTeleNumberIdentifier(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetSimPhoneNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetVoiceMailInfor(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetVoiceMailIdentifier(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetVoiceMailInfor write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetVoiceMailNumber(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetVoiceMailNumber(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetVoiceMailNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnDiallingNumbersGet(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    auto result = QueryIccDiallingNumbers(slotId, type);
    bool ret = reply.WriteInt32(static_cast<int32_t>(result.size()));
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnDiallingNumbersGet write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    for (const auto &v : result) {
        v->Marshalling(reply);
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAddIccDiallingNumbers(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(data);
    bool result = false;
    if (diallingNumber != nullptr) {
        result = AddIccDiallingNumbers(slotId, type, diallingNumber);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnAddIccDiallingNumbers callback is null");
    }

    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnAddIccDiallingNumbers write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUpdateIccDiallingNumbers(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(data);
    bool result = false;
    if (diallingNumber != nullptr) {
        result = UpdateIccDiallingNumbers(slotId, type, diallingNumber);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnUpdateIccDiallingNumbers callback is null");
    }

    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnUpdateIccDiallingNumbers write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnDelIccDiallingNumbers(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(data);
    bool result = false;
    if (diallingNumber != nullptr) {
        result = DelIccDiallingNumbers(slotId, type, diallingNumber);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnDelIccDiallingNumbers callback is null");
    }
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnDelIccDiallingNumbers write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetVoiceMailInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string name = data.ReadString16();
    std::u16string number = data.ReadString16();
    bool result = SetVoiceMailInfo(slotId, name, number);

    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetVoiceMailInfo write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetMaxSimCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = GetMaxSimCount();
    int32_t ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetMaxSimCount write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSendEnvelopeCmd(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::string cmd = data.ReadString();
    bool result = SendEnvelopeCmd(slotId, cmd);
    TELEPHONY_LOGI("OnRemoteRequest::OnSendEnvelopeCmd result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSendEnvelopeCmd write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSendTerminalResponseCmd(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::string cmd = data.ReadString();
    bool result = SendTerminalResponseCmd(slotId, cmd);
    TELEPHONY_LOGI("OnRemoteRequest::OnSendTerminalResponseCmd result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSendTerminalResponseCmd write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockSimLock(MessageParcel &data, MessageParcel &reply)
{
    PersoLockInfo lockInfo;
    int32_t slotId = data.ReadInt32();
    lockInfo.lockType = static_cast<PersoLockType>(data.ReadInt32());
    lockInfo.password = data.ReadString16();
    LockStatusResponse response = {0};

    TELEPHONY_LOGI("CoreServiceStub::OnUnlockSimLock(), password = %{public}s, lockType = %{public}d",
        Str16ToStr8(lockInfo.password).c_str(), lockInfo.lockType);
    bool result = UnlockSimLock(slotId, lockInfo, response);
    uint32_t ret = 0;
    ret = reply.WriteBool(result);
    ret &= reply.WriteInt32(response.result);
    ret &= reply.WriteInt32(response.remain);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockSimLock write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetImsRegStatus(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = GetImsRegStatus(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetImsRegStatus write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCellInfoList(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    auto result = GetCellInfoList(slotId);
    reply.WriteInt32(static_cast<int32_t>(result.size()));
    TELEPHONY_LOGI("OnRemoteRequest OnGetCellInfoList cell size %{public}zu", result.size());
    for (const auto &v : result) {
        v->Marshalling(reply);
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCellLocation(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = SendUpdateCellLocationRequest(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetCellLocation write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnHasOperatorPrivileges(MessageParcel &data, MessageParcel &reply)
{
    const int32_t slotId = data.ReadInt32();
    bool result = HasOperatorPrivileges(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnHasOperatorPrivileges write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}
} // namespace Telephony
} // namespace OHOS

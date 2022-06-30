/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "core_service_proxy.h"

#include "parameter.h"
#include "string_ex.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
bool CoreServiceProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(CoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write interface token failed");
        return false;
    }
    return true;
}

int32_t CoreServiceProxy::GetPsRadioTech(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPsRadioTech WriteInterfaceToken is false");
        return TELEPHONY_ERROR;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetPsRadioTech Remote is null");
        return TELEPHONY_ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_PS_RADIO_TECH), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetPsRadioTech failed, error code is %{public}d ", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    return result;
}

int32_t CoreServiceProxy::GetCsRadioTech(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCsRadioTech WriteInterfaceToken is false");
        return TELEPHONY_ERROR;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetCsRadioTech Remote is null");
        return TELEPHONY_ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_CS_RADIO_TECH), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCsRadioTech failed, error code is %{public}d \n", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetCsRadioTech call end: result=%{public}d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetOperatorNumeric(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetOperatorNumeric WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetOperatorNumeric Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_OPERATOR_NUMERIC), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCsRadioTech failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("CoreServiceProxy GetOperatorNumeric success");
    return result;
}

std::u16string CoreServiceProxy::GetOperatorName(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_OPERATOR_NAME), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGI("GetOperatorName failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("GetOperatorName call end");
    return result;
}

bool CoreServiceProxy::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_NETWORK_SEARCH_RESULT), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkSearchInformation failed, error code is: %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

const sptr<NetworkState> CoreServiceProxy::GetNetworkState(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNetworkState WriteInterfaceToken is false");
        return nullptr;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetNetworkState Remote is null");
        return nullptr;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_NETWORK_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkState failed, error code is %{public}d \n", st);
        return nullptr;
    }
    sptr<NetworkState> result = NetworkState::Unmarshalling(reply);
    if (result == nullptr) {
        TELEPHONY_LOGE("GetNetworkState is null\n");
        return nullptr;
    }
    return result;
}

std::vector<sptr<SignalInformation>> CoreServiceProxy::GetSignalInfoList(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy::GetSignalInfoList slotId : %{public}d", slotId);
    std::vector<sptr<SignalInformation>> result;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSignalInfoList WriteInterfaceToken is false");
        return result;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSignalInfoList Remote is null");
        return result;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIGNAL_INFO_LIST), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSignalInfoList failed, error code is %{public}d\n", st);
        return result;
    }
    ProcessSignalInfo(reply, result);
    return result;
}

static void ProcessSignalInfoGsm(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    std::unique_ptr<GsmSignalInformation> signal = std::make_unique<GsmSignalInformation>();
    if (signal != nullptr) {
        signal->ReadFromParcel(reply);
        result.emplace_back(signal.release());
    }
}

static void ProcessSignalInfoCdma(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    std::unique_ptr<CdmaSignalInformation> signal = std::make_unique<CdmaSignalInformation>();
    if (signal != nullptr) {
        signal->ReadFromParcel(reply);
        result.emplace_back(signal.release());
    }
}

static void ProcessSignalInfoLte(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    std::unique_ptr<LteSignalInformation> signal = std::make_unique<LteSignalInformation>();
    if (signal != nullptr) {
        signal->ReadFromParcel(reply);
        result.emplace_back(signal.release());
    }
}

static void ProcessSignalInfoWcdma(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    std::unique_ptr<WcdmaSignalInformation> signal = std::make_unique<WcdmaSignalInformation>();
    if (signal != nullptr) {
        signal->ReadFromParcel(reply);
        result.emplace_back(signal.release());
    }
}

static void ProcessSignalInfoTdscdma(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    std::unique_ptr<TdScdmaSignalInformation> signal = std::make_unique<TdScdmaSignalInformation>();
    if (signal != nullptr) {
        signal->ReadFromParcel(reply);
        result.emplace_back(signal.release());
    }
}

static void ProcessSignalInfoNr(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    std::unique_ptr<NrSignalInformation> signal = std::make_unique<NrSignalInformation>();
    if (signal != nullptr) {
        signal->ReadFromParcel(reply);
        result.emplace_back(signal.release());
    }
}

void CoreServiceProxy::ProcessSignalInfo(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGI("CoreServiceProxy::GetSignalInfoList size:%{public}d\n", size);
    SignalInformation::NetworkType type;
    for (int i = 0; i < size; ++i) {
        type = static_cast<SignalInformation::NetworkType>(reply.ReadInt32());
        switch (type) {
            case SignalInformation::NetworkType::GSM: {
                ProcessSignalInfoGsm(reply, result);
                break;
            }
            case SignalInformation::NetworkType::CDMA: {
                ProcessSignalInfoCdma(reply, result);
                break;
            }
            case SignalInformation::NetworkType::LTE: {
                ProcessSignalInfoLte(reply, result);
                break;
            }
            case SignalInformation::NetworkType::WCDMA: {
                ProcessSignalInfoWcdma(reply, result);
                break;
            }
            case SignalInformation::NetworkType::TDSCDMA: {
                ProcessSignalInfoTdscdma(reply, result);
                break;
            }
            case SignalInformation::NetworkType::NR: {
                ProcessSignalInfoNr(reply, result);
                break;
            }
            default:
                break;
        }
    }
}

bool CoreServiceProxy::SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("CoreServiceProxy SetRadioState isOn:%{public}d", isOn);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetRadioState WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    data.WriteBool(isOn);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetRadioState Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_RADIO_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetRadioState failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetRadioState WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetRadioState Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_RADIO_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetRadioState failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

std::u16string CoreServiceProxy::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_ISO_COUNTRY_CODE_FOR_NETWORK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("GetIsoCountryCodeForNetwork call end");
    return result;
}

std::u16string CoreServiceProxy::GetImei(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetImei WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetImei Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_IMEI), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetImei failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("CoreServiceProxy::GetImei success");
    return result;
}

std::u16string CoreServiceProxy::GetMeid(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetMeid WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetMeid Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_MEID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetMeid failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("CoreServiceProxy::GetMeid success");
    return result;
}

std::u16string CoreServiceProxy::GetUniqueDeviceId(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetUniqueDeviceId WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetUniqueDeviceId Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_UNIQUE_DEVICE_ID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetUniqueDeviceId failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    return result;
}

bool CoreServiceProxy::HasSimCard(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy HasSimCard ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("HasSimCard WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("HasSimCard Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::HAS_SIM_CARD), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("HasSimCard failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetSimState(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy GetSimState ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimState WriteInterfaceToken is false");
        return TELEPHONY_ERROR;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimState Remote is null");
        return TELEPHONY_ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimState failed, error code is %{public}d \n", st);
        return st;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetSimState call end: result=%{public}d \n", result);
    return result;
}

int32_t CoreServiceProxy::GetCardType(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy GetCardType ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCardType WriteInterfaceToken is false");
        return TELEPHONY_ERROR;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetCardType Remote is null");
        return TELEPHONY_ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_CARD_TYPE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCardType failed, error code is %{public}d \n", st);
        return st;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetCardType call end: result=%{public}d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetISOCountryCodeForSim(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_ISO_COUNTRY_CODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("GetISOCountryCodeForSim call end");
    return result;
}

std::u16string CoreServiceProxy::GetSimOperatorNumeric(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimOperatorNumeric WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimOperatorNumeric Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_OPERATOR_NUMERIC), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimOperatorNumeric failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("GetSimOperatorNumeric call end");
    return result;
}

std::u16string CoreServiceProxy::GetSimSpn(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimSpn WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimSpn Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SPN), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimSpn failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("GetSimSpn call end");
    return result;
}

std::u16string CoreServiceProxy::GetSimIccId(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimIccId WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimIccId Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_ICCID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimIccId failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetIMSI(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetIMSI WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetIMSI Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_IMSI), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIMSI failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

bool CoreServiceProxy::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy IsSimActive ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CoreServiceProxy::IsSimActive invalid simId");
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("IsSimActive WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("IsSimActive Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::IS_SIM_ACTIVE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("IsSimActive failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNetworkSelectionMode WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetNetworkSelectionMode WriteInt32 slotId is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetNetworkSelectionMode Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_NETWORK_SELECTION_MODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkSelectionMode failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteInt32(selectMode)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteInt32 selectMode is false");
        return false;
    }
    if (!data.WriteBool(resumeSelection)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteBool resumeSelection is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (networkInformation != nullptr) {
        networkInformation->Marshalling(data);
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetNetworkSelectionMode Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_NETWORK_SELECTION_MODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetNetworkSelectionMode failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

std::u16string CoreServiceProxy::GetLocaleFromDefaultSim()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim WriteInterfaceToken is false");
        return Str8ToStr16("");
    }

    data.WriteInt32(DEFAULT_SIM_SLOT_ID);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_LANGUAGE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetSimGid1(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimGid1 WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimGid1 Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_GID1), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimGid1 failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac,
    bool longNameRequired)
{
    if (!IsValidSlotId(slotId)) {
        return Str8ToStr16("");
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimEons WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    data.WriteString(plmn);
    data.WriteInt32(lac);
    data.WriteBool(longNameRequired);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimEons Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_EONS), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimEons failed, error code is %{public}d", st);
        return Str8ToStr16("");
    }
    return reply.ReadString16();
}

bool CoreServiceProxy::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    TELEPHONY_LOGI("GetSimAccountInfo slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimAccountInfo WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimAccountInfo Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_SUB_INFO), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimAccountInfo failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    if (result) {
        info.ReadFromParcel(reply);
    }
    return result;
}

bool CoreServiceProxy::SetDefaultVoiceSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetDefaultVoiceSlotId slotId = %{public}d", slotId);
    if (!IsValidSlotIdForDefault(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_DEFAULT_VOICE_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetDefaultVoiceSlotId()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId WriteInterfaceToken is false");
        return ERROR;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId Remote is null");
        return ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_DEFAULT_VOICE_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId failed, error code is %{public}d \n", st);
        return ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetDefaultVoiceSlotId end: result=%{public}d \n", result);
    return result;
}

bool CoreServiceProxy::SetPrimarySlotId(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetPrimarySlotId slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetPrimarySlotId WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetPrimarySlotId Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_PRIMARY_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetPrimarySlotId failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetPrimarySlotId()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPrimarySlotId WriteInterfaceToken is false");
        return ERROR;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetPrimarySlotId Remote is null");
        return ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_PRIMARY_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetPrimarySlotId failed, error code is %{public}d \n", st);
        return ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetPrimarySlotId end: result=%{public}d \n", result);
    return result;
}

bool CoreServiceProxy::SetShowNumber(int32_t slotId, const std::u16string number)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetShowNumber slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    if (!IsValidStringLength(number)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetShowNumber WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(number);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetShowNumber Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_SHOW_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetShowNumber failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("SetShowNumber end: result=%{public}d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetShowNumber(int32_t slotId)
{
    TELEPHONY_LOGI("GetShowNumber slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetShowNumber WriteInterfaceToken is false");
        return u"";
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetShowNumber Remote is null");
        return u"";
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SHOW_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetShowNumber failed, error code is %{public}d \n", st);
        return u"";
    }
    std::u16string result = reply.ReadString16();
    return result;
}

bool CoreServiceProxy::SetShowName(int32_t slotId, const std::u16string name)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetShowName slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    if (!IsValidStringLength(name)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetShowName WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(name);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetShowName Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_SHOW_NAME), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetShowName failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("SetShowName end: result=%{public}d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetShowName(int32_t slotId)
{
    TELEPHONY_LOGI("GetShowName slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetShowName WriteInterfaceToken is false");
        return u"";
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetShowName Remote is null");
        return u"";
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SHOW_NAME), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetShowName failed, error code is %{public}d \n", st);
        return u"";
    }
    std::u16string result = reply.ReadString16();
    return result;
}

bool CoreServiceProxy::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetActiveSimAccountInfoList WriteInterfaceToken is false");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetActiveSimAccountInfoList Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_ACTIVE_ACCOUNT_INFO_LIST), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetActiveSimAccountInfoList failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    if (result) {
        int32_t size = reply.ReadInt32();
        TELEPHONY_LOGI("CoreServiceProxy::GetActiveSimAccountInfoList size = %{public}d", size);
        if (size > MAX_VECTOR) {
            return false;
        }
        iccAccountInfoList.clear();
        for (int i = 0; i < size; i++) {
            IccAccountInfo accountInfo;
            accountInfo.ReadFromParcel(reply);
            TELEPHONY_LOGI("CoreServiceProxy::GetActiveSimAccountInfoList success");
            iccAccountInfoList.emplace_back(accountInfo);
        }
    }
    return result;
}

bool CoreServiceProxy::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CoreServiceProxy::OperatorConfig invalid slotId");
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetOperatorConfigs WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetOperatorConfigs Remote is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_OPERATOR_CONFIG), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetOperatorConfigs failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    if (result) {
        poc.ReadFromParcel(reply);
    }
    return result;
}

bool CoreServiceProxy::IsValidSlotId(int32_t slotId)
{
    int32_t count = GetMaxSimCount();
    if ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < count)) {
        return true;
    } else {
        TELEPHONY_LOGE("SimId is InValid = %{public}d", slotId);
        return false;
    }
}

bool CoreServiceProxy::IsValidSlotIdForDefault(int32_t slotId)
{
    int32_t count = GetMaxSimCount();
    if ((slotId >= DEFAULT_SIM_SLOT_ID_REMOVE) && (slotId < count)) {
        return true;
    } else {
        TELEPHONY_LOGE("SimId is InValid = %{public}d", slotId);
        return false;
    }
}

bool CoreServiceProxy::IsValidStringLength(std::u16string str)
{
    int32_t length = static_cast<int32_t>(str.length());
    if ((length >= MIN_STRING_LE) && (length <= MAX_STRING_LE)) {
        return true;
    } else {
        TELEPHONY_LOGE("string length is InValid = %{public}s", Str16ToStr8(str).c_str());
        return false;
    }
}

bool CoreServiceProxy::UnlockPin(const int32_t slotId, std::u16string pin, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::UnlockPin(), pin = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPin WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(pin);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("UnlockPin Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::UNLOCK_PIN), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPin failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("UnlockPin successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
    }
    return result;
}

bool CoreServiceProxy::UnlockPuk(
    const int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::UnlockPuk(), slotId = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPuk WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin);
    data.WriteString16(puk);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("UnlockPuk Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::UNLOCK_PUK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPuk failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("UnlockPuk successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
    }
    return result;
}

bool CoreServiceProxy::AlterPin(
    const int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::AlterPin(), slotId = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("AlterPin WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin);
    data.WriteString16(oldPin);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("AlterPin Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::ALTER_PIN), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AlterPin failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("AlterPin successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
    }
    return result;
}

bool CoreServiceProxy::UnlockPin2(const int32_t slotId, std::u16string pin2, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::UnlockPin2(), pin = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPin2 WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(pin2);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("UnlockPin2 Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::UNLOCK_PIN2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPin2 failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("UnlockPin2 successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
    }
    return result;
}

bool CoreServiceProxy::UnlockPuk2(
    const int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::UnlockPuk2(), slotId = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPuk2 WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin2);
    data.WriteString16(puk2);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("UnlockPuk2 Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::UNLOCK_PUK2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPuk2 failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("UnlockPuk2 successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
    }
    return result;
}

bool CoreServiceProxy::AlterPin2(
    const int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::AlterPin2(), slotId = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("AlterPin2 WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin2);
    data.WriteString16(oldPin2);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("AlterPin2 Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::ALTER_PIN2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AlterPin2 failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("AlterPin2 successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
    }
    return result;
}

bool CoreServiceProxy::SetLockState(const int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetLockState(), slotId = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetLockState WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(options.lockType));
    data.WriteInt32(static_cast<int32_t>(options.lockState));
    data.WriteString16(options.password);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetLockState Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SWITCH_LOCK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetLockState failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("SetLockState successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("SetLockState successful, result:%{public}d \n", result);
    response.result = reply.ReadInt32();
    if (response.result == UNLOCK_INCORRECT) {
        response.remain = reply.ReadInt32();
        TELEPHONY_LOGI("SetLockState successful, response.remain code is %{public}d \n", response.remain);
    }
    return result;
}

int32_t CoreServiceProxy::GetLockState(int32_t slotId, LockType lockType)
{
    TELEPHONY_LOGI("CoreServiceProxy::GetLockState(), slotId = %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetLockState WriteInterfaceToken is false");
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGI("GetLockState WriteInterfaceToken is true");
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(lockType));
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetLockState Remote is null");
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGI("GetLockState Remote is  != null");
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::CHECK_LOCK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetLockState failed, error code is %{public}d \n", st);
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGI("GetLockState successful, error code is %{public}d \n", st);
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetLockState call end: result=%{public}d \n", result);
    return result;
}

int32_t CoreServiceProxy::RefreshSimState(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy RefreshSimState ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RefreshSimState WriteInterfaceToken is false");
        return TELEPHONY_ERROR;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RefreshSimState Remote is null");
        return TELEPHONY_ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::REFRESH_SIM_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RefreshSimState failed, error code is %{public}d \n", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("RefreshSimState call end:: result = %{public}d", result);
    return result;
}

bool CoreServiceProxy::SetActiveSim(int32_t slotId, int32_t enable)
{
    TELEPHONY_LOGI("CoreServiceProxy SetActiveSim ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CoreServiceProxy::SetActiveSim invalid simId");
        return false;
    }
    static const int32_t DISABLE = 0;
    static const int32_t ENABLE = 1;
    if (enable != DISABLE && enable != ENABLE) {
        TELEPHONY_LOGE("CoreServiceProxy::SetActiveSim invalid enable status");
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetActiveSim WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(enable);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetActiveSim Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_SIM_ACTIVE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetActiveSim failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("SetActiveSim call end:: result = %{public}d", result);
    return result;
}

bool CoreServiceProxy::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("CoreServiceProxy GetPreferredNetwork");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPreferredNetwork WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetPreferredNetwork WriteInt32 slotId is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetPreferredNetwork Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_PREFERRED_NETWORK_MODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetPreferredNetwork failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetPreferredNetwork WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetPreferredNetwork WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteInt32(networkMode)) {
        TELEPHONY_LOGE("SetPreferredNetwork WriteInt32 networkMode is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetPreferredNetwork Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_PREFERRED_NETWORK_MODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetPreferredNetwork failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

std::u16string CoreServiceProxy::GetSimTelephoneNumber(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimTelephoneNumber WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimTelephoneNumber Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_PHONE_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimTelephoneNumber failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimTeleNumberIdentifier WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimTeleNumberIdentifier Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_SIM_TELENUMBER_IDENTIFIER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimTeleNumberIdentifier failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetVoiceMailIdentifier(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_VOICE_MAIL_TAG), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetVoiceMailNumber(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return u"";
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetVoiceMailNumber WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetVoiceMailNumber Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_VOICE_MAIL_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailNumber failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreServiceProxy::QueryIccDiallingNumbers(int slotId, int type)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    if (!IsValidSlotId(slotId)) {
        return result;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers WriteInterfaceToken is false");
        return result;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers WriteInt32 slotId is false");
        return result;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers WriteInt32 type is false");
        return result;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers Remote is null");
        return result;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_GET), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers failed, error code is %{public}d\n", st);
        return result;
    }
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGI("CoreServiceProxy::QueryIccDiallingNumbers size:%{public}d\n", size);
    for (int i = 0; i < size; i++) {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(reply);
        result.emplace_back(diallingNumber);
    }
    return result;
}

bool CoreServiceProxy::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy AddIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("AddIccDiallingNumbers WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("AddIccDiallingNumbers WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("AddIccDiallingNumbers WriteInt32 type is false");
        return false;
    }
    if (diallingNumber != nullptr) {
        diallingNumber->Marshalling(data);
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("AddIccDiallingNumbers Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_INSERT), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AddIccDiallingNumbers failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy DelIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("DelIccDiallingNumbers WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("DelIccDiallingNumbers WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("DelIccDiallingNumbers WriteInt32 type is false");
        return false;
    }
    if (diallingNumber != nullptr) {
        diallingNumber->Marshalling(data);
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("DelIccDiallingNumbers Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_DELETE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("DelIccDiallingNumbers failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy UpdateIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers WriteInt32 type is false");
        return false;
    }
    if (diallingNumber != nullptr) {
        diallingNumber->Marshalling(data);
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::ICC_DIALLING_NUMBERS_UPDATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::SetVoiceMailInfo(
    const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy SetVoiceMailInfo ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetVoiceMailInfo WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetVoiceMailInfo WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteString16(mailName)) {
        TELEPHONY_LOGE("SetVoiceMailInfo WriteString16 mailName is false");
        return false;
    }
    if (!data.WriteString16(mailNumber)) {
        TELEPHONY_LOGE("SetVoiceMailInfo WriteString16 mailNumber is false");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetVoiceMailInfo Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SET_VOICE_MAIL), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetVoiceMailInfo failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetMaxSimCount()
{
    char simSlotCount[SYSPARA_SIZE] = {0};
    GetParameter(TEL_SIM_SLOT_COUNT.c_str(), DEFAULT_SLOT_COUNT.c_str(), simSlotCount, SYSPARA_SIZE);
    int32_t slotCount = std::atoi(simSlotCount);
    return slotCount;
}

bool CoreServiceProxy::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SendEnvelopeCmd WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    data.WriteString(cmd);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SendEnvelopeCmd Remote is null");
        return ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::STK_CMD_FROM_APP_ENVELOPE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SendEnvelopeCmd failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("SendEnvelopeCmd end: result=%{public}d \n", result);
    return result;
}

bool CoreServiceProxy::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SendTerminalResponseCmd WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    data.WriteString(cmd);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SendTerminalResponseCmd Remote is null");
        return ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::STK_CMD_FROM_APP_TERMINAL_RESPONSE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SendTerminalResponseCmd failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("SendTerminalResponseCmd end: result=%{public}d \n", result);
    return result;
}

bool CoreServiceProxy::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    TELEPHONY_LOGI("CoreServiceProxy::UnlockSimLock(), slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockSimLock WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(lockInfo.lockType));
    data.WriteString16(lockInfo.password);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("UnlockSimLock Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::UNLOCK_SIMLOCK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockSimLock failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGI("UnlockSimLock successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    response.remain = reply.ReadInt32();
    return result;
}

int32_t CoreServiceProxy::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slotId!");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    TELEPHONY_LOGI("CoreServiceProxy GetImsRegStatus slotId:%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetImsRegStatus WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetImsRegStatus WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(imsSrvType)) {
        TELEPHONY_LOGE("GetImsRegStatus WriteInt32 imsSrvType is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetImsRegStatus Remote is null");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(InterfaceID::GET_IMS_REG_STATUS), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetImsRegStatus failed, error code is %{public}d \n", st);
        return st;
    }
    int32_t ret = reply.ReadInt32();
    info.imsRegState = static_cast<ImsRegState>(reply.ReadInt32());
    info.imsRegTech = static_cast<ImsRegTech>(reply.ReadInt32());
    return ret;
}

std::vector<sptr<CellInformation>> CoreServiceProxy::GetCellInfoList(int32_t slotId)
{
    std::vector<sptr<CellInformation>> cells;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCellInfoList WriteInterfaceToken is false");
        return cells;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetCellInfoList Remote is null");
        return cells;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_CELL_INFO_LIST), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCellInfoList failed, error code is %{public}d\n", st);
        return cells;
    }

    ProcessCellInfo(reply, cells);
    TELEPHONY_LOGI("CoreServiceProxy::GetCellInfoList cell size:%{public}zu\n", cells.size());
    return cells;
}

void CoreServiceProxy::ProcessCellInfo(MessageParcel &reply, std::vector<sptr<CellInformation>> &cells)
{
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGI("CoreServiceProxy::ProcessCellInfo size:%{public}d\n", size);
    CellInformation::CellType type;
    for (int i = 0; i < size; ++i) {
        type = static_cast<CellInformation::CellType>(reply.ReadInt32());
        switch (type) {
            case CellInformation::CellType::CELL_TYPE_GSM: {
                ProcessReply<GsmCellInformation>(reply, cells);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_LTE: {
                ProcessReply<LteCellInformation>(reply, cells);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_WCDMA: {
                ProcessReply<WcdmaCellInformation>(reply, cells);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_CDMA: {
                ProcessReply<CdmaCellInformation>(reply, cells);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
                ProcessReply<TdscdmaCellInformation>(reply, cells);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_NR: {
                ProcessReply<NrCellInformation>(reply, cells);
                break;
            }
            default:
                break;
        }
    }
}

bool CoreServiceProxy::SendUpdateCellLocationRequest(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest WriteInterfaceToken is false");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest Remote is null");
        return false;
    }
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::GET_CELL_LOCATION), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest failed, error code is %{public}d \n", st);
        return false;
    }

    return reply.ReadBool();
}

bool CoreServiceProxy::HasOperatorPrivileges(const int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("HasOperatorPrivileges WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("HasOperatorPrivileges Remote is null");
        return ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::HAS_OPERATOR_PRIVILEGES), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("HasOperatorPrivileges failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    TELEPHONY_LOGI("HasOperatorPrivileges end: result=%{public}d \n", result);
    return result;
}

int32_t CoreServiceProxy::SimAuthentication(int32_t slotId, const std::string &aid, const std::string &authData,
    SimAuthenticationResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SimAuthentication WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    data.WriteString(aid);
    data.WriteString(authData);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SimAuthentication Remote is null");
        return ERROR;
    }
    int32_t st = Remote()->SendRequest(uint32_t(InterfaceID::SIM_AUTHENTICATION), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SimAuthentication failed, error code is %{public}d", st);
        return ERROR;
    }
    response.sw1 = reply.ReadInt32();
    response.sw2 = reply.ReadInt32();
    response.response = reply.ReadString();
    TELEPHONY_LOGI("SimAuthentication end: result=%{public}d", st);
    return ERR_NONE;
}

bool CoreServiceProxy::IsNrSupported(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("IsNrSupported WriteInterfaceToken is false");
        return false;
    }
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(static_cast<uint32_t>(InterfaceID::IS_NR_SUPPORTED), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("IsNrSupported failed, error code is %{public}d \n", st);
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

NrMode CoreServiceProxy::GetNrOptionMode(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNrOptionMode WriteInterfaceToken is false");
        return NrMode::NR_MODE_UNKNOWN;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetNrOptionMode Remote is null");
        return NrMode::NR_MODE_UNKNOWN;
    }
    int32_t st = Remote()->SendRequest(static_cast<uint32_t>(InterfaceID::GET_NR_OPTION_MODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetNrOptionMode failed, error code is %{public}d \n", st);
        return NrMode::NR_MODE_UNKNOWN;
    }

    return static_cast<NrMode>(reply.ReadInt32());
}

int32_t CoreServiceProxy::RegImsCallback(MessageParcel &idata)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t imsSrvType = idata.ReadInt32();
    int32_t slotId = idata.ReadInt32();
    sptr<IRemoteObject> callback  = idata.ReadRemoteObject();
    TELEPHONY_LOGI("imsSrvType is %{public}d, slotId is %{public}d", imsSrvType, slotId);
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceProxy::RegImsCallback is nullptr");
        return ERROR;
    }
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RegisterCallBack WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(imsSrvType)) {
        TELEPHONY_LOGE("WriteInt32 ERROR");
        return ERROR;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 ERROR");
        return ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        TELEPHONY_LOGE("WriteRemoteObject ERROR");
        return ERROR;
    }
    sptr<OHOS::IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(InterfaceID::REG_IMS_CALLBACK), data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function RegisterCallBack! errCode:%{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::UnRegImsCallback(MessageParcel &idata)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t imsSrvType = idata.ReadInt32();
    int32_t slotId = idata.ReadInt32();
    sptr<IRemoteObject> callback  = idata.ReadRemoteObject();
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceProxy::RegImsCallback is nullptr");
    }
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RegisterCallBack WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(imsSrvType);
    data.WriteInt32(slotId);
    data.WriteRemoteObject(callback);
    sptr<OHOS::IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(InterfaceID::UN_REG_IMS_CALLBACK), data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function UnRegImsCallback! errCode:%{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}
} // namespace Telephony
} // namespace OHOS

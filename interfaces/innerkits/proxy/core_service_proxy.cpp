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

#include "core_service_proxy.h"
#include "string_ex.h"
#include "core_manager.h"

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
    TELEPHONY_LOGD("CoreServiceProxy GetPsRadioTech");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPsRadioTech WriteInterfaceToken is false");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetPsRadioTech Remote is null");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    int32_t st = Remote()->SendRequest(GET_PS_RADIO_TECH, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetPsRadioTech failed, error code is %{public}d ", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGD("GetPsRadioTech call end: result=%{public}d \n", result);
    return result;
}

int32_t CoreServiceProxy::GetCsRadioTech(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy GetCsRadioTech");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCsRadioTech WriteInterfaceToken is false");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetCsRadioTech Remote is null");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    int32_t st = Remote()->SendRequest(GET_CS_RADIO_TECH, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCsRadioTech failed, error code is %{public}d \n", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGD("GetCsRadioTech call end: result=%{public}d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetOperatorNumeric(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy GetOperatorNumeric");
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

    int32_t st = Remote()->SendRequest(GET_OPERATOR_NUMERIC, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCsRadioTech failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGD("CoreServiceProxy GetOperatorNumeric %{public}s\n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetOperatorName(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetOperatorName");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetOperatorName WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetOperatorName Remote is null");
        return Str8ToStr16("");
    }

    int32_t st = Remote()->SendRequest(GET_OPERATOR_NAME, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetOperatorName failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGD("GetOperatorName call end: result=%{public}s \n", str.c_str());
    return result;
}

bool CoreServiceProxy::GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetNetworkSearchResult");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNetworkSearchResult WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetNetworkSearchResult WriteInt32 slotId is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchResult Remote is null");
        return false;
    }

    int32_t st = Remote()->SendRequest(GET_NETWORK_SEARCH_RESULT, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkSearchResult failed, error code is: %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

const sptr<NetworkState> CoreServiceProxy::GetNetworkState(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetNetworkState");
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

    int32_t st = Remote()->SendRequest(GET_NETWORK_STATE, data, reply, option);
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
    TELEPHONY_LOGD("CoreServiceProxy::GetSignalInfoList");
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

    int32_t st = Remote()->SendRequest(GET_SIGNAL_INFO_LIST, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSignalInfoList failed, error code is %{public}d\n", st);
        return result;
    }
    ProcessSignalInfo(reply, result);
    return result;
}

void CoreServiceProxy::ProcessSignalInfo(MessageParcel &reply, std::vector<sptr<SignalInformation>> &result)
{
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGD("CoreServiceProxy::GetSignalInfoList size:%{public}d\n", size);
    SignalInformation::NetworkType type;
    for (int i = 0; i < size; ++i) {
        type = static_cast<SignalInformation::NetworkType>(reply.ReadInt32());
        switch (type) {
            case SignalInformation::NetworkType::GSM: {
                std::unique_ptr<GsmSignalInformation> signal = std::make_unique<GsmSignalInformation>();
                if (signal != nullptr) {
                    signal->ReadFromParcel(reply);
                    result.emplace_back(signal.release());
                }
                break;
            }
            case SignalInformation::NetworkType::CDMA: {
                std::unique_ptr<CdmaSignalInformation> signal = std::make_unique<CdmaSignalInformation>();
                if (signal != nullptr) {
                    signal->ReadFromParcel(reply);
                    result.emplace_back(signal.release());
                }
                break;
            }
            case SignalInformation::NetworkType::LTE: {
                std::unique_ptr<LteSignalInformation> signal = std::make_unique<LteSignalInformation>();
                if (signal != nullptr) {
                    signal->ReadFromParcel(reply);
                    result.emplace_back(signal.release());
                }
                break;
            }
            case SignalInformation::NetworkType::WCDMA: {
                std::unique_ptr<WcdmaSignalInformation> signal = std::make_unique<WcdmaSignalInformation>();
                if (signal != nullptr) {
                    signal->ReadFromParcel(reply);
                    result.emplace_back(signal.release());
                }
                break;
            }
            default:
                break;
        }
    }
}

bool CoreServiceProxy::SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreServiceProxy SetRadioState isOn:%{public}d", isOn);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetRadioState WriteInterfaceToken is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    data.WriteBool(isOn);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetRadioState Remote is null");
        return false;
    }

    int32_t st = Remote()->SendRequest(SET_RADIO_STATE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetRadioState failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreServiceProxy GetRadioState");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetRadioState WriteInterfaceToken is false");
        return false;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetRadioState Remote is null");
        return false;
    }

    int32_t st = Remote()->SendRequest(GET_RADIO_STATE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetRadioState failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

std::u16string CoreServiceProxy::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetIsoCountryCodeForNetwork");
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

    int32_t st = Remote()->SendRequest(GET_ISO_COUNTRY_CODE_FOR_NETWORK, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGD("GetIsoCountryCodeForNetwork call end: result=%{public}s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetImei(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetImei");
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
    int32_t st = Remote()->SendRequest(GET_IMEI, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetImei failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    return result;
}

bool CoreServiceProxy::HasSimCard(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy HasSimCard ::%{public}d", slotId);
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

    int32_t st = Remote()->SendRequest(HAS_SIM_CARD, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("HasSimCard failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetSimState(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy GetSimState ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimState WriteInterfaceToken is false");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimState Remote is null");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    int32_t st = Remote()->SendRequest(GET_SIM_STATE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimState failed, error code is %{public}d \n", st);
        return st;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGD("GetSimState call end: result=%{public}d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetIsoCountryCodeForSim(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetIsoCountryCodeForSim");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetIsoCountryCodeForSim WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetIsoCountryCodeForSim Remote is null");
        return Str8ToStr16("");
    }

    int32_t st = Remote()->SendRequest(GET_ISO_COUNTRY_CODE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIsoCountryCodeForSim failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGD("GetIsoCountryCodeForSim call end: result=%s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetSimOperatorNumeric(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetSimOperatorNumeric");
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

    int32_t st = Remote()->SendRequest(GET_SIM_OPERATOR_NUMERIC, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimOperatorNumeric failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGD("GetSimOperatorNumeric call end: result=%{public}s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetSimSpn(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetSimSpn");
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

    int32_t st = Remote()->SendRequest(GET_SPN, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimSpn failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGD("GetSimSpn call end: result=%s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetSimIccId(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetSimIccId");
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

    int32_t st = Remote()->SendRequest(GET_ICCID, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimIccId failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetSimIccId call end");
    return result;
}

std::u16string CoreServiceProxy::GetIMSI(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetIMSI");
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

    int32_t st = Remote()->SendRequest(GET_IMSI, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIMSI failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetIMSI call end");
    return result;
}

bool CoreServiceProxy::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy IsSimActive ::%{public}d", slotId);
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

    int32_t st = Remote()->SendRequest(IS_SIM_ACTIVE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("IsSimActive failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGD("CoreServiceProxy GetNetworkSelectionMode ::%{public}d", slotId);
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

    int32_t st = Remote()->SendRequest(GET_NETWORK_SELECTION_MODE, data, reply, option);
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
    TELEPHONY_LOGD("CoreServiceProxy SetNetworkSelectionMode ::%{public}d", slotId);
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

    int32_t st = Remote()->SendRequest(SET_NETWORK_SELECTION_MODE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetNetworkSelectionMode failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

std::u16string CoreServiceProxy::GetLocaleFromDefaultSim()
{
    TELEPHONY_LOGD("CoreServiceProxy::GetLocaleFromDefaultSim");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    int slotId = CoreManager::DEFAULT_SLOT_ID;
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim Remote is null");
        return Str8ToStr16("");
    }

    int32_t st = Remote()->SendRequest(GET_SIM_LANGUAGE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetLocaleFromDefaultSim call end");
    return result;
}

std::u16string CoreServiceProxy::GetSimGid1(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetSimGid1");
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

    int32_t st = Remote()->SendRequest(GET_SIM_GID1, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimGid1 failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetSimGid1 call end");
    return result;
}

bool CoreServiceProxy::GetSimAccountInfo(int32_t subId, IccAccountInfo &info)
{
    TELEPHONY_LOGD("GetSimAccountInfo subId = %{public}d", subId);
    if (!IsValidSimId(subId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimAccountInfo WriteInterfaceToken is false");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    data.WriteInt32(subId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetSimAccountInfo Remote is null");
        return false;
    }

    int32_t st = Remote()->SendRequest(GET_SIM_ACCOUNT_INFO, data, reply, option);
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

bool CoreServiceProxy::SetDefaultVoiceSlotId(int32_t subId)
{
    TELEPHONY_LOGD("CoreServiceProxy::SetDefaultVoiceSlotId subId = %{public}d", subId);
    if (!IsValidSimId(subId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId WriteInterfaceToken is false");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    data.WriteInt32(subId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId Remote is null");
        return false;
    }

    int32_t st = Remote()->SendRequest(SET_DEFAULT_VOICE_SLOTID, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetDefaultVoiceSlotId()
{
    TELEPHONY_LOGD("CoreServiceProxy::GetDefaultVoiceSlotId ");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId WriteInterfaceToken is false");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId Remote is null");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = Remote()->SendRequest(GET_DEFAULT_VOICE_SLOTID, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId failed, error code is %{public}d \n", st);
        return ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGD("GetDefaultVoiceSlotId end: result=%{public}d \n", result);
    return result;
}

bool CoreServiceProxy::IsValidSimId(int32_t subId)
{
    if (subId >= CoreManager::DEFAULT_SLOT_ID && subId <= MAX_SLOT) {
        return true;
    }
    TELEPHONY_LOGE("SimId is InValid = %d", subId);
    return false;
}

bool CoreServiceProxy::UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId)
{
    TELEPHONY_LOGD("CoreServiceProxy::UnlockPin(), pin = %{public}d", phoneId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RequestUnlockPin WriteInterfaceToken is false");
        return false;
    }
    TELEPHONY_LOGD("RequestUnlockPin WriteInterfaceToken is true");
    data.WriteString16(pin);
    data.WriteInt32(phoneId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RequestUnlockPin Remote is null");
        return false;
    }

    TELEPHONY_LOGD("RequestUnlockPin Remote is  != null");
    int32_t st = Remote()->SendRequest(UNLOCK_PIN, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RequestUnlockPin failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGD("RequestUnlockPin successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    response.remain = reply.ReadInt32();
    return result;
}

bool CoreServiceProxy::UnlockPuk(
    std::u16string newPin, std::u16string puk, LockStatusResponse &response, int32_t phoneId)
{
    TELEPHONY_LOGD("CoreServiceProxy::UnlockPuk(), phoneId = %{public}d", phoneId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RequestUnlockPuk WriteInterfaceToken is false");
        return false;
    }
    TELEPHONY_LOGD("RequestUnlockPuk WriteInterfaceToken is true");
    data.WriteString16(newPin);
    data.WriteString16(puk);
    data.WriteInt32(phoneId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RequestUnlockPuk Remote is null");
        return false;
    }

    TELEPHONY_LOGD("RequestUnlockPuk Remote is  != null");
    int32_t st = Remote()->SendRequest(UNLOCK_PUK, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RequestUnlockPuk failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGD("RequestUnlockPuk successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    response.remain = reply.ReadInt32();
    return result;
}

bool CoreServiceProxy::AlterPin(
    std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int32_t phoneId)
{
    TELEPHONY_LOGD("CoreServiceProxy::AlterPin(), phoneId = %{public}d", phoneId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RequestAlterPin WriteInterfaceToken is false");
        return false;
    }
    TELEPHONY_LOGD("RequestAlterPin WriteInterfaceToken is true");
    data.WriteString16(newPin);
    data.WriteString16(oldPin);
    data.WriteInt32(phoneId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RequestAlterPin Remote is null");
        return false;
    }

    TELEPHONY_LOGD("RequestAlterPin Remote is  != null");
    int32_t st = Remote()->SendRequest(ALTER_PIN, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RequestAlterPin failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGD("RequestAlterPin successful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    response.remain = reply.ReadInt32();
    return result;
}

bool CoreServiceProxy::SetLockState(
    std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId)
{
    TELEPHONY_LOGD("CoreServiceProxy::SetLockState(), phoneId = %{public}d", phoneId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RequestSetLockState WriteInterfaceToken is false");
        return false;
    }
    TELEPHONY_LOGD("RequestSetLockState WriteInterfaceToken is true");
    data.WriteString16(pin);
    data.WriteInt32(enable);
    data.WriteInt32(phoneId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RequestSetLockState Remote is null");
        return false;
    }

    TELEPHONY_LOGD("RequestSetLockState Remote is  != null");
    int32_t st = Remote()->SendRequest(SWITCH_PIN, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RequestSetLockState failed, error code is %{public}d \n", st);
        return false;
    }
    TELEPHONY_LOGD("RequestSetLockState sucessful, error code is %{public}d \n", st);
    bool result = reply.ReadBool();
    response.result = reply.ReadInt32();
    response.remain = reply.ReadInt32();
    return result;
}

int32_t CoreServiceProxy::GetLockState(int32_t phoneId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetLockState(), phoneId = %{public}d", phoneId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RequestGetLockState WriteInterfaceToken is false");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    TELEPHONY_LOGD("RequestGetLockState WriteInterfaceToken is true");
    data.WriteInt32(phoneId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RequestGetLockState Remote is null");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    TELEPHONY_LOGD("RequestGetLockState Remote is  != null");
    int32_t st = Remote()->SendRequest(CHECK_PIN, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RequestGetLockState failed, error code is %{public}d \n", st);
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGD("RequestGetLockState successful, error code is %{public}d \n", st);
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGD("GetLockState call end: result=%{public}d \n", result);
    return result;
}

int32_t CoreServiceProxy::RefreshSimState(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy RefreshSimState ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RefreshSimState WriteInterfaceToken is false");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("RefreshSimState Remote is null");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    int32_t st = Remote()->SendRequest(REFRESH_SIM_STATE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RefreshSimState failed, error code is %{public}d \n", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGD("RefreshSimState call end:: result = %{public}d", result);
    return result;
}
std::u16string CoreServiceProxy::GetSimTelephoneNumber(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetSimTelephoneNumber");
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(GET_SIM_PHONE_NUMBER, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimTelephoneNumber failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetSimTelephoneNumber call end");
    return result;
}

std::u16string CoreServiceProxy::GetVoiceMailIdentifier(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetVoiceMailIdentifier");
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(GET_VOICE_MAIL_TAG, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetVoiceMailIdentifier call end");
    return result;
}

std::u16string CoreServiceProxy::GetVoiceMailNumber(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetVoiceMailNumber");
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(GET_VOICE_MAIL_NUMBER, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailNumber failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    TELEPHONY_LOGD("GetVoiceMailNumber call end");
    return result;
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreServiceProxy::QueryIccDiallingNumbers(int slotId, int type)
{
    TELEPHONY_LOGD("CoreServiceProxy::QueryIccDiallingNumbers");
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(ICC_PHONE_BOOK_GET, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers failed, error code is %{public}d\n", st);
        return result;
    }
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGD("CoreServiceProxy::QueryIccDiallingNumbers size:%{public}d\n", size);
    for (int i = 0; i < size; i++) {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(reply);
        result.emplace_back(diallingNumber);
    }
    return result;
}

bool CoreServiceProxy::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGD("CoreServiceProxy AddIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(ICC_PHONE_BOOK_INSERT, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AddIccDiallingNumbers failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGD("CoreServiceProxy DelIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(ICC_PHONE_BOOK_DELETE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("DelIccDiallingNumbers failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGD("CoreServiceProxy UpdateIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSimId(slotId)) {
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
    int32_t st = Remote()->SendRequest(ICC_PHONE_BOOK_UPDATE, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}


bool CoreServiceProxy::SetVoiceMail(
    const std::u16string &mailName, const std::u16string &mailNumber, int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy SetVoiceMail ::%{public}d", slotId);
    if (!IsValidSimId(slotId)) {
        return false;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetVoiceMail WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetVoiceMail WriteInt32 slotId is false");
        return false;
    }
    if (!data.WriteString16(mailName)) {
        TELEPHONY_LOGE("SetVoiceMail WriteString16 mailName is false");
        return false;
    }
    if (!data.WriteString16(mailNumber)) {
        TELEPHONY_LOGE("SetVoiceMail WriteString16 mailNumber is false");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("SetVoiceMail Remote is null");
        return false;
    }
    int32_t st = Remote()->SendRequest(SET_VOICE_MAIL, data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetVoiceMail failed, error code is %{public}d \n", st);
        return false;
    }
    return reply.ReadBool();
}
} // namespace Telephony
} // namespace OHOS

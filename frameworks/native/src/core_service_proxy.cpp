/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "network_search_types.h"
#include "parameter.h"
#include "sim_state_type.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t MAX_SIZE = 1000;
#ifdef CORE_SERVICE_SUPPORT_ESIM
constexpr uint32_t ESIM_MAX_SIZE = 1000;
#endif
bool CoreServiceProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(CoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write interface token failed");
        return false;
    }
    return true;
}

int32_t CoreServiceProxy::GetPsRadioTech(int32_t slotId, int32_t &psRadioTech)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPsRadioTech WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetPsRadioTech Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_PS_RADIO_TECH), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetPsRadioTech failed, error code is %{public}d ", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        psRadioTech = reply.ReadInt32();
    }
    return result;
}

int32_t CoreServiceProxy::GetCsRadioTech(int32_t slotId, int32_t &csRadioTech)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCsRadioTech WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetCsRadioTech Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_CS_RADIO_TECH), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCsRadioTech failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        csRadioTech = reply.ReadInt32();
    } else {
        TELEPHONY_LOGE("GetCsRadioTech call failed: result=%{public}d", result);
    }
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetOperatorNumeric Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_OPERATOR_NUMERIC), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCsRadioTech failed, error code is %{public}d", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("CoreServiceProxy GetOperatorNumeric success");
    return result;
}

std::string CoreServiceProxy::GetResidentNetworkNumeric(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetResidentNetworkNumeric WriteInterfaceToken is false");
        return "";
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetResidentNetworkNumeric Remote is null");
        return "";
    }
    int32_t st = remote->SendRequest(
        uint32_t(CoreServiceInterfaceCode::GET_RESIDENT_NETWORK_NUMERIC), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetResidentNetworkNumeric failed, error code is %{public}d", st);
        return "";
    }
    std::string result = reply.ReadString();
    return result;
}

int32_t CoreServiceProxy::GetOperatorName(int32_t slotId, std::u16string &operatorName)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_OPERATOR_NAME), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGI("GetOperatorName failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        operatorName = reply.ReadString16();
    } else {
        TELEPHONY_LOGE("GetOperatorName call fail,slotId:%{public}d", slotId);
    }
    return result;
}


int32_t CoreServiceProxy::GetBasebandVersion(int32_t slotId, std::string &version)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetBasebandVersion WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetBasebandVersion Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_BASEBAND_VERSION),
        data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetBasebandVersion failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        version = reply.ReadString();
    }
    return result;
}

int32_t CoreServiceProxy::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_NETWORK_SEARCH_RESULT), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkSearchInformation failed, error code is: %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNetworkState WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetNetworkState Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_NETWORK_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkState failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        networkState = NetworkState::Unmarshalling(reply);
    }
    return result;
}

int32_t CoreServiceProxy::GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals)
{
    TELEPHONY_LOGD("CoreServiceProxy::GetSignalInfoList slotId : %{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSignalInfoList WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSignalInfoList Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIGNAL_INFO_LIST), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSignalInfoList failed, error code is %{public}d\n", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        ProcessSignalInfo(reply, signals);
    }
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
    TELEPHONY_LOGD("CoreServiceProxy::GetSignalInfoList size:%{public}d\n", size);
    if (size >= MAX_SIZE) {
        TELEPHONY_LOGE("CoreServiceProxy::GetSignalInfoList over max size");
        return;
    }
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

int32_t CoreServiceProxy::SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("CoreServiceProxy SetRadioState isOn:%{public}d", isOn);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetRadioState WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    data.WriteBool(isOn);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetRadioState Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_RADIO_STATE), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetRadioState failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetRadioState WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetRadioState Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_RADIO_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetRadioState failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_ISO_COUNTRY_CODE_FOR_NETWORK), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIsoCountryCodeForNetwork failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        countryCode = reply.ReadString16();
    }
    TELEPHONY_LOGD("GetIsoCountryCodeForNetwork call end");
    return result;
}

int32_t CoreServiceProxy::GetImei(int32_t slotId, std::u16string &imei)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetImei WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetImei Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_IMEI), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetImei failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        imei = reply.ReadString16();
    }
    TELEPHONY_LOGD("CoreServiceProxy::GetImei success");
    return result;
}

int32_t CoreServiceProxy::GetImeiSv(int32_t slotId, std::u16string &imeiSv)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetImeiSv WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetImeiSv Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_IMEISV), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetImeiSv failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        imeiSv = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetMeid(int32_t slotId, std::u16string &meid)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetMeid WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetMeid Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_MEID), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetMeid failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        meid = reply.ReadString16();
    }
    TELEPHONY_LOGI("CoreServiceProxy::GetMeid success");
    return result;
}

int32_t CoreServiceProxy::GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetUniqueDeviceId WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetUniqueDeviceId Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_UNIQUE_DEVICE_ID), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetUniqueDeviceId failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        deviceId = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::HasSimCard(int32_t slotId, bool &hasSimCard)
{
    TELEPHONY_LOGD("CoreServiceProxy HasSimCard ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("HasSimCard WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("HasSimCard Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::HAS_SIM_CARD), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("HasSimCard failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        hasSimCard = reply.ReadBool();
    }
    return result;
}

int32_t CoreServiceProxy::GetSimState(int32_t slotId, SimState &simState)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        simState = static_cast<SimState>(reply.ReadInt32());
    }
    TELEPHONY_LOGD("call end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetDsdsMode(int32_t &dsdsMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_DSDS_MODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        dsdsMode = static_cast<int32_t>(reply.ReadInt32());
    }
    TELEPHONY_LOGD("call end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetCardType(int32_t slotId, CardType &cardType)
{
    TELEPHONY_LOGI("CoreServiceProxy GetCardType ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCardType WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetCardType Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_CARD_TYPE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetCardType failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        cardType = static_cast<CardType>(reply.ReadInt32());
    }
    TELEPHONY_LOGI("GetCardType call end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_ISO_COUNTRY_CODE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetISOCountryCodeForSim failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        countryCode = reply.ReadString16();
    }
    TELEPHONY_LOGI("GetISOCountryCodeForSim call end");
    return result;
}

int32_t CoreServiceProxy::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimOperatorNumeric WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimOperatorNumeric Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_OPERATOR_NUMERIC), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimOperatorNumeric failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        operatorNumeric = reply.ReadString16();
    }
    TELEPHONY_LOGD("GetSimOperatorNumeric call end");
    return result;
}

int32_t CoreServiceProxy::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimSpn WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimSpn Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SPN), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimSpn failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        spn = reply.ReadString16();
    }
    TELEPHONY_LOGI("GetSimSpn call end");
    return result;
}

int32_t CoreServiceProxy::GetSimIccId(int32_t slotId, std::u16string &iccId)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimIccId WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimIccId Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_ICCID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimIccId failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        iccId = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetIMSI(int32_t slotId, std::u16string &imsi)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetIMSI WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetIMSI Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_IMSI), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetIMSI failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        imsi = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::IsCTSimCard(int32_t slotId, bool &isCTSimCard)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("IsCTSimCard WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("IsCTSimCard Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::IS_CT_SIM_CARD), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("IsCTSimCard failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        isCTSimCard = reply.ReadBool();
    }
    return result;
}

bool CoreServiceProxy::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGD("CoreServiceProxy IsSimActive ::%{public}d", slotId);
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("IsSimActive Remote is null");
        return false;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::IS_SIM_ACTIVE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("IsSimActive failed, error code is %{public}d", st);
        return false;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetSlotId(int32_t simId)
{
    if (simId <= 0) {
        TELEPHONY_LOGE("CoreServiceProxy::GetSlotId invalid simId");
        return ERROR;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSlotId WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(simId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSlotId Remote is null");
        return ERROR;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSlotId failed, error code is %{public}d", st);
        return ERROR;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetSimId(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CoreServiceProxy::GetSimId invalid slotId");
        return ERROR;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimId WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimId Remote is null");
        return ERROR;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_SIMID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimId failed, error code is %{public}d", st);
        return ERROR;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNetworkSelectionMode WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetNetworkSelectionMode WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetNetworkSelectionMode Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_NETWORK_SELECTION_MODE), data,
        reply, option);
    if (st != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("GetNetworkSelectionMode failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!data.WriteInt32(selectMode)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteInt32 selectMode is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!data.WriteBool(resumeSelection)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode WriteBool resumeSelection is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    if (networkInformation != nullptr) {
        networkInformation->Marshalling(data);
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetNetworkSelectionMode Remote is null");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_NETWORK_SELECTION_MODE), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetNetworkSelectionMode failed, error code is %{public}d", error);
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return reply.ReadInt32();
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_LANGUAGE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetLocaleFromDefaultSim failed, error code is %{public}d", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

int32_t CoreServiceProxy::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimGid1 WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimGid1 Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_GID1), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimGid1 failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        gid1 = reply.ReadString16();
    }
    return result;
}

std::u16string CoreServiceProxy::GetSimGid2(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return Str8ToStr16("");
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimGid2 WriteInterfaceToken is false");
        return Str8ToStr16("");
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimGid2 Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_GID2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimGid2 failed, error code is %{public}d", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

std::u16string CoreServiceProxy::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired)
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimEons Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_EONS), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimEons failed, error code is %{public}d", st);
        return Str8ToStr16("");
    }
    return reply.ReadString16();
}

int32_t CoreServiceProxy::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    TELEPHONY_LOGD("GetSimAccountInfo slotId = %{public}d", slotId);
    if (!IsValidSlotIdEx(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimAccountInfo WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimAccountInfo Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_SUB_INFO), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimAccountInfo failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        info.ReadFromParcel(reply);
    }
    return result;
}

int32_t CoreServiceProxy::SetDefaultVoiceSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetDefaultVoiceSlotId slotId = %{public}d", slotId);
    if (!IsValidSlotIdForDefault(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_DEFAULT_VOICE_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetDefaultVoiceSlotId failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId Remote is null");
        return ERROR;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_DEFAULT_VOICE_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetDefaultVoiceSlotId failed, error code is %{public}d", st);
        return ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("GetDefaultVoiceSlotId end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetDefaultVoiceSimId(int32_t &simId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_DEFAULT_VOICE_SIMID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("end: result=%{public}d", result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        simId = reply.ReadInt32();
    }
    return result;
}

int32_t CoreServiceProxy::SetPrimarySlotId(int32_t slotId)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetPrimarySlotId slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetPrimarySlotId WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetPrimarySlotId Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_PRIMARY_SLOTID), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetPrimarySlotId failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetPrimarySlotId(int32_t &slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPrimarySlotId WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetPrimarySlotId Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_PRIMARY_SLOTID), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetPrimarySlotId failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        slotId = reply.ReadInt32();
    } else {
        TELEPHONY_LOGE("GetPrimarySlotId failed: result=%{public}d", result);
    }
    return result;
}

int32_t CoreServiceProxy::SetShowNumber(int32_t slotId, const std::u16string &number)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetShowNumber slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (!IsValidStringLength(number)) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetShowNumber WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(number);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetShowNumber Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_SHOW_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetShowNumber failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("SetShowNumber end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetShowNumber(int32_t slotId, std::u16string &showNumber)
{
    TELEPHONY_LOGI("GetShowNumber slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetShowNumber WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetShowNumber Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SHOW_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetShowNumber failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        showNumber = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::SetShowName(int32_t slotId, const std::u16string &name)
{
    TELEPHONY_LOGI("CoreServiceProxy::SetShowName slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (!IsValidStringLength(name)) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetShowName WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(name);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetShowName Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_SHOW_NAME), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetShowName failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("SetShowName end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetShowName(int32_t slotId, std::u16string &showName)
{
    TELEPHONY_LOGD("GetShowName slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetShowName WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetShowName Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SHOW_NAME), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetShowName failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        showName = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetActiveSimAccountInfoList WriteInterfaceToken is false");
        return false;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetActiveSimAccountInfoList Remote is null");
        return false;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_ACTIVE_ACCOUNT_INFO_LIST), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetActiveSimAccountInfoList failed, error code is %{public}d", st);
        return false;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        int32_t size = reply.ReadInt32();
        TELEPHONY_LOGI("CoreServiceProxy::GetActiveSimAccountInfoList size = %{public}d", size);
        if (size > MAX_VECTOR) {
            return false;
        }
        iccAccountInfoList.clear();
        for (int i = 0; i < size; i++) {
            IccAccountInfo accountInfo;
            accountInfo.ReadFromParcel(reply);
            TELEPHONY_LOGD("CoreServiceProxy::GetActiveSimAccountInfoList success");
            iccAccountInfoList.emplace_back(accountInfo);
        }
    }
    return result;
}

int32_t CoreServiceProxy::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CoreServiceProxy::OperatorConfig invalid slotId");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetOperatorConfigs WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetOperatorConfigs Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_OPERATOR_CONFIG), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetOperatorConfigs failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        poc.ReadFromParcel(reply);
    }
    return result;
}

bool CoreServiceProxy::IsValidSlotId(int32_t slotId)
{
    int32_t count = GetMaxSimCount();
    if ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < count)) {
        return true;
    }

    TELEPHONY_LOGE("SlotId is InValid = %{public}d", slotId);
    return false;
}

bool CoreServiceProxy::IsValidSlotIdEx(int32_t slotId)
{
    int32_t count = GetMaxSimCount();
    // One more slot for VSim.
    if ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < count + 1)) {
        return true;
    }

    TELEPHONY_LOGE("SlotId is InValid = %{public}d", slotId);
    return false;
}

bool CoreServiceProxy::IsValidSlotIdForDefault(int32_t slotId)
{
    int32_t count = GetMaxSimCount();
    if ((slotId >= DEFAULT_SIM_SLOT_ID_REMOVE) && (slotId < count)) {
        return true;
    }

    TELEPHONY_LOGE("SlotId is InValid = %{public}d", slotId);
    return false;
}

bool CoreServiceProxy::IsValidStringLength(std::u16string str)
{
    int32_t length = static_cast<int32_t>(str.length());
    if ((length >= MIN_STRING_LE) && (length <= MAX_STRING_LE)) {
        return true;
    }
    TELEPHONY_LOGE("string length is InValid = %{public}d", length);
    return false;
}

bool CoreServiceProxy::IsValidServiceType(ImsServiceType serviceType)
{
    if (serviceType < ImsServiceType::TYPE_VOICE || serviceType > ImsServiceType::TYPE_SMS) {
        TELEPHONY_LOGE("ServiceType is InValid = %{public}d", serviceType);
        return false;
    }

    return true;
}

int32_t CoreServiceProxy::UnlockPin(const int32_t slotId, const std::u16string &pin, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPin WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(pin);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UnlockPin Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::UNLOCK_PIN), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPin failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::UnlockPuk(
    const int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPuk WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin);
    data.WriteString16(puk);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UnlockPuk Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::UNLOCK_PUK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPuk failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::AlterPin(
    const int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("AlterPin WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin);
    data.WriteString16(oldPin);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("AlterPin Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::ALTER_PIN), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AlterPin failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::UnlockPin2(const int32_t slotId, const std::u16string &pin2, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPin2 WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(pin2);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UnlockPin2 Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::UNLOCK_PIN2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPin2 failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::UnlockPuk2(
    const int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockPuk2 WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin2);
    data.WriteString16(puk2);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UnlockPuk2 Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::UNLOCK_PUK2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockPuk2 failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::AlterPin2(
    const int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("AlterPin2 WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString16(newPin2);
    data.WriteString16(oldPin2);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("AlterPin2 Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::ALTER_PIN2), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AlterPin2 failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::SetLockState(const int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetLockState WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(options.lockType));
    data.WriteInt32(static_cast<int32_t>(options.lockState));
    data.WriteString16(options.password);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetLockState Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SWITCH_LOCK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetLockState failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("SetLockState successful, result:%{public}d", result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        if (response.result == UNLOCK_INCORRECT) {
            response.remain = reply.ReadInt32();
        }
    }
    return result;
}

int32_t CoreServiceProxy::GetLockState(int32_t slotId, LockType lockType, LockState &lockState)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetLockState WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    TELEPHONY_LOGI("GetLockState WriteInterfaceToken is true");
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(lockType));
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetLockState Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    TELEPHONY_LOGI("GetLockState Remote is  != null");
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::CHECK_LOCK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetLockState failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        lockState = static_cast<LockState>(reply.ReadInt32());
    }
    TELEPHONY_LOGI("GetLockState call end: result=%{public}d", result);
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("RefreshSimState Remote is null");
        return TELEPHONY_ERROR;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::REFRESH_SIM_STATE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("RefreshSimState failed, error code is %{public}d", st);
        return TELEPHONY_ERROR;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("RefreshSimState call end:: result = %{public}d", result);
    return result;
}

int32_t CoreServiceProxy::SetActiveSim(int32_t slotId, int32_t enable)
{
    TELEPHONY_LOGI("CoreServiceProxy SetActiveSim ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("CoreServiceProxy::SetActiveSim invalid simId");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    static const int32_t DISABLE = 0;
    static const int32_t ENABLE = 1;
    if (enable != DISABLE && enable != ENABLE) {
        TELEPHONY_LOGE("CoreServiceProxy::SetActiveSim invalid enable status");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetActiveSim WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(enable);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetActiveSim Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_SIM_ACTIVE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetActiveSim failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("SetActiveSim call end:: result = %{public}d", result);
    return result;
}

int32_t CoreServiceProxy::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("CoreServiceProxy GetPreferredNetwork");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetPreferredNetwork WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetPreferredNetwork WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetPreferredNetwork Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_PREFERRED_NETWORK_MODE), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetPreferredNetwork failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetPreferredNetwork WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetPreferredNetwork WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!data.WriteInt32(networkMode)) {
        TELEPHONY_LOGE("SetPreferredNetwork WriteInt32 networkMode is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetPreferredNetwork Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_PREFERRED_NETWORK_MODE), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetPreferredNetwork failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState)
{
    TELEPHONY_LOGD("CoreServiceProxy GetNetworkCapability");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNetworkCapability WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetNetworkCapability WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(networkCapabilityType)) {
        TELEPHONY_LOGE("GetNetworkCapability WriteInt32 deviceType is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetNetworkCapability Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_NETWORK_CAPABILITY), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetNetworkCapability failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t ret = reply.ReadInt32();
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("GetNetworkCapability failed!");
        return ret;
    }
    networkCapabilityState = reply.ReadInt32();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreServiceProxy::SetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState)
{
    TELEPHONY_LOGD("CoreServiceProxy SetNetworkCapability");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetNetworkCapability WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetNetworkCapability WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(networkCapabilityType)) {
        TELEPHONY_LOGE("SetNetworkCapability WriteInt32 type is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(networkCapabilityState)) {
        TELEPHONY_LOGE("SetNetworkCapability WriteInt32 enabled is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetNetworkCapability Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_NETWORK_CAPABILITY), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetNetworkCapability failed, error code is %{public}d \n", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimTelephoneNumber WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimTelephoneNumber Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_PHONE_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimTelephoneNumber failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        telephoneNumber = reply.ReadString16();
    }
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
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimTeleNumberIdentifier Remote is null");
        return Str8ToStr16("");
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_TELENUMBER_IDENTIFIER), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimTeleNumberIdentifier failed, error code is %{public}d", st);
        return Str8ToStr16("");
    }
    std::u16string result = reply.ReadString16();
    return result;
}

int32_t CoreServiceProxy::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_VOICE_MAIL_TAG), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailIdentifier failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        voiceMailIdentifier = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetVoiceMailNumber WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetVoiceMailNumber Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_VOICE_MAIL_NUMBER), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailNumber failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        voiceMailNumber = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetVoiceMailCount WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetVoiceMailCount Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_VOICE_MAIL_COUNT), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetVoiceMailCount failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        voiceMailCount = reply.ReadInt32();
    }
    return result;
}

int32_t CoreServiceProxy::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetVoiceMailCount WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(voiceMailCount);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetVoiceMailCount Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_VOICE_MAIL_COUNT), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetVoiceMailCount failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetVoiceCallForwarding WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteBool(enable);
    data.WriteString(number);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetVoiceCallForwarding Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_VOICE_CALL_FORWARDING), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SetVoiceCallForwarding failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::QueryIccDiallingNumbers(
    int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers WriteInt32 type is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_GET), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("QueryIccDiallingNumbers failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t errorCode = reply.ReadInt32();
    if (errorCode != TELEPHONY_ERR_SUCCESS) {
        return errorCode;
    }
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGI("CoreServiceProxy::QueryIccDiallingNumbers size:%{public}d", size);
    if (size >= MAX_SIZE) {
        TELEPHONY_LOGE("CoreServiceProxy::QueryIccDiallingNumbers over max size");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    for (int i = 0; i < size; i++) {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(reply);
        if (diallingNumber != nullptr) {
            result.emplace_back(diallingNumber);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreServiceProxy::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy AddIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("AddIccDiallingNumbers WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("AddIccDiallingNumbers WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("AddIccDiallingNumbers WriteInt32 type is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (diallingNumber != nullptr) {
        diallingNumber->Marshalling(data);
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("AddIccDiallingNumbers Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_INSERT), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("AddIccDiallingNumbers failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy DelIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("DelIccDiallingNumbers WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("DelIccDiallingNumbers WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("DelIccDiallingNumbers WriteInt32 type is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (diallingNumber != nullptr) {
        diallingNumber->Marshalling(data);
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("DelIccDiallingNumbers Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_DELETE), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("DelIccDiallingNumbers failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    TELEPHONY_LOGI("CoreServiceProxy UpdateIccDiallingNumbers ::%{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(type)) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers WriteInt32 type is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (diallingNumber != nullptr) {
        diallingNumber->Marshalling(data);
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_UPDATE), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UpdateIccDiallingNumbers failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::SetVoiceMailInfo(
    const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    TELEPHONY_LOGI("slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (!IsValidStringLength(mailName) || !IsValidStringLength(mailNumber)) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(mailName)) {
        TELEPHONY_LOGE("WriteString16 mailName is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(mailNumber)) {
        TELEPHONY_LOGE("WriteString16 mailNumber is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SET_VOICE_MAIL), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetOpKey WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetOpKey Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_OPKEY), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetOpKey failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        opkey = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_OPKEY_EXT), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        opkeyExt = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetOpName(int32_t slotId, std::u16string &opname)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetOpName WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetOpName Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_OPNAME), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetOpName failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        opname = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetMaxSimCount()
{
    return SIM_SLOT_COUNT_REAL;
}

int32_t CoreServiceProxy::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (cmd.empty()) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString(cmd);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::STK_CMD_FROM_APP_ENVELOPE), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (cmd.empty()) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SendTerminalResponseCmd WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteString(cmd);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SendTerminalResponseCmd Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::STK_CMD_FROM_APP_TERMINAL_RESPONSE), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SendTerminalResponseCmd failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("SendTerminalResponseCmd end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SendCallSetupRequestResult WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(accept);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SendCallSetupRequestResult Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::STK_RESULT_FROM_APP_CALL_SETUP_REQUEST),
        data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SendCallSetupRequestResult failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("SendCallSetupRequestResult end: result=%{public}d", result);
    return result;
}

int32_t CoreServiceProxy::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (!IsValidSlotId(slotId)) {
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnlockSimLock WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(lockInfo.lockType));
    data.WriteString16(lockInfo.password);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UnlockSimLock Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::UNLOCK_SIMLOCK), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("UnlockSimLock failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        response.result = reply.ReadInt32();
        response.remain = reply.ReadInt32();
    }
    return result;
}

int32_t CoreServiceProxy::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slotId!");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    TELEPHONY_LOGD("slotId:%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(imsSrvType)) {
        TELEPHONY_LOGE("WriteInt32 imsSrvType is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_IMS_REG_STATUS), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("failed, error code is %{public}d", st);
        return st;
    }
    int32_t ret = reply.ReadInt32();
    info.imsRegState = static_cast<ImsRegState>(reply.ReadInt32());
    info.imsRegTech = static_cast<ImsRegTech>(reply.ReadInt32());
    return ret;
}

int32_t CoreServiceProxy::GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetCellInfoList WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("GetCellInfoList WriteInt32 imsSrvType is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetCellInfoList Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_CELL_INFO_LIST), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetCellInfoList failed, error code is %{public}d\n", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        ProcessCellInfo(reply, cellInfo);
    }
    TELEPHONY_LOGD("CoreServiceProxy::GetCellInfoList cell size:%{public}zu\n", cellInfo.size());
    return result;
}

void CoreServiceProxy::ProcessCellInfo(MessageParcel &reply, std::vector<sptr<CellInformation>> &cells)
{
    int32_t size = reply.ReadInt32();
    TELEPHONY_LOGD("CoreServiceProxy::ProcessCellInfo size:%{public}d\n", size);
    if (size >= MAX_SIZE) {
        TELEPHONY_LOGE("CoreServiceProxy::ProcessCellInfo over max size");
        return;
    }
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

int32_t CoreServiceProxy::SendUpdateCellLocationRequest(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    data.WriteInt32(slotId);
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_CELL_LOCATION), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    return reply.ReadInt32();
}

int32_t CoreServiceProxy::HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("HasOperatorPrivileges WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("HasOperatorPrivileges Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::HAS_OPERATOR_PRIVILEGES), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("HasOperatorPrivileges failed, error code is %{public}d", st);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    TELEPHONY_LOGI("HasOperatorPrivileges end: result=%{public}d", result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        hasOperatorPrivileges = reply.ReadBool();
    }
    return result;
}

int32_t CoreServiceProxy::SimAuthentication(
    int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SimAuthentication WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(authType));
    data.WriteString(authData);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SimAuthentication Remote is null");
        return ERROR;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::SIM_AUTHENTICATION), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("SimAuthentication failed, error code is %{public}d", st);
        return ERROR;
    }
    int32_t ret = reply.ReadInt32();
    response.sw1 = reply.ReadInt32();
    response.sw2 = reply.ReadInt32();
    response.response = reply.ReadString();
    TELEPHONY_LOGI("SimAuthentication end: result=%{public}d", ret);
    return ret;
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
    auto remote = Remote();
    data.WriteInt32(slotId);
    if (remote == nullptr) {
        TELEPHONY_LOGE("SimAuthentication Remote is null");
        return ERROR;
    }
    int32_t st = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::IS_NR_SUPPORTED), data,
        reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("IsNrSupported failed, error code is %{public}d", st);
        return false;
    }
    bool result = reply.ReadBool();
    return result;
}

int32_t CoreServiceProxy::SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetNrOptionMode WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("SetNrOptionMode WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!data.WriteInt32(mode)) {
        TELEPHONY_LOGE("SetNrOptionMode WriteInt32 mode is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetNrOptionMode Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::SET_NR_OPTION_MODE), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetNrOptionMode failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetNrOptionMode WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    data.WriteInt32(slotId);
    if (callback != nullptr) {
        data.WriteRemoteObject(callback->AsObject().GetRefPtr());
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetNrOptionMode Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_NR_OPTION_MODE), data,
        reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetNrOptionMode failed, error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::RegisterImsRegInfoCallback(
    int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is nullptr!");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = SerializeImsRegInfoData(slotId, imsSrvType, data);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("serialize data failed, result is %{public}d", ret);
        return ret;
    }
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        TELEPHONY_LOGE("write remote object failed!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<OHOS::IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("remote is nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::REG_IMS_CALLBACK), data,
        reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("error! errCode:%{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = SerializeImsRegInfoData(slotId, imsSrvType, data);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("serialize data failed, result is %{public}d", ret);
        return ret;
    }
    sptr<OHOS::IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("remote is nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::UN_REG_IMS_CALLBACK), data,
        reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("error! errCode:%{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::SerializeImsRegInfoData(int32_t slotId, ImsServiceType imsSrvType, MessageParcel &data)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("invalid slotId");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (!IsValidServiceType(imsSrvType)) {
        TELEPHONY_LOGE("invalid serviceType!");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("write interface token failed!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("write slotId failed!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(static_cast<int32_t>(imsSrvType))) {
        TELEPHONY_LOGE("write imsSrvType failed!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t CoreServiceProxy::GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    if (nrSsbInformation == nullptr) {
        TELEPHONY_LOGE("nrSsbInformation is null");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    int32_t error = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_NR_SSB_ID_INFO), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("Failed, error code is %{public}d\n", error);
        return error;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!nrSsbInformation->ReadFromParcel(reply)) {
            TELEPHONY_LOGE("ReadFromParcel is failed");
            return TELEPHONY_ERR_READ_DATA_FAIL;
        }
    }
    return result;
}

int32_t CoreServiceProxy::FactoryReset(int32_t slotId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    data.WriteInt32(slotId);
    MessageParcel reply;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::FACTORY_RESET), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("Error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return reply.ReadInt32();
}

bool CoreServiceProxy::IsAllowedInsertApn(std::string &value)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return true;
    }

    if (!data.WriteString(value)) {
        TELEPHONY_LOGE("WriteString is false");
        return true;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return true;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(CoreServiceInterfaceCode::IS_ALLOWED_INSERT_APN), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("Error code is %{public}d", error);
        return true;
    }
    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetTargetOpkey(int32_t slotId, std::u16string &opkey)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }

    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_TARGET_OPKEY), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("Error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    opkey = reply.ReadString16();
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetOpkeyVersion(std::string &versionInfo)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_OPKEY_VERSION), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("Error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    versionInfo = reply.ReadString();
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetOpnameVersion(std::string &versionInfo)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_OPNAME_VERSION), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("Error code is %{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    versionInfo = reply.ReadString();
    return reply.ReadInt32();
}

int32_t CoreServiceProxy::GetSimIO(int32_t slotId, int32_t command,
    int32_t fileId, const std::string &dataStr, const std::string &path, SimAuthenticationResponse &response)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSimIO WriteInterfaceToken is false");
        return ERROR;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(command));
    data.WriteInt32(static_cast<int32_t>(fileId));
    data.WriteString(dataStr);
    data.WriteString(path);
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSimIO Remote is null");
        return ERROR;
    }
    int32_t st = remote->SendRequest(uint32_t(CoreServiceInterfaceCode::GET_SIM_IO_DONE), data, reply, option);
    if (st != ERR_NONE) {
        TELEPHONY_LOGE("GetSimIO failed, error code is %{public}d", st);
        return ERROR;
    }
    int32_t ret = reply.ReadInt32();
    response.sw1 = reply.ReadInt32();
    response.sw2 = reply.ReadInt32();
    response.response = reply.ReadString();
    return ret;
}

#ifdef CORE_SERVICE_SUPPORT_ESIM
int32_t CoreServiceProxy::GetEid(int32_t slotId, std::u16string &eId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendRequestRet =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_EID), data, reply, option);
    if (sendRequestRet != ERR_NONE) {
        TELEPHONY_LOGE("GetEid failed, error code is %{public}d", sendRequestRet);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        eId = reply.ReadString16();
    }
    return result;
}

void CoreServiceProxy::ReadEuiccProfileFromReply(MessageParcel &reply, EuiccProfile &euiccProfile)
{
    euiccProfile.iccId_ = reply.ReadString16();
    euiccProfile.nickName_ = reply.ReadString16();
    euiccProfile.serviceProviderName_ = reply.ReadString16();
    euiccProfile.profileName_ = reply.ReadString16();
    euiccProfile.state_ = static_cast<ProfileState>(reply.ReadInt32());
    euiccProfile.profileClass_ = static_cast<ProfileClass>(reply.ReadInt32());
    euiccProfile.carrierId_.mcc_ = reply.ReadString16();
    euiccProfile.carrierId_.mnc_ = reply.ReadString16();
    euiccProfile.carrierId_.gid1_ = reply.ReadString16();
    euiccProfile.carrierId_.gid2_ = reply.ReadString16();
    euiccProfile.policyRules_ = static_cast<PolicyRules>(reply.ReadInt32());

    uint32_t accessRulesSize = reply.ReadUint32();
    if (accessRulesSize >= ESIM_MAX_SIZE) {
        TELEPHONY_LOGE("over max size");
        return;
    }
    euiccProfile.accessRules_.resize(accessRulesSize);
    for (uint32_t j = 0; j < accessRulesSize; ++j) {
        AccessRule &rule = euiccProfile.accessRules_[j];
        rule.certificateHashHexStr_ = reply.ReadString16();
        rule.packageName_ = reply.ReadString16();
        rule.accessType_ = reply.ReadInt32();
    }
}

int32_t CoreServiceProxy::GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResult &euiccProfileInfoList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendRequestRet = remote->SendRequest(
        static_cast<uint32_t>(CoreServiceInterfaceCode::GET_EUICC_PROFILE_INFO_LIST), data, reply, option);
    if (sendRequestRet != ERR_NONE) {
        TELEPHONY_LOGE("GetEuiccProfileInfoList failed, error code is %{public}d", sendRequestRet);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        uint32_t profileCount = reply.ReadUint32();
        if (profileCount >= ESIM_MAX_SIZE) {
            TELEPHONY_LOGE("over max size");
            return TELEPHONY_ERR_READ_DATA_FAIL;
        }
        euiccProfileInfoList.profiles_.resize(profileCount);
        for (uint32_t i = 0; i < profileCount; ++i) {
            EuiccProfile &euiccProfile = euiccProfileInfoList.profiles_[i];
            ReadEuiccProfileFromReply(reply, euiccProfile);
        }
        euiccProfileInfoList.isRemovable_ = reply.ReadBool();
        euiccProfileInfoList.result_ = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

int32_t CoreServiceProxy::GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendRequestRet = remote->SendRequest(
        static_cast<uint32_t>(CoreServiceInterfaceCode::GET_EUICC_INFO), data, reply, option);
    if (sendRequestRet != ERR_NONE) {
        TELEPHONY_LOGE("GetEuiccInfo failed, error code is %{public}d", sendRequestRet);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        eUiccInfo.osVersion_ = reply.ReadString16();
        eUiccInfo.response_ = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::DisableProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(iccId)) {
        TELEPHONY_LOGE("WriteString16 iccId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteBool(refresh)) {
        TELEPHONY_LOGE("WriteBool refresh is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t profileResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::DISABLE_PROFILE), data, reply, option);
    if (profileResult != ERR_NONE) {
        TELEPHONY_LOGE("DisableProfile senRequest failed, error code is %{public}d", profileResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

int32_t CoreServiceProxy::GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t addressResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_SMDSADDRESS), data, reply, option);
    if (addressResult != ERR_NONE) {
        TELEPHONY_LOGE("GetSmdsAddress sendRequest failed, error code is %{public}d", addressResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        smdsAddress = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::ParseRulesAuthTableReply(MessageParcel &reply, EuiccRulesAuthTable &eUiccRulesAuthTable)
{
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        uint32_t policyRulesSize = reply.ReadUint32();
        if (policyRulesSize > ESIM_MAX_SIZE) {
            return TELEPHONY_ERR_FAIL;
        }
        eUiccRulesAuthTable.policyRules_.resize(policyRulesSize);
        for (uint32_t i = 0; i < policyRulesSize; ++i) {
            eUiccRulesAuthTable.policyRules_[i] = reply.ReadInt32();
        }
        uint32_t carrierIdsSize = reply.ReadUint32();
        if (carrierIdsSize > ESIM_MAX_SIZE) {
            return TELEPHONY_ERR_FAIL;
        }
        eUiccRulesAuthTable.carrierIds_.resize(carrierIdsSize);
        for (uint32_t j = 0; j < carrierIdsSize; ++j) {
            CarrierIdentifier &ci = eUiccRulesAuthTable.carrierIds_[j];
            ci.mcc_ = reply.ReadString16();
            ci.mnc_ = reply.ReadString16();
            ci.spn_ = reply.ReadString16();
            ci.imsi_ = reply.ReadString16();
            ci.gid1_ = reply.ReadString16();
            ci.gid2_ = reply.ReadString16();
            ci.carrierId_ = reply.ReadInt32();
            ci.specificCarrierId_ = reply.ReadInt32();
        }
        uint32_t policyRuleFlagsSize = reply.ReadUint32();
        if (policyRuleFlagsSize > ESIM_MAX_SIZE) {
            return TELEPHONY_ERR_FAIL;
        }
        eUiccRulesAuthTable.policyRuleFlags_.resize(policyRuleFlagsSize);
        for (uint32_t k = 0; k < policyRuleFlagsSize; ++k) {
            eUiccRulesAuthTable.policyRuleFlags_[k] = reply.ReadInt32();
        }
        eUiccRulesAuthTable.position_ = reply.ReadInt32();
    }
    return result;
}

int32_t CoreServiceProxy::GetRulesAuthTable(
    int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t getRulesResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_RULES_AUTH_TABLE), data, reply, option);
    if (getRulesResult != ERR_NONE) {
        TELEPHONY_LOGE("DisableProfile sendRequest failed, error code is %{public}d", getRulesResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return ParseRulesAuthTableReply(reply, eUiccRulesAuthTable);
}

int32_t CoreServiceProxy::GetEuiccChallenge(
    int32_t slotId, int32_t portIndex, ResponseEsimResult &responseResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t euiccResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_EUICC_CHALLENGE), data, reply, option);
    if (euiccResult != ERR_NONE) {
        TELEPHONY_LOGE("GetEuiccChallenge sendRequest failed, error code is %{public}d", euiccResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        responseResult.resultCode_ = static_cast<ResultCode>(reply.ReadInt32());
        responseResult.response_ = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::REQUEST_DEFAULT_SMDP_ADDRESS), data,
        reply, option);
    if (sendResult != ERR_NONE) {
        TELEPHONY_LOGE("GetDefaultSmdpAddress failed, error code is %{public}d", sendResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        defaultSmdpAddress = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::CancelSession(
    int32_t slotId, const std::u16string &transactionId, CancelReason cancelReason, ResponseEsimResult &responseResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(transactionId)) {
        TELEPHONY_LOGE("WriteString16 transactionId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(static_cast<int32_t>(cancelReason))) {
        TELEPHONY_LOGE("WriteInt32 cancelReason is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendResult = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::CANCEL_SESSION),
        data, reply, option);
    if (sendResult != ERR_NONE) {
        TELEPHONY_LOGE("CancelSession failed, error code is %{public}d", sendResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        responseResult.resultCode_ = static_cast<ResultCode>(reply.ReadInt32());
        responseResult.response_ = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::GetProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(iccId)) {
        TELEPHONY_LOGE("WriteString16 iccId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t resultSend =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_PROFILE), data, reply, option);
    if (resultSend != ERR_NONE) {
        TELEPHONY_LOGE("GetProfile sendRequest failed, error code is %{public}d", resultSend);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        ReadEuiccProfileFromReply(reply, eUiccProfile);
    }
    return result;
}

int32_t CoreServiceProxy::ResetMemory(int32_t slotId, ResetOption resetOption, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(static_cast<int32_t>(resetOption))) {
        TELEPHONY_LOGE("WriteInt32 resetOption is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t requestResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::RESET_MEMORY), data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("ResetMemory failed, error code is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

int32_t CoreServiceProxy::SetDefaultSmdpAddress(
    int32_t slotId, const std::u16string &defaultSmdpAddress, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(defaultSmdpAddress)) {
        TELEPHONY_LOGE("WriteString16 defaultSmdpAddress is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t requestResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::SET_DEFAULT_SMDP_ADDRESS),
        data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("SetDefaultSmdpAddress failed, error code is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

bool CoreServiceProxy::IsSupported(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return false;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return false;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return false;
    }
    int32_t requestResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::IS_ESIM_SUPPORTED), data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("IsSupported sendRequest failed, error code is %{public}d", requestResult);
        return false;
    }
    return reply.ReadBool();
}

bool CoreServiceProxy::WriteEsimApduData(MessageParcel &data, const EsimApduData &apduData)
{
    if (!data.WriteBool(apduData.closeChannelFlag_)) {
        TELEPHONY_LOGE("WriteBool closeChannelFlag is failed");
        return false;
    }
    if (!data.WriteBool(apduData.unusedDefaultReqHeadFlag_)) {
        TELEPHONY_LOGE("WriteBool unusedDefaultReqHeadFlag is failed");
        return false;
    }
    if (!data.WriteString16(apduData.data_)) {
        TELEPHONY_LOGE("WriteString16 data is failed");
        return false;
    }
    if (!data.WriteInt32(apduData.instructionType_)) {
        TELEPHONY_LOGE("WriteInt32 instructionType_ is failed");
        return false;
    }
    if (!data.WriteInt32(apduData.instruction_)) {
        TELEPHONY_LOGE("WriteInt32 instruction_ is failed");
        return false;
    }
    if (!data.WriteInt32(apduData.p1_)) {
        TELEPHONY_LOGE("WriteInt32 p1 is failed");
        return false;
    }
    if (!data.WriteInt32(apduData.p2_)) {
        TELEPHONY_LOGE("WriteInt32 p2 is failed");
        return false;
    }
    if (!data.WriteInt32(apduData.p3_)) {
        TELEPHONY_LOGE("WriteInt32 p3 is failed");
        return false;
    }
    return true;
}

int32_t CoreServiceProxy::SendApduData(
    int32_t slotId, const std::u16string &aid, const EsimApduData &apduData, ResponseEsimResult &responseResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(aid)) {
        TELEPHONY_LOGE("WriteString16 aid is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!WriteEsimApduData(data, apduData)) {
        TELEPHONY_LOGE("WriteEsimApduData is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t requestResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::SEND_APDU_DATA), data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("SendApduData sendRequest failed, error code is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        responseResult.resultCode_ = static_cast<ResultCode>(reply.ReadInt32());
        responseResult.response_ = reply.ReadString16();
        responseResult.sw1_ = reply.ReadInt32();
        responseResult.sw2_ = reply.ReadInt32();
    }
    return result;
}

int32_t CoreServiceProxy::PrepareDownload(int32_t slotId, const DownLoadConfigInfo &downLoadConfigInfo,
    ResponseEsimResult &responseResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    bool ret = data.WriteInt32(slotId);
    ret = (ret && data.WriteInt32(downLoadConfigInfo.portIndex_));
    ret = (ret && data.WriteString16(downLoadConfigInfo.hashCc_));
    ret = (ret && data.WriteString16(downLoadConfigInfo.smdpSigned2_));
    ret = (ret && data.WriteString16(downLoadConfigInfo.smdpSignature2_));
    ret = (ret && data.WriteString16(downLoadConfigInfo.smdpCertificate_));
    if (!ret) {
        TELEPHONY_LOGE("Write data false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::PREPARE_DOWNLOAD),
        data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("PrepareDownload sendRequest failed, error code is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        responseResult.resultCode_ = static_cast<ResultCode>(reply.ReadInt32());
        responseResult.response_ = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::LoadBoundProfilePackage(int32_t slotId, int32_t portIndex,
    const std::u16string &boundProfilePackage, ResponseEsimBppResult &responseResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }

    bool ret = data.WriteInt32(slotId);
    ret = (ret && data.WriteInt32(portIndex));
    ret = (ret && data.WriteString16(boundProfilePackage));
    if (!ret) {
        TELEPHONY_LOGE("Write data is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t requestResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::LOAD_BOUND_PROFILE_PACKAGE), data,
        reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("LoadBoundProfilePackage sendRequest failed, errcode is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        responseResult.resultCode_ = reply.ReadInt32();
        responseResult.response_ = reply.ReadString16();
        responseResult.seqNumber_ = reply.ReadInt32();
        responseResult.profileManagementOperation_ = reply.ReadInt32();
        responseResult.notificationAddress_ = reply.ReadString16();
        responseResult.iccId_ = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::ListNotifications(
    int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }

    bool ret = data.WriteInt32(slotId);
    ret = (ret && data.WriteInt32(portIndex));
    ret = (ret && data.WriteInt32(static_cast<int32_t>(events)));
    if (!ret) {
        TELEPHONY_LOGE("Write data is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::LIST_NOTIFICATIONS),
        data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("ListNotifications sendRequest failed, error code is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        uint32_t euiccNotificationCount = reply.ReadUint32();
        if (euiccNotificationCount >= ESIM_MAX_SIZE) {
            TELEPHONY_LOGE("CoreServiceProxy::RetrieveNotificationList over max size");
            return TELEPHONY_ERR_READ_DATA_FAIL;
        }
        notificationList.euiccNotification_.resize(euiccNotificationCount);
        for (uint32_t i = 0; i < euiccNotificationCount; ++i) {
            EuiccNotification &nf = notificationList.euiccNotification_[i];
            nf.seq_ = reply.ReadInt32();
            nf.targetAddr_ = reply.ReadString16();
            nf.event_ = reply.ReadInt32();
            nf.data_ = reply.ReadString16();
        }
    }
    return result;
}

int32_t CoreServiceProxy::RetrieveNotificationList(
    int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RetrieveNotificationList WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("RetrieveNotificationList WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("RetrieveNotificationList WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(static_cast<int32_t>(events))) {
        TELEPHONY_LOGE("RetrieveNotificationList WriteInt32 events is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("RetrieveNotificationList Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    int32_t requestResult =
        remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::RETRIEVE_NOTIFICATION_LIST), data,
        reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("RetrieveNotificationList sendRequest failed, errcode is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        uint32_t euiccNotificationCount = reply.ReadUint32();
        if (euiccNotificationCount >= ESIM_MAX_SIZE) {
            TELEPHONY_LOGE("CoreServiceProxy::RetrieveNotificationList over max size");
            return TELEPHONY_ERR_READ_DATA_FAIL;
        }
        notificationList.euiccNotification_.resize(euiccNotificationCount);
        for (uint32_t i = 0; i < euiccNotificationCount; ++i) {
            EuiccNotification &nf = notificationList.euiccNotification_[i];
            nf.seq_ = reply.ReadInt32();
            nf.targetAddr_ = reply.ReadString16();
            nf.event_ = reply.ReadInt32();
            nf.data_ = reply.ReadString16();
        }
    }
    return result;
}

int32_t CoreServiceProxy::RetrieveNotification(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RetrieveNotification WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("RetrieveNotification WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("RetrieveNotification WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(seqNumber)) {
        TELEPHONY_LOGE("RetrieveNotification WriteInt32 seqNumber is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("RetrieveNotification Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::RETRIEVE_NOTIFICATION),
        data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("RetrieveNotification sendRequest failed, errcode is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t res = reply.ReadInt32();
    if (res == TELEPHONY_ERR_SUCCESS) {
        notification.seq_ = reply.ReadInt32();
        notification.targetAddr_ = reply.ReadString16();
        notification.event_ = reply.ReadInt32();
        notification.data_ = reply.ReadString16();
    }
    return res;
}

int32_t CoreServiceProxy::RemoveNotificationFromList(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RemoveNotificationFromList WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("RemoveNotificationFromList WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("RemoveNotificationFromList WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(seqNumber)) {
        TELEPHONY_LOGE("RemoveNotificationFromList WriteInt32 seqNumber is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("RemoveNotificationFromList Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::REMOVE_NOTIFICATION),
        data, reply, option);
    if (requestResult != ERR_NONE) {
        TELEPHONY_LOGE("RemoveNotificationFromList sendRequest failed, errcode is %{public}d", requestResult);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

int32_t CoreServiceProxy::DeleteProfile(int32_t slotId, const std::u16string &iccId, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId) || data.WriteString16(iccId)) {
        TELEPHONY_LOGE("WriteInt32 or WriteString16 is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendRequestRet = remote->SendRequest(static_cast<uint32_t>(
        CoreServiceInterfaceCode::DELETE_PROFILE), data, reply, option);
    if (sendRequestRet != ERR_NONE) {
        TELEPHONY_LOGE("DeleteProfile failed, error code is %{public}d", sendRequestRet);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

int32_t CoreServiceProxy::SwitchToProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool forceDisableProfile, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId) || !data.WriteInt32(portIndex) ||
        !data.WriteString16(iccId) || !data.WriteBool(forceDisableProfile)) {
        TELEPHONY_LOGE("Write is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendRequestRet = remote->SendRequest(static_cast<uint32_t>(
        CoreServiceInterfaceCode::SWITCH_TO_PROFILE), data, reply, option);
    if (sendRequestRet != ERR_NONE) {
        TELEPHONY_LOGE("SwitchToProfile failed, error code is %{public}d", sendRequestRet);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

int32_t CoreServiceProxy::SetProfileNickname(
    int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, ResultCode &enumResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId) || data.WriteString16(iccId) || !data.WriteString16(nickname)) {
        TELEPHONY_LOGE("Write is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t sendRequestRet = remote->SendRequest(
        static_cast<uint32_t>(CoreServiceInterfaceCode::UPDATE_PROFILE_NICKNAME), data, reply, option);
    if (sendRequestRet != ERR_NONE) {
        TELEPHONY_LOGE("SetProfileNickname failed, error code is %{public}d", sendRequestRet);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        enumResult = static_cast<ResultCode>(reply.ReadInt32());
    }
    return result;
}

void CoreServiceProxy::ReadEuiccInfo2FromReply(MessageParcel &reply, EuiccInfo2 &euiccInfo2)
{
    euiccInfo2.raw_ = reply.ReadString();
    euiccInfo2.rawLen_ = reply.ReadUint32();
    euiccInfo2.svn_ = reply.ReadString();
    euiccInfo2.profileVersion_ = reply.ReadString();
    euiccInfo2.firmwareVer_ = reply.ReadString();
    euiccInfo2.extCardResource_ = reply.ReadString();
    euiccInfo2.uiccCapability_ = reply.ReadString();
    euiccInfo2.ts102241Version_ = reply.ReadString();
    euiccInfo2.globalPlatformVersion_ = reply.ReadString();
    euiccInfo2.rspCapability_ = reply.ReadString();
    euiccInfo2.euiccCiPKIdListForVerification_ = reply.ReadString();
    euiccInfo2.euiccCiPKIdListForSigning_ = reply.ReadString();
    euiccInfo2.euiccCategory_ = reply.ReadInt32();
    euiccInfo2.forbiddenProfilePolicyRules_ = reply.ReadString();
    euiccInfo2.ppVersion_ = reply.ReadString();
    euiccInfo2.sasAccreditationNumber_ = reply.ReadString();
    euiccInfo2.response_ = reply.ReadString();
    euiccInfo2.resultCode_ = static_cast<ResultCode>(reply.ReadInt32());
}

int32_t CoreServiceProxy::GetEuiccInfo2(int32_t slotId, int32_t portIndex, EuiccInfo2 &euiccInfo2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(portIndex)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t resultSend = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::GET_EUICC_INFO2),
        data, reply, option);
    if (resultSend != ERR_NONE) {
        TELEPHONY_LOGE("GetEuiccInfo2 sendRequest failed, error code is %{public}d", resultSend);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        ReadEuiccInfo2FromReply(reply, euiccInfo2);
    }
    return result;
}

int32_t CoreServiceProxy::RealAuthenticateServer(
    MessageParcel &data, MessageParcel &reply, MessageOption &option, ResponseEsimResult &responseResult)
{
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t resultSend = remote->SendRequest(static_cast<uint32_t>(CoreServiceInterfaceCode::AUTHENTICATE_SERVER),
        data, reply, option);
    if (resultSend != ERR_NONE) {
        TELEPHONY_LOGE("GetEuiccChallenge sendRequest failed, error code is %{public}d", resultSend);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t result = reply.ReadInt32();
    if (result == TELEPHONY_ERR_SUCCESS) {
        responseResult.resultCode_ = static_cast<ResultCode>(reply.ReadInt32());
        responseResult.response_ = reply.ReadString16();
    }
    return result;
}

int32_t CoreServiceProxy::AuthenticateServer(
    int32_t slotId, const AuthenticateConfigInfo &authenticateConfigInfo, ResponseEsimResult &responseResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        TELEPHONY_LOGE("WriteInt32 slotId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(authenticateConfigInfo.portIndex_)) {
        TELEPHONY_LOGE("WriteInt32 portIndex is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(authenticateConfigInfo.matchingId_)) {
        TELEPHONY_LOGE("WriteString16 matchingId is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(authenticateConfigInfo.serverSigned1_)) {
        TELEPHONY_LOGE("WriteString16 serverSigned1 is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(authenticateConfigInfo.serverSignature1_)) {
        TELEPHONY_LOGE("WriteString16 serverSignature1 is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(authenticateConfigInfo.euiccCiPkIdToBeUsed_)) {
        TELEPHONY_LOGE("WriteString16 euiccCiPkIdToBeUsed is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteString16(authenticateConfigInfo.serverCertificate_)) {
        TELEPHONY_LOGE("WriteString16 serverCertificate is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return RealAuthenticateServer(data, reply, option, responseResult);
}
#endif
} // namespace Telephony
} // namespace OHOS

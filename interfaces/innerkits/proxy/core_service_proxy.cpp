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
#include <securec.h>
#include "hilog/log.h"
#include "string_ex.h"

using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = {LOG_CORE, 1, "CoreServiceProxy"};

namespace OHOS {
int32_t CoreServiceProxy::GetPsRadioTech(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy GetPsRadioTech");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_PS_RADIO_TECH, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetPsRadioTech failed, error code is %{public}d ", st);
        return -1;
    }

    int32_t result = reply.ReadInt32();

    HiLog::Error(LABEL, "GetPsRadioTech call end: result=%{public}d \n", result);

    return result;
}

int32_t CoreServiceProxy::GetCsRadioTech(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy GetCsRadioTech");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_CS_RADIO_TECH, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetCsRadioTech failed, error code is %{public}d \n", st);
        return -1;
    }

    int32_t result = reply.ReadInt32();

    HiLog::Error(LABEL, "GetCsRadioTech call end: result=%{public}d \n", result);

    return result;
}

std::u16string CoreServiceProxy::GetOperatorNumeric(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy GetOperatorNumeric");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_OPERATOR_NUMERIC, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetCsRadioTech failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "CoreServiceProxy GetOperatorNumeric %{public}s\n", str.c_str());

    return result;
}

std::u16string CoreServiceProxy::GetOperatorName(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetOperatorName");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(slotId);
    MessageOption option;

    int32_t st = Remote()->SendRequest(GET_OPERATOR_NAME, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetOperatorName failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "GetOperatorName call end: result=%s \n", str.c_str());

    return result;
}

const sptr<NetworkState> CoreServiceProxy::GetNetworkStatus(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetNetworkStatus");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_NETWORK_STATE, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetNetworkStatus failed, error code is %d \n", st);
        return nullptr;
    }

    sptr<NetworkState> result = NetworkState::UnMarshalling(reply).release();
    if (result == nullptr) {
        HiLog::Error(LABEL, "GetNetworkStatus is null\n");
        return nullptr;
    }
    return result;
}

std::vector<sptr<SignalInformation>> CoreServiceProxy::GetSignalInfoList(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetSignalInfoList");
    std::vector<sptr<SignalInformation>> result;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_SIGNAL_INFO_LIST, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetSignalInfoList failed, error code is %d\n", st);
        return result;
    }
    int32_t size = reply.ReadInt32();

    SignalInformation::NetworkType type;
    for (int i = 0; i < size; ++i) {
        type = static_cast<SignalInformation::NetworkType>(reply.ReadInt32());
        switch (type) {
            case SignalInformation::NetworkType::GSM: {
                std::unique_ptr<GsmSignalInformation> signal = std::make_unique<GsmSignalInformation>();
                signal->ReadFromParcel(reply);
                result.emplace_back(signal.release());
            } break;
            case SignalInformation::NetworkType::CDMA: {
                std::unique_ptr<CdmaSignalInformation> signal = std::make_unique<CdmaSignalInformation>();
                signal->ReadFromParcel(reply);
                result.emplace_back(signal.release());
            } break;
            default:
                break;
        }
    }
    HiLog::Info(LABEL, "CoreServiceProxy::GetSignalInfoList size:%{public}d\n", size);
    return result;
}

void CoreServiceProxy::SetHRilRadioState(int32_t slotId, bool isOn)
{
    HiLog::Error(LABEL, "CoreServiceProxy SetHRilRadioState");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    data.WriteBool(isOn);
    int32_t st = Remote()->SendRequest(SET_RADIO_STATE, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "SetHRilRadioState failed, error code is %{public}d \n", st);
        return;
    }

    return;
}

int32_t CoreServiceProxy::GetRadioState(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy GetRadioState");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_RADIO_STATE, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetRadioState failed, error code is %{public}d \n", st);
        return -1;
    }

    int32_t result = reply.ReadInt32();
    HiLog::Error(LABEL, "GetRadioState call end: result=%d \n", result);
    return result;
}

bool CoreServiceProxy::HasSimCard(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy HasSimCard ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(HAS_SIM_CARD, data, reply, option);
    if (st != ERR_NONE) {
        printf("GetSimState failed, error code is %d \n", st);
        return st;
    }

    return reply.ReadBool();
}

int32_t CoreServiceProxy::GetSimState(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy GetSimState ::%{public}d", slotId);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_SIM_STATE, data, reply, option);
    if (st != ERR_NONE) {
        printf("GetSimState failed, error code is %d \n", st);
        return st;
    }

    int32_t result = reply.ReadInt32();
    printf("GetSimState call end: result=%d \n", result);
    return result;
}

std::u16string CoreServiceProxy::GetIsoCountryCode(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetIsoCountryCode");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_ISO_COUNTRY_CODE, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetIsoCountryCode failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "GetIsoCountryCode call end: result=%s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetSimOperator(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetSimOperator");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_SIM_OPERATOR_NUMERIC, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetSimOperator failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "GetSimOperator call end: result=%s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetSpn(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetSpn");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_SPN, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetSpn failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "GetSpn call end: result=%s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetIccId(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetIccId");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_ICCID, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetIccId failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "GetIccId call end: result=%s \n", str.c_str());
    return result;
}

std::u16string CoreServiceProxy::GetIMSI(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy::GetIMSI");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(GET_IMSI, data, reply, option);
    if (st != ERR_NONE) {
        HiLog::Error(LABEL, "GetIMSI failed, error code is %{public}d \n", st);
        return Str8ToStr16("");
    }

    std::u16string result = reply.ReadString16();
    std::string str = Str16ToStr8(result);
    HiLog::Error(LABEL, "GetIMSI call end: result=%s \n", str.c_str());
    return result;
}

bool CoreServiceProxy::IsSimActive(int32_t slotId)
{
    HiLog::Error(LABEL, "CoreServiceProxy IsSimActive ::%{public}d", slotId);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(slotId);
    int32_t st = Remote()->SendRequest(IS_SIM_ACTIVE, data, reply, option);
    if (st != ERR_NONE) {
        printf("IsSimActive failed, error code is %d \n", st);
        return st;
    }

    return reply.ReadBool();
}
} // namespace OHOS

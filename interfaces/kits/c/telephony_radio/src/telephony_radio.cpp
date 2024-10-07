/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "telephony_radio.h"
#include "core_service_client.h"
#include "network_search_types.h"
#include "network_state.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"
#include "refbase.h"
#include "securec.h"
#include <string>

using namespace OHOS::Telephony;

static Telephony_RadioTechnology Conv2TelRadioTechnology(OHOS::Telephony::RadioTech radioTechType)
{
    switch (radioTechType) {
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_GSM:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_GSM;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_LTE:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_LTE;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_WCDMA:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_WCDMA;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_1XRTT:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_1XRTT;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_HSPA:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_HSPA;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_HSPAP:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_HSPAP;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_TD_SCDMA;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_EVDO:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_EVDO;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_EHRPD:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_EHRPD;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_LTE_CA:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_LTE_CA;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_IWLAN:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_IWLAN;
        case OHOS::Telephony::RadioTech::RADIO_TECHNOLOGY_NR:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_NR;
        default:
            return Telephony_RadioTechnology::TEL_RADIO_TECHNOLOGY_UNKNOWN;
    }
}

static Telephony_RegState Conv2TelRegState(OHOS::Telephony::RegServiceState regStateType)
{
    switch (regStateType) {
        case OHOS::Telephony::RegServiceState::REG_STATE_IN_SERVICE: {
            return Telephony_RegState::TEL_REG_STATE_IN_SERVICE;
        }
        case OHOS::Telephony::RegServiceState::REG_STATE_EMERGENCY_ONLY: {
            return Telephony_RegState::TEL_REG_STATE_EMERGENCY_CALL_ONLY;
        }
        case OHOS::Telephony::RegServiceState::REG_STATE_POWER_OFF: {
            return Telephony_RegState::TEL_REG_STATE_POWER_OFF;
        }
        default:
            return Telephony_RegState::TEL_REG_STATE_NO_SERVICE;
    }
}

static Telephony_RadioResult TelephonyErrorCodeTrans(int32_t err)
{
    switch (err) {
        case OHOS::Telephony::TELEPHONY_ERR_SUCCESS:
            return Telephony_RadioResult::TEL_RADIO_SUCCESS;
        case OHOS::Telephony::TELEPHONY_ERR_PERMISSION_ERR:
            return Telephony_RadioResult::TEL_RADIO_PERMISSION_DENIED;
        case OHOS::Telephony::TELEPHONY_ERR_SLOTID_INVALID:
            return Telephony_RadioResult::TEL_RADIO_ERR_INVALID_PARAM;
        case OHOS::Telephony::TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL:
        case OHOS::Telephony::TELEPHONY_ERR_WRITE_DATA_FAIL:
            return Telephony_RadioResult::TEL_RADIO_ERR_MARSHALLING_FAILED;
        case OHOS::Telephony::TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL:
            return Telephony_RadioResult::TEL_RADIO_ERR_SERVICE_CONNECTION_FAILED;
        case OHOS::Telephony::TELEPHONY_ERR_LOCAL_PTR_NULL:
            return Telephony_RadioResult::TEL_RADIO_ERR_OPERATION_FAILED;
        default:
            return Telephony_RadioResult::TEL_RADIO_ERR_OPERATION_FAILED;
    }
}

static bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT + 1));
}

Telephony_RadioResult Conv2TelNetworkState(const OHOS::sptr<NetworkState> &networkState, Telephony_NetworkState *state)
{
    std::string name = networkState->GetLongOperatorName();
    if (strcpy_s(state->longOperatorName_, TELEPHONY_MAX_OPERATOR_LEN, name.c_str()) != 0) {
        TELEPHONY_LOGE("state->longOperatorName_ string copy failed");
        return Telephony_RadioResult::TEL_RADIO_ERR_OPERATION_FAILED;
    }
    name = networkState->GetShortOperatorName();
    if (strcpy_s(state->shortOperatorName_, TELEPHONY_MAX_OPERATOR_LEN, name.c_str()) != 0) {
        TELEPHONY_LOGE("state->shortOperatorName_ string copy failed");
        return Telephony_RadioResult::TEL_RADIO_ERR_OPERATION_FAILED;
    }
    name = networkState->GetPlmnNumeric();
    if (strcpy_s(state->plmnNumeric_, TELEPHONY_MAX_PLMN_NUMERIC_LEN, name.c_str()) != 0) {
        TELEPHONY_LOGE("state->plmnNumeric_ string copy failed");
        return Telephony_RadioResult::TEL_RADIO_ERR_OPERATION_FAILED;
    }
    state->isRoaming_ = networkState->IsRoaming();
    state->regState_ = Conv2TelRegState(networkState->GetRegStatus());
    state->cfgTech_ = Conv2TelRadioTechnology(networkState->GetCfgTech());
    state->nsaState_ = Telephony_NsaState::TEL_NSA_STATE_NOT_SUPPORTED;
    state->isCaActive_ = false;
    state->isEmergency_ = networkState->IsEmergency();

    return Telephony_RadioResult::TEL_RADIO_SUCCESS;
}

Telephony_RadioResult OH_Telephony_GetNetworkStateForSlot(int32_t slotId, Telephony_NetworkState *state)
{
    if (state == nullptr) {
        TELEPHONY_LOGE("OH_Telephony_GetNetworkStateForSlot received invalid parameters");
        return Telephony_RadioResult::TEL_RADIO_ERR_INVALID_PARAM;
    }

    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("GetNetworkState slotId is invalid");
        return Telephony_RadioResult::TEL_RADIO_ERR_INVALID_PARAM;
    }

    OHOS::sptr<NetworkState> networkState = nullptr;
    int32_t result = OHOS::Telephony::CoreServiceClient::GetInstance().GetNetworkState(slotId, networkState);
    if (result != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetNetworkState errorCode = %{public}d", result);
        return TelephonyErrorCodeTrans(result);
    }
    if (networkState == nullptr) {
        TELEPHONY_LOGE("GetNetworkState networkState is nullptr");
        return Telephony_RadioResult::TEL_RADIO_ERR_OPERATION_FAILED;
    }

    return Conv2TelNetworkState(networkState, state);
}

Telephony_RadioResult OH_Telephony_GetNetworkState(Telephony_NetworkState *state)
{
    int32_t slotId = 0;
    int32_t result = OHOS::Telephony::CoreServiceClient::GetInstance().GetPrimarySlotId(slotId);
    if (result != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetPrimarySlotId errorCode = %{public}d", result);
        return TelephonyErrorCodeTrans(result);
    }
    TELEPHONY_LOGD("GetDefaultSlotId = %{public}d", slotId);

    return OH_Telephony_GetNetworkStateForSlot(slotId, state);
}

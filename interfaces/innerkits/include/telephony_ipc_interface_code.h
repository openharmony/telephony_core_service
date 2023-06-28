/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef I_CORE_SERVICE_INTERFACE_CODE_H
#define I_CORE_SERVICE_INTERFACE_CODE_H

namespace OHOS {
namespace Telephony {
class ITelephony : public IRemoteBroker {
    enum class CoreServiceInterfaceCode {
        GET_PS_RADIO_TECH = 0,
        GET_CS_RADIO_TECH,
        GET_OPERATOR_NUMERIC,
        GET_OPERATOR_NAME,
        GET_SIGNAL_INFO_LIST,
        GET_NETWORK_STATE,
        GET_CELL_INFO_LIST,
        SET_RADIO_STATE,
        GET_RADIO_STATE,
        GET_IMEI,
        GET_MEID,
        GET_UNIQUE_DEVICE_ID,
        HAS_SIM_CARD,
        GET_SIM_STATE,
        GET_ISO_COUNTRY_CODE,
        GET_ISO_COUNTRY_CODE_FOR_NETWORK,
        SET_PS_ATTACH_STATUS,
        GET_SPN,
        GET_ICCID,
        GET_IMSI,
        IS_SIM_ACTIVE,
        UNLOCK_PIN,
        UNLOCK_PUK,
        ALTER_PIN,
        CHECK_LOCK,
        SWITCH_LOCK,
        UNLOCK_PIN2,
        UNLOCK_PUK2,
        ALTER_PIN2,
        GET_SIM_OPERATOR_NUMERIC,
        GET_NETWORK_SEARCH_RESULT,
        GET_NETWORK_SELECTION_MODE,
        GET_SIM_LANGUAGE,
        GET_SIM_GID1,
        GET_SIM_GID2,
        SET_NETWORK_SELECTION_MODE,
        GET_CELL_LOCATION,
        GET_SIM_SUB_INFO,
        SET_DEFAULT_VOICE_SLOTID,
        GET_DEFAULT_VOICE_SLOTID,
        GET_DEFAULT_VOICE_SIMID,
        SET_PRIMARY_SLOTID,
        GET_PRIMARY_SLOTID,
        SET_DEFAULT_DATA_SLOTID,
        GET_DEFAULT_DATA_SLOTID,
        SET_SHOW_NUMBER,
        GET_SHOW_NUMBER,
        SET_SHOW_NAME,
        GET_SHOW_NAME,
        GET_ACTIVE_ACCOUNT_INFO_LIST,
        GET_OPERATOR_CONFIG,
        REFRESH_SIM_STATE,
        SET_SIM_ACTIVE,
        GET_PREFERRED_NETWORK_MODE,
        SET_PREFERRED_NETWORK_MODE,
        GET_NETWORK_CAPABILITY,
        SET_NETWORK_CAPABILITY,
        GET_SIM_PHONE_NUMBER,
        GET_SIM_TELENUMBER_IDENTIFIER,
        GET_VOICE_MAIL_TAG,
        GET_VOICE_MAIL_NUMBER,
        ICC_DIALLING_NUMBERS_GET,
        ICC_DIALLING_NUMBERS_DELETE,
        ICC_DIALLING_NUMBERS_INSERT,
        ICC_DIALLING_NUMBERS_UPDATE,
        SET_VOICE_MAIL,
        GET_MAX_SIM_COUNT,
        GET_OPKEY,
        GET_OPKEY_EXT,
        GET_OPNAME,
        GET_IMS_REG_STATUS,
        STK_CMD_FROM_APP_ENVELOPE,
        STK_CMD_FROM_APP_TERMINAL_RESPONSE,
        STK_RESULT_FROM_APP_CALL_SETUP_REQUEST,
        GET_CARD_TYPE,
        UNLOCK_SIMLOCK,
        HAS_OPERATOR_PRIVILEGES,
        SIM_AUTHENTICATION,
        IS_NR_SUPPORTED,
        SET_NR_OPTION_MODE,
        GET_NR_OPTION_MODE,
        REG_IMS_CALLBACK,
        UN_REG_IMS_CALLBACK,
        GET_SIM_EONS,
        GET_SIM_SLOTID,
        GET_SIM_SIMID,
        GET_VOICE_MAIL_COUNT,
        SET_VOICE_MAIL_COUNT,
        SET_VOICE_CALL_FORWARDING,
        GET_BASEBAND_VERSION,
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // I_CORE_SERVICE_INTERFACE_CODE_H
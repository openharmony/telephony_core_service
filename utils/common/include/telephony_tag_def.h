/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_TAG_DEF_H
#define TELEPHONY_TAG_DEF_H

namespace OHOS {
namespace Telephony {
// Command type tags
const int32_t TAG_ESIM_PROFILE_INSTALLATION_RESULT = 0xBF37;
const int32_t TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA = 0xBF27;
const int32_t TAG_ESIM_NOTIFICATION_METADATA = 0xBF2F;
const int32_t TAG_ESIM_SEQ = 0x80;
const int32_t TAG_ESIM_TARGET_ADDR = 0x0C;
const int32_t TAG_ESIM_EVENT = 0x81;
const int32_t TAG_ESIM_CANCEL_SESSION = 0xBF41;
const int32_t TAG_ESIM_PROFILE_INFO = 0xE3;
const int32_t TAG_ESIM_TAG_LIST = 0x5C;
const int32_t TAG_ESIM_EID = 0x5A;
const int32_t TAG_ESIM_NICKNAME = 0x90;
const int32_t TAG_ESIM_ICCID = 0x5A;
const int32_t TAG_ESIM_PROFILE_STATE = 0x9F70;
const int32_t TAG_ESIM_OBTAIN_OPERATOR_NAME = 0x91;
const int32_t TAG_ESIM_PROFILE_CLASS = 0x95;
const int32_t TAG_ESIM_PROFILE_POLICY_RULE = 0x99;
const int32_t TAG_ESIM_PROFILE_NAME = 0x92;
const int32_t TAG_ESIM_OPERATOR_ID = 0xB7;
const int32_t TAG_ESIM_CARRIER_PRIVILEGE_RULES = 0xBF76;
const int32_t TAG_ESIM_PORT = 0x9F24;

// Constructed types tags
const int32_t TAG_ESIM_CTX_COMP_0 = 0xA0;
const int32_t TAG_ESIM_CTX_COMP_1 = 0xA1;
const int32_t TAG_ESIM_CTX_COMP_2 = 0xA2;
const int32_t TAG_ESIM_CTX_COMP_3 = 0xA3;
const int32_t TAG_ESIM_CTX_COMP_4 = 0xA4;
const int32_t TAG_ESIM_CTX_COMP_5 = 0xA5;
const int32_t TAG_ESIM_CTX_COMP_6 = 0xA6;
const int32_t TAG_ESIM_CTX_COMP_7 = 0xA7;
const int32_t TAG_ESIM_CTX_COMP_8 = 0xA8;
const int32_t TAG_ESIM_CTX_COMP_9 = 0xA9;
const int32_t TAG_ESIM_CTX_COMP_A = 0xAA;

// Base type tags
const int32_t TAG_ESIM_CTX_0 = 0x80;
const int32_t TAG_ESIM_CTX_1 = 0x81;
const int32_t TAG_ESIM_CTX_2 = 0x82;
const int32_t TAG_ESIM_CTX_3 = 0x83;
const int32_t TAG_ESIM_CTX_4 = 0x84;
const int32_t TAG_ESIM_CTX_5 = 0x85;
const int32_t TAG_ESIM_CTX_6 = 0x86;
const int32_t TAG_ESIM_CTX_7 = 0x87;
const int32_t TAG_ESIM_CTX_8 = 0x88;
const int32_t TAG_ESIM_CTX_9 = 0x89;
const int32_t TAG_ESIM_CTX_A = 0x8A;
const int32_t TAG_ESIM_CTX_B = 0x8B;

// Common tags
const int32_t TAG_ESIM_UNI_2 = 0x02;
const int32_t TAG_ESIM_UNI_4 = 0x04;
const int32_t TAG_ESIM_SEQUENCE = 0x30;

// Standard RefArDo data tags
const int32_t TAG_ESIM_REF_AR_DO = 0xE2;
const int32_t TAG_ESIM_REF_DO = 0xE1;
const int32_t TAG_ESIM_DEVICE_APP_ID_REF_DO = 0xC1;
const int32_t TAG_ESIM_PKG_REF_DO = 0xCA;
const int32_t TAG_ESIM_AR_DO = 0xE3;
const int32_t TAG_ESIM_PERM_AR_DO = 0xDB;
const int32_t TAG_ESIM_OCTET_STRING_TYPE = 0x04;
const int32_t TAG_ESIM_INTEGER_TYPE = 0x02;

// Esim related protocol tags
const int32_t TAG_ESIM_GET_PROFILES = 0xBF2D;
const int32_t TAG_ESIM_DISABLE_PROFILE = 0xBF32;
const int32_t TAG_ESIM_ENABLE_PROFILE = 0xBF31;
const int32_t TAG_ESIM_GET_EID = 0xBF3E;
const int32_t TAG_ESIM_SET_NICKNAME = 0xBF29;
const int32_t TAG_ESIM_DELETE_PROFILE = 0xBF33;
const int32_t TAG_ESIM_GET_CONFIGURED_ADDRESSES = 0xBF3C;
const int32_t TAG_ESIM_SET_DEFAULT_SMDP_ADDRESS = 0xBF3F;
const int32_t TAG_ESIM_GET_RAT = 0xBF43;
const int32_t TAG_ESIM_EUICC_MEMORY_RESET = 0xBF34;
const int32_t TAG_ESIM_GET_EUICC_CHALLENGE = 0xBF2E;
const int32_t TAG_ESIM_GET_EUICC_INFO_1 = 0xBF20;
const int32_t TAG_ESIM_GET_EUICC_INFO_2 = 0xBF22;
const int32_t TAG_ESIM_LIST_NOTIFICATION = 0xBF28;
const int32_t TAG_ESIM_RETRIEVE_NOTIFICATIONS_LIST = 0xBF2B;
const int32_t TAG_ESIM_REMOVE_NOTIFICATION_FROM_LIST = 0xBF30;
const int32_t TAG_ESIM_AUTHENTICATE_SERVER = 0xBF38;
const int32_t TAG_ESIM_PREPARE_DOWNLOAD = 0xBF21;
const int32_t TAG_ESIM_INITIALISE_SECURE_CHANNEL = 0xBF23;
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_TAG_DEF_H
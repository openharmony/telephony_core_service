/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OPERATOR_CONFIG_HISYSEVENT_ENUM_H
#define OPERATOR_CONFIG_HISYSEVENT_ENUM_H

#include <sctdint>
#include <string>
namespace OHOS {
namespace Telephony {
enum class MatchSimFileType : int8_t {
    MATCH_NONE = -1,
    MATCH_IMSI = 0,
    MATCH_ICCID,
    MATCH_SPN,
    MATCH_GID1,
    MATCH_GID2,
    MATCH_MCCMNC
};

// 新加事件,在后面加
enum class MatchSimState : int8_t {
    CREATE_SIM_HELPER_SUCC = 0,
    CREATE_SIM_HELPER_FAIL,
    GET_OPKEY_FROM_SIM_SUCC,
    GET_OPKEY_FROM_SIM_FAIL,
    CREATE_OPKEY_HELPER_SUCC,
    CREATE_OPKEY_HELPER_FAIL,
    GET_ALL_RULE_FROM_OPKEY_SUCC,
    GET_ALL_RULE_FROM_OPKEY_FAIL,
    OPKEY_LOADED_TRIGGER_BLOCKED,
    OPKEY_LOADED_RESULT_VALID,
    OPKEY_LOADED_RESULT_INVALID,
    SIM_RECORDS_LOADED,
    SIM_RECORDS_LOADED_TRIGGER_BLOCKED,
    GET_OPKEY_SUCC,
    GET_OPKEY_SUCC_NORULE,
    GET_OPKEY_FAIL_CREATE_OPKEY_URI,
    GET_OPKEY_FAIL_NONEED,
    OPKEY_DB_UPDATE_SUCC,
    OPKEY_DB_UPDATE_FAIL,
    RESET_DATASHARE_ERROR,
    SEND_OPC_SUCC,
    SEND_OPC_FAIL,
    IMS_CLOUD_SUCC,
    IMS_CLOUD_FAIL
};

enum class MatchSimReason : int8_t (
    QUICK_MATCH_SIM = 1,
    SIM_RECORDS_LOADED,
    DATA_SHARE_READY,
    PARAM_UPDATE
);
}
}
#endif
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

#ifndef TELEPHONY_ERRORS_H
#define TELEPHONY_ERRORS_H

#include <errors.h>

namespace OHOS {
namespace Telephony {
const int TELEPHONY_PERMISSION_ERROR = -2;
const int TELEPHONY_ERROR = -1;
const int TELEPHONY_SUCCESS = 0;

enum {
    TELEPHONY_COMMON = 0x00,
    TELEPHONY_CALL_MANAGER = 0x01,
    TELEPHONY_CELLULAR_CALL = 0x02,
    TELEPHONY_CELLULAR_DATA = 0x03,
    TELEPHONY_SMS_MMS = 0x04,
    TELEPHONY_STATE_REGISTRY = 0x05,
    TELEPHONY_NET_MANAGER = 0x06,
    TELEPHONY_CORE_SERVICE_SIM = 0x07,
    TELEPHONY_CORE_SERVICE_NETWORK_SEARCH = 0x08,
    TELEPHONY_CORE_SERVICE_CORE = 0x09,
    TELEPHONY_DATA_STORAGE = 0x10,
    TELEPHONY_IMS = 0x11,
};

// Error code for common
constexpr ErrCode COMMON_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_COMMON);

enum {
    TELEPHONY_ERR_SUCCESS = 0,
    TELEPHONY_ERR_FAIL = COMMON_ERR_OFFSET,
    TELEPHONY_ERR_ARGUMENT_MISMATCH,
    TELEPHONY_ERR_ARGUMENT_INVALID,
    TELEPHONY_ERR_ARGUMENT_NULL,
    TELEPHONY_ERR_MEMCPY_FAIL,
    TELEPHONY_ERR_MEMSET_FAIL,
    TELEPHONY_ERR_STRCPY_FAIL,
    TELEPHONY_ERR_LOCAL_PTR_NULL,
    TELEPHONY_ERR_PERMISSION_ERR,
    TELEPHONY_ERR_DESCRIPTOR_MISMATCH,
    TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL,
    TELEPHONY_ERR_WRITE_DATA_FAIL,
    TELEPHONY_ERR_WRITE_REPLY_FAIL,
    TELEPHONY_ERR_READ_DATA_FAIL,
    TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL,
    TELEPHONY_ERR_ADD_DEATH_RECIPIENT_FAIL,
    TELEPHONY_ERR_REGISTER_CALLBACK_FAIL,
    TELEPHONY_ERR_UNINIT,
    TELEPHONY_ERR_UNREGISTER_CALLBACK_FAIL,
    TELEPHONY_ERR_SLOTID_INVALID,
    TELEPHONY_ERR_SUBSCRIBE_BROADCAST_FAIL,
    TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL,
    TELEPHONY_ERR_STRTOINT_FAIL,
    TELEPHONY_ERR_NO_SIM_CARD,
    TELEPHONY_ERR_DATABASE_WRITE_FAIL,
    TELEPHONY_ERR_DATABASE_READ_FAIL,
    TELEPHONY_ERR_RIL_CMD_FAIL,
    TELEPHONY_ERR_UNKNOWN_NETWORK_TYPE,
};

// Error code for telephony call manager
constexpr ErrCode CALL_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_CALL_MANAGER);

// Error code for telephony cellular call
constexpr ErrCode PROTOCOL_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_CELLULAR_CALL);

// Error code for telephony cellular data
constexpr ErrCode CELLULAR_DATA_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_CELLULAR_DATA);

// Error code for telephony sms mms
constexpr ErrCode SMS_MMS_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_SMS_MMS);

// Error code for telephony state registry
constexpr ErrCode STATE_REGISTRY_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_STATE_REGISTRY);

// Error code for telephony ner work
constexpr ErrCode NET_MANAGER_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_NET_MANAGER);

// Error code for telephony sim of core service
constexpr ErrCode CORE_SERVICE_SIM_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_CORE_SERVICE_SIM);

// Error code for telephony network search of core service
constexpr ErrCode CORE_SERVICE_NETWORK_SEARCH_ERR_OFFSET =
    ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_CORE_SERVICE_NETWORK_SEARCH);

// Error code for telephony core of core service
constexpr ErrCode CORE_SERVICE_CORE_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_CORE_SERVICE_CORE);

// Error code for telephony data storage
constexpr ErrCode CORE_DATA_STORAGE_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_DATA_STORAGE);

// Error code for telephony ims
constexpr ErrCode IMS_ERR_OFFSET = ErrCodeOffset(SUBSYS_TELEPONY, TELEPHONY_IMS);
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_ERRORS_H

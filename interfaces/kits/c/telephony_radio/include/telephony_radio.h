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

/**
 * @addtogroup Telephony
 * @{
 *
 * @brief Provides C interface for the telephony radio.
 *
 * @since 13
 */

/**
 * @file telephony_radio.h
 *
 * @brief Provides C interface for the telephony radio.
 *
 * @kit TelephonyKit
 * @syscap SystemCapability.Telephony.CoreService
 * @library libtelephony_radio.so
 * @since 13
 */

#ifndef NATIVE_TELEPHONY_RADIO_API_H
#define NATIVE_TELEPHONY_RADIO_API_H

#include "telephony_radio_type.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Obtains the radio network state.
 *
 * @param state Pointer to the network state.
 * @return the result defines in {@link Telephony_RadioResult}.
 *         {@link TEL_RADIO_SUCCESS} Success.
 *         {@link TEL_RADIO_PERMISSION_DENIED} Permission denied.
 *         {@link TEL_RADIO_ERR_MARSHALLING_FAILED} Low probability Marshalling failed, try again later.
 *         {@link TEL_RADIO_ERR_SERVICE_CONNECTION_FAILED} Unable to connect to telephony service, try again later.
 *         {@link TEL_RADIO_ERR_OPERATION_FAILED} Operation failed in telephony service, try again later.
 *         {@link TEL_RADIO_ERR_INVALID_PARAM} Invalid parameter.
 * @permission ohos.permission.GET_NETWORK_INFO
 * @syscap SystemCapability.Telephony.CoreService
 * @since 13
 */
Telephony_RadioResult OH_Telephony_GetNetworkState(Telephony_NetworkState *state);

/**
 * @brief Obtains the radio network state for given slot id.
 *
 * @param slotId the number of slot, 0 for card slot 1, 1 for card slot 2.
 * @param state Pointer to the network state.
 * @return the result defines in {@link Telephony_RadioResult}.
 *         {@link TEL_RADIO_SUCCESS} Success.
 *         {@link TEL_RADIO_PERMISSION_DENIED} Permission denied.
 *         {@link TEL_RADIO_ERR_MARSHALLING_FAILED} Low probability Marshalling failed, try again later.
 *         {@link TEL_RADIO_ERR_SERVICE_CONNECTION_FAILED} Unable to connect to telephony service, try again later.
 *         {@link TEL_RADIO_ERR_OPERATION_FAILED} Operation failed in telephony service, try again later.
 *         {@link TEL_RADIO_ERR_INVALID_PARAM} Invalid parameter.
 * @permission ohos.permission.GET_NETWORK_INFO
 * @syscap SystemCapability.Telephony.CoreService
 * @since 13
 */
Telephony_RadioResult OH_Telephony_GetNetworkStateForSlot(int32_t slotId, Telephony_NetworkState *state);
#ifdef __cplusplus
}
#endif

#endif // NATIVE_TELEPHONY_RADIO_API_H
/** @} */

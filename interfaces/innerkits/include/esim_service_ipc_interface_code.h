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

#ifndef ESIM_SERVICE_INTERFACE_CODE_H
#define ESIM_SERVICE_INTERFACE_CODE_H

/* SAID:4018 */
namespace OHOS {
namespace Telephony {
enum class EsimServiceInterfaceCode {
    GET_EID = 0,
    GET_OSU_STATUS,
    START_OSU,
    GET_DOWNLOAD_ABLE_PROFILE_METADATA,
    GET_AVAILABLE_DOWNLOADABLE_PROFILE_LIST,
    DOWNLOAD_PROFILE,
    GET_EUICC_PROFILE_INFO_LIST,
    GET_EUICC_INFO,
    DELETE_PROFILE,
    SWITCH_TO_PROFILE,
    SET_PROFILE_NICKNAME,
    RESET_MEMORY,
    RESERVE_PROFILES_FOR_FACTORY_RESTORE,
    SET_DEFAULT_SMDP_ADDRESS,
    GET_DEFAULT_SMDP_ADDRESS,
    CANCEL_SESSION,
    IS_ESIM_SUPPORTED,
};
} // namespace Telephony
} // namespace OHOS
#endif // ESIM_SERVICE_INTERFACE_CODE_H
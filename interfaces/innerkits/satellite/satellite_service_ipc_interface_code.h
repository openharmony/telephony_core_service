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

#ifndef SATELLITE_SERVICE_INTERFACE_CODE_H
#define SATELLITE_SERVICE_INTERFACE_CODE_H

/* SAID:4012 */
namespace OHOS {
namespace Telephony {
enum class SatelliteServiceInterfaceCode {
    IS_SATELLITE_ENABLED,
    SET_RADIO_STATE,
    REGISTER_CORE_NOTIFY,
    UNREGISTER_CORE_NOTIFY,
    GET_PROXY_OBJECT_PTR,
    GET_IMEI,
    GET_SATELLITE_CAPABILITY,
};
} // namespace Telephony
} // namespace OHOS
#endif // SATELLITE_SERVICE_INTERFACE_CODE_H

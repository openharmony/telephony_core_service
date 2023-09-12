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

#ifndef TELEPHONY_IMS_CORE_SERVICE_IPC_INTERFACE_CODE_H
#define TELEPHONY_IMS_CORE_SERVICE_IPC_INTERFACE_CODE_H

/* SAID:4010 */
namespace OHOS {
namespace Telephony {
enum class ImsCoreServiceInterfaceCode {
    /****************** core basic ******************/
    IMS_GET_REGISTRATION_STATUS = 0,
    IMS_GET_PHONE_NUMBER_FROM_IMPU,

    /****************** callback ******************/
    IMS_REGISTER_CALLBACK = 100,
    IMS_GET_PROXY_OBJECT_PTR,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_IPC_INTERFACE_CODE_H
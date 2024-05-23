/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef NAPI_IMS_REG_INFO_CALLBACK_MANAGER_H
#define NAPI_IMS_REG_INFO_CALLBACK_MANAGER_H

#include <uv.h>

#include "napi_radio.h"

namespace OHOS {
namespace Telephony {
class NapiImsRegInfoCallbackManager {
public:
    int32_t RegisterImsRegStateCallback(ImsRegStateCallback &stateCallback);
    int32_t UnregisterImsRegStateCallback(napi_env env, int32_t slotId, ImsServiceType imsSrvType);
    int32_t ReportImsRegInfo(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info);

private:
    int32_t ReportImsRegInfoInner(const ImsRegStateCallback &stateCallback, const ImsRegInfo &info);
    int32_t InsertImsRegCallback(int32_t slotId, ImsServiceType imsSrvType, ImsRegStateCallback &stateCallback);
    void RemoveImsRegCallback(int32_t slotId, ImsServiceType imsSrvType);
    static void ReportImsRegInfoWork(uv_work_t *work, int32_t status);
    static int32_t ReportImsRegInfo(const ImsRegInfo &info, const ImsRegStateCallback &stateCallback);

private:
    std::list<ImsRegStateCallback> listImsRegStateCallback_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NAPI_IMS_REG_INFO_CALLBACK_MANAGER_H
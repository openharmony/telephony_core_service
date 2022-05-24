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

#ifndef NAPI_IMS_CALLBACK_MANAGER_H
#define NAPI_IMS_CALLBACK_MANAGER_H

#include <securec.h>
#include <uv.h>
#include <ctime>
#include "singleton.h"

#include "napi_util.h"
#include "napi_radio.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class NapiImsCallbackManager {
public:
    void RegImsStateCallback(ImsStateCallback stateCallback);
    void UnRegImsStateCallback(napi_env env, int32_t slotId, ImsServiceType imsSrvType);
    void UnRegAllImsStateCallbackOfType(napi_env env, int32_t slotId, ImsServiceType imsSrvType);
    int32_t UpdateImsState(ImsServiceType imsSrvType, const ImsRegInfo &info);
private:
    void UnRegCallback(ImsServiceType imsSrvType, int32_t slotId, std::list<ImsStateCallback>::iterator iter);
    int32_t UpdateImsStateInfo(ImsStateCallback stateCallback, const ImsRegInfo &info);
    static void ReportImsStateWork(uv_work_t *work, int32_t status);
    static int32_t ReportImsState(ImsRegInfo &info, ImsStateCallback stateCallback);
    ImsStateCallback stateCallback_;
    std::list<ImsStateCallback> listStateCallback_;
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // NAPI_IMS_CALLBACK_MANAGER_H
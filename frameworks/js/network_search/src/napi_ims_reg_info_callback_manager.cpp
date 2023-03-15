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
#include "napi_ims_reg_info_callback_manager.h"

#include "core_service_client.h"
#include "napi_util.h"
#include "singleton.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
int32_t NapiImsRegInfoCallbackManager::RegisterImsRegStateCallback(ImsRegStateCallback &stateCallback)
{
    int32_t slotId = stateCallback.slotId;
    ImsServiceType imsSrvType = stateCallback.imsSrvType;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter : listImsRegStateCallback_) {
        if ((iter.slotId == slotId) && (iter.imsSrvType == imsSrvType)) {
            TELEPHONY_LOGI("[slot%{public}d] Ignore register action, since callback is existent, type %{public}d",
                slotId, imsSrvType);
            return TELEPHONY_SUCCESS;
        }
    }
    stateCallback.imsCallback = new NapiImsRegInfoCallback();
    if (stateCallback.imsCallback == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] Creat ImsRegInfoCallback failed, type %{public}d,", slotId, imsSrvType);
        return TELEPHONY_ERR_REGISTER_CALLBACK_FAIL;
    }
    int32_t ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().RegisterImsRegInfoCallback(
        slotId, imsSrvType, stateCallback.imsCallback);
    if (ret == TELEPHONY_SUCCESS) {
        listImsRegStateCallback_.push_back(stateCallback);
        TELEPHONY_LOGI(
            "[slot%{public}d] Register imsRegState callback successfully, type %{public}d", slotId, imsSrvType);
    } else {
        if (stateCallback.imsCallback != nullptr) {
            stateCallback.imsCallback = nullptr;
        }
        TELEPHONY_LOGE("[slot%{public}d] Register imsRegState callback failed, type %{public}d, ret %{public}d", slotId,
            imsSrvType, ret);
    }
    return ret;
}

int32_t NapiImsRegInfoCallbackManager::UnregisterImsRegStateCallback(
    napi_env env, int32_t slotId, ImsServiceType imsSrvType)
{
    int32_t ret = TELEPHONY_SUCCESS;
    std::lock_guard<std::mutex> lock(mutex_);
    ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnregisterImsRegInfoCallback(slotId, imsSrvType);
    auto iter = listImsRegStateCallback_.begin();
    for (; iter != listImsRegStateCallback_.end(); ++iter) {
        if ((iter->slotId == slotId) && (iter->imsSrvType == imsSrvType)) {
            if (iter->imsCallback != nullptr) {
                iter->imsCallback = nullptr;
            }
            listImsRegStateCallback_.erase(iter);
            break;
        }
    }
    TELEPHONY_LOGI(
        "[slot%{public}d] Unregister imsRegState callback successfully, type %{public}d", slotId, imsSrvType);
    return ret;
}

int32_t NapiImsRegInfoCallbackManager::ReportImsRegInfo(
    int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    int32_t ret = TELEPHONY_ERROR;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter : listImsRegStateCallback_) {
        if ((iter.slotId == slotId) && (iter.imsSrvType == imsSrvType)) {
            ret = ReportImsRegInfoInner(iter, info);
            break;
        }
    }
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d] Report imsRegState callback failed, type %{public}d, ret %{public}d", slotId,
            imsSrvType, ret);
        return ret;
    }
    TELEPHONY_LOGI("[slot%{public}d] Report imsRegState callback successfully, type %{public}d", slotId, imsSrvType);
    return ret;
}

int32_t NapiImsRegInfoCallbackManager::ReportImsRegInfoInner(
    const ImsRegStateCallback &stateCallback, const ImsRegInfo &info)
{
    uv_loop_s *loop = nullptr;
#if NAPI_VERSION >= 2
    napi_get_uv_event_loop(stateCallback.env, &loop);
#endif
    ImsStateWorker *dataWorker = new ImsStateWorker();
    dataWorker->info = info;
    dataWorker->callback = stateCallback;
    uv_work_t *work = new uv_work_t();
    work->data = (void *)(dataWorker);
    uv_queue_work(
        loop, work, [](uv_work_t *work) {}, ReportImsRegInfoWork);
    return TELEPHONY_SUCCESS;
}

void NapiImsRegInfoCallbackManager::ReportImsRegInfoWork(uv_work_t *work, int32_t status)
{
    ImsStateWorker *dataWorkerData = (ImsStateWorker *)work->data;
    int32_t ret = ReportImsRegInfo(dataWorkerData->info, dataWorkerData->callback);
    delete dataWorkerData;
    dataWorkerData = nullptr;
    delete work;
    work = nullptr;
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ReportImsRegInfo failed, result: %{public}d", ret);
        return;
    }
    TELEPHONY_LOGI("ReportImsRegInfo successfully");
}

int32_t NapiImsRegInfoCallbackManager::ReportImsRegInfo(
    const ImsRegInfo &info, const ImsRegStateCallback &stateCallback)
{
    napi_env env = stateCallback.env;
    napi_value callbackValues[CALLBACK_VALUES_SIZE] = { 0 };
    napi_create_object(env, &callbackValues[0]);
    NapiUtil::SetPropertyInt32(env, callbackValues[0], "imsRegState", static_cast<int32_t>(info.imsRegState));
    NapiUtil::SetPropertyInt32(env, callbackValues[0], "imsRegTech", static_cast<int32_t>(info.imsRegTech));
    napi_value thisVar = nullptr;
    napi_get_reference_value(env, stateCallback.thisVar, &thisVar);
    napi_value callbackFunc = nullptr;
    napi_get_reference_value(env, stateCallback.callbackRef, &callbackFunc);
    if (callbackFunc == nullptr) {
        TELEPHONY_LOGE("callbackFunc is nullptr!");
        return TELEPHONY_ERROR;
    }
    napi_value callbackResult = nullptr;
    napi_status ret =
        napi_call_function(env, thisVar, callbackFunc, std::size(callbackValues), callbackValues, &callbackResult);
    if (ret != napi_status::napi_ok) {
        TELEPHONY_LOGE("napi_call_function failed!");
        return TELEPHONY_ERROR;
    }
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
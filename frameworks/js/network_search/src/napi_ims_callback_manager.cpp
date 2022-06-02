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
#include "napi_ims_callback_manager.h"
#include "core_service_client.h"

namespace OHOS {
namespace Telephony {
void NapiImsCallbackManager::RegImsStateCallback(ImsStateCallback stateCallback)
{
    if (stateCallback.voiceCallback != nullptr
        || stateCallback.videoCallback != nullptr
        || stateCallback.utCallback != nullptr
        || stateCallback.smsCallback != nullptr) {
            listStateCallback_.push_back(stateCallback);
    }
}

void NapiImsCallbackManager::UnRegCallback(
    ImsServiceType imsSrvType, int32_t slotId, std::list<ImsStateCallback>::iterator iter)
{
    switch (imsSrvType) {
        case ImsServiceType::TYPE_VOICE:
            DelayedRefSingleton<CoreServiceClient>::GetInstance()
                .UnRegImsVoiceCallback(slotId, iter->voiceCallback);
            (void)memset_s(&iter->voiceCallback, sizeof(ImsStateCallback), 0, sizeof(ImsStateCallback));
            break;
        case ImsServiceType::TYPE_VIDEO:
            DelayedRefSingleton<CoreServiceClient>::GetInstance()
                .UnRegImsVideoCallback(slotId, iter->videoCallback);
            (void)memset_s(&iter->videoCallback, sizeof(ImsStateCallback), 0, sizeof(ImsStateCallback));
            break;
        case ImsServiceType::TYPE_UT:
            DelayedRefSingleton<CoreServiceClient>::GetInstance()
                .UnRegImsUtCallback(slotId, iter->utCallback);
            (void)memset_s(&iter->utCallback, sizeof(ImsStateCallback), 0, sizeof(ImsStateCallback));
            break;
        case ImsServiceType::TYPE_SMS:
            DelayedRefSingleton<CoreServiceClient>::GetInstance()
                .UnRegImsSmsCallback(slotId, iter->smsCallback);
            (void)memset_s(&iter->smsCallback, sizeof(ImsStateCallback), 0, sizeof(ImsStateCallback));
            break;
        default:
            TELEPHONY_LOGE("%{public}d type is error!", imsSrvType);
            break;
    }
}

void NapiImsCallbackManager::UnRegImsStateCallback(napi_env env, int32_t slotId, ImsServiceType imsSrvType)
{
    auto iter = listStateCallback_.begin();
    for (; iter != listStateCallback_.end(); ++iter) {
        if ((iter->env == env)
            && (iter->slotId == slotId)
            && (iter->imsSrvType == imsSrvType)
            && (iter->callbackRef)) {
                UnRegCallback(imsSrvType, slotId, iter);
                listStateCallback_.erase(iter);
        }
    }
}

void NapiImsCallbackManager::UnRegAllImsStateCallbackOfType(
    napi_env env, int32_t slotId, ImsServiceType imsSrvType)
{
    auto iter = listStateCallback_.begin();
    for (; iter != listStateCallback_.end(); ++iter) {
        if ((iter->slotId == slotId)
            && (iter->imsSrvType == imsSrvType)
            && (iter->callbackRef)) {
                UnRegCallback(imsSrvType, slotId, iter);
                listStateCallback_.erase(iter);
        }
    }
}

int32_t NapiImsCallbackManager::UpdateImsState(ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    int32_t ret;
    auto iter = listStateCallback_.begin();
    for (; iter != listStateCallback_.end(); ++iter) {
        if (iter->imsSrvType == imsSrvType) {
            UpdateImsStateInfo(*iter, info);
            ret = SUCCESS;
        } else {
            TELEPHONY_LOGE("%{public}d type is null!", imsSrvType);
            ret = ERROR;
        }
    }
    return ret;
}

int32_t NapiImsCallbackManager::UpdateImsStateInfo(ImsStateCallback stateCallback, const ImsRegInfo &info)
{
    if (stateCallback.thisVar == nullptr) {
        TELEPHONY_LOGE("stateCallback is null!");
        return ERROR;
    }
    uv_loop_s *loop = nullptr;
#if NAPI_VERSION >= 2
    napi_get_uv_event_loop(stateCallback.env, &loop);
#endif
    ImsStateWorker *dataWorker = std::make_unique<ImsStateWorker>().release();
    if (dataWorker == nullptr) {
        TELEPHONY_LOGE("dataWorker is nullptr!");
        return ERROR;
    }
    dataWorker->info = info;
    dataWorker->callback = stateCallback;
    uv_work_t *work = std::make_unique<uv_work_t>().release();
    if (work == nullptr) {
        TELEPHONY_LOGE("work is nullptr!");
        return ERROR;
    }
    work->data = (void *)dataWorker;
    uv_queue_work(
        loop, work, [](uv_work_t *work) {}, ReportImsStateWork);
    return SUCCESS;
}

void NapiImsCallbackManager::ReportImsStateWork(uv_work_t *work, int32_t status)
{
    ImsStateWorker *dataWorkerData = (ImsStateWorker *)work->data;
    if (dataWorkerData == nullptr) {
        TELEPHONY_LOGE("dataWorkerData is nullptr!");
        return;
    }
    int32_t ret = ReportImsState(dataWorkerData->info, dataWorkerData->callback);
    TELEPHONY_LOGI("ReportImsState is %{public}d", ret);
    delete dataWorkerData;
    dataWorkerData = nullptr;
    delete work;
    work = nullptr;
}
int32_t NapiImsCallbackManager::ReportImsState(ImsRegInfo &info, ImsStateCallback stateCallback)
{
    napi_value callbackFunc = nullptr;
    napi_env env = stateCallback.env;
    napi_value callbackValues[2] = {0};
    napi_create_object(env, &callbackValues[0]);
    NapiUtil::SetPropertyInt32(
        env, callbackValues[0], "imsRegState", static_cast<int32_t>(info.imsRegState));
    NapiUtil::SetPropertyInt32(
        env, callbackValues[0], "imsRegTech", static_cast<int32_t>(info.imsRegTech));
    napi_get_reference_value(env, stateCallback.callbackRef, &callbackFunc);
    napi_value callbackResult = nullptr;
    if (callbackFunc == nullptr) {
        TELEPHONY_LOGE("callbackFunc is null!");
        return ERROR;
    }
    napi_call_function(env, stateCallback.thisVar, callbackFunc, 1, callbackValues, &callbackResult);
    return SUCCESS;
}
}  // namespace Telephony
}  // namespace OHOS
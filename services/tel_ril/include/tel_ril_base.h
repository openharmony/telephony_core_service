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

#ifndef TEL_RIL_BASE_H
#define TEL_RIL_BASE_H

#include <any>
#include <mutex>

#include "event_runner.h"
#include "functional"
#include "hril_base_parcel.h"
#include "hril_types.h"
#include "iremote_broker.h"
#include "observer_handler.h"
#include "radio_event.h"
#include "sim_constant.h"
#include "tel_ril_common.h"
#include "tel_ril_handler.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"
#include "v1_0/iril.h"

namespace OHOS {
namespace Telephony {
struct TelRilRequest {
    int32_t serialId_ = 0;
    int32_t requestId_ = 0;
    AppExecFwk::InnerEvent::Pointer &pointer_ = nullptr_;

    TelRilRequest(int32_t serialId, int32_t requestId, const AppExecFwk::InnerEvent::Pointer &pointer)
    {
        serialId_ = serialId;
        requestId_ = requestId;
        pointer_ = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(pointer));
    }
private:
    AppExecFwk::InnerEvent::Pointer nullptr_ = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
};

class TelRilBase {
public:
    TelRilBase(int32_t slotId, sptr<HDI::Ril::V1_0::IRil> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    virtual ~TelRilBase() = default;

    static std::shared_ptr<TelRilRequest> CreateTelRilRequest(
        int32_t request, const AppExecFwk::InnerEvent::Pointer &result);
    void ResetRilInterface(sptr<HDI::Ril::V1_0::IRil> rilInterface);
    static std::shared_ptr<TelRilRequest> FindTelRilRequest(const HRilRadioResponseInfo &responseInfo);
    int32_t ErrorResponse(std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo);

protected:
    template<typename FuncType, typename... ParamTypes>
    inline int32_t Request(const char *funcName, const AppExecFwk::InnerEvent::Pointer &response, int32_t requestId,
        FuncType &&_func, ParamTypes &&... _args);
    inline HRilRadioResponseInfo BuildHRilRadioResponseInfo(const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo);
    inline int32_t Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo);
    template<typename T>
    inline int32_t Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo, T data);
    template<typename T>
    inline int32_t Response(
        const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo, std::shared_ptr<T> data);
    template<typename T>
    inline int32_t Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo,
        std::function<std::shared_ptr<T>(std::shared_ptr<TelRilRequest>)> getDataFunc);
    template<typename T>
    inline int32_t Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo,
        std::function<T(std::shared_ptr<TelRilRequest>)> getDataFunc);
    inline int32_t Notify(const char *funcName, RadioEvent notifyId);
    template<typename T>
    inline int32_t Notify(const char *funcName, std::shared_ptr<T> data, RadioEvent notifyId);
    inline int32_t ConfirmSupplementOfTelRilRequestInfo(
        const char *funcName, std::shared_ptr<TelRilRequest> telRilRequest);

protected:
    std::shared_ptr<ObserverHandler> observerHandler_;
    sptr<HDI::Ril::V1_0::IRil> rilInterface_;
    int32_t slotId_;

private:
    static int32_t GetNextSerialId(void);
    int32_t GetSerialId(const AppExecFwk::InnerEvent::Pointer &response, uint32_t requestId);
    template<typename T>
    inline int32_t SendHandlerEvent(const char *funcName, std::shared_ptr<TelRilRequest> telRilRequest,
        std::function<T(std::shared_ptr<TelRilRequest>)> getDataFunc);
    template<typename T>
    inline int32_t SendEventData(
        const char *funcName, uint32_t eventId, std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler, T data);
    void DfxWriteCallFaultEvent(std::shared_ptr<TelRilRequest> telRilRequest, const int32_t error);

private:
    static std::atomic_uint nextSerialId_;
    static std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> requestMap_;
    static std::mutex requestLock_;
    static std::shared_ptr<TelRilHandler> handler_;
};

template<typename FuncType, typename... ParamTypes>
inline int32_t TelRilBase::Request(const char *funcName, const AppExecFwk::InnerEvent::Pointer &response,
    int32_t requestId, FuncType &&_func, ParamTypes &&... _args)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(requestId, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("%{public}s() telRilRequest is null: eventid=%{public}d", funcName, requestId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (rilInterface_ == nullptr) {
        TELEPHONY_LOGE("%{public}s() rilInterface_ is null: eventid=%{public}d", funcName, requestId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return (rilInterface_->*(_func))(slotId_, telRilRequest->serialId_, std::forward<ParamTypes>(_args)...);
}

inline int32_t TelRilBase::Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo)
{
    auto getDataFunc = [&iResponseInfo](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        result->flag = telRilRequest->pointer_->GetParam();
        result->error = static_cast<HRilErrType>(iResponseInfo.error);
        result->serial = iResponseInfo.serial;
        return result;
    };
    return Response<HRilRadioResponseInfo>(funcName, iResponseInfo, getDataFunc);
}

template<typename T>
inline int32_t TelRilBase::Response(
    const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo, T data)
{
    auto getDataFunc = [data](std::shared_ptr<TelRilRequest> telRilRequest) { return data; };
    return Response<T>(funcName, iResponseInfo, getDataFunc);
}

template<typename T>
inline int32_t TelRilBase::Response(
    const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo, std::shared_ptr<T> data)
{
    if (data == nullptr) {
        TELEPHONY_LOGE("Response func %{public}s data  is null", funcName);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto getDataFunc = [&data](std::shared_ptr<TelRilRequest> telRilRequest) { return data; };
    return Response<T>(funcName, iResponseInfo, getDataFunc);
}

template<typename T>
inline int32_t TelRilBase::Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo,
    std::function<std::shared_ptr<T>(std::shared_ptr<TelRilRequest>)> getDataFunc)
{
    return Response<std::shared_ptr<T>>(funcName, iResponseInfo, getDataFunc);
}

template<typename T>
inline int32_t TelRilBase::Response(const char *funcName, const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo,
    std::function<T(std::shared_ptr<TelRilRequest>)> getDataFunc)
{
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(iResponseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("func %{public}s telRilReques or telRilRequest->pointer or data is null", funcName);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (radioResponseInfo.error != HRilErrType::NONE) {
        return ErrorResponse(telRilRequest, radioResponseInfo);
    }
    return SendHandlerEvent<T>(funcName, telRilRequest, getDataFunc);
}

template<typename T>
inline int32_t TelRilBase::SendHandlerEvent(const char *funcName, std::shared_ptr<TelRilRequest> telRilRequest,
    std::function<T(std::shared_ptr<TelRilRequest>)> getDataFunc)
{
    auto handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("func %{public}s handler == nullptr !!!", funcName);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return SendEventData<T>(funcName, telRilRequest->pointer_->GetInnerEventId(), handler, getDataFunc(telRilRequest));
}

template<typename T>
inline int32_t TelRilBase::SendEventData(
    const char *funcName, uint32_t eventId, std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler, T data)
{
    if (!handler->SendEvent(eventId, data)) {
        TELEPHONY_LOGE("func %{public}s Send eventId:%{public}d is failed!", funcName, eventId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    TELEPHONY_LOGD("func %{public}s Send eventId:%{public}d finish", funcName, eventId);
    return TELEPHONY_ERR_SUCCESS;
}

template<typename T>
inline int32_t TelRilBase::Notify(const char *funcName, std::shared_ptr<T> data, RadioEvent notifyId)
{
    if (observerHandler_ == nullptr || data == nullptr) {
        TELEPHONY_LOGE("%{public}s() observerHandler_ or data is nullptr", funcName);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGD("%{public}s() notify event %{public}d notifyId slotId:%{public}d", funcName, notifyId, slotId_);
    observerHandler_->NotifyObserver(notifyId, data);
    return TELEPHONY_ERR_SUCCESS;
}

inline int32_t TelRilBase::Notify(const char *funcName, RadioEvent notifyId)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("%{public}s() observerHandler_  is nullptr", funcName);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGD("%{public}s() notify event %{public}d notifyId slotId:%{public}d", funcName, notifyId, slotId_);
    observerHandler_->NotifyObserver(notifyId);
    return TELEPHONY_ERR_SUCCESS;
}

inline HRilRadioResponseInfo TelRilBase::BuildHRilRadioResponseInfo(
    const HDI::Ril::V1_0::RilRadioResponseInfo &iResponseInfo)
{
    HRilRadioResponseInfo responseInfo = { 0 };
    responseInfo.flag = iResponseInfo.flag;
    responseInfo.serial = iResponseInfo.serial;
    responseInfo.error = (HRilErrType)iResponseInfo.error;
    responseInfo.type = (HRilResponseTypes)iResponseInfo.type;
    return responseInfo;
}

inline int32_t TelRilBase::ConfirmSupplementOfTelRilRequestInfo(
    const char *funcName, std::shared_ptr<TelRilRequest> telRilRequest)
{
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("func %{public}s telRilReques or telRilRequest->pointer or data is null", funcName);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    auto handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("func %{public}s handler is nullptr !!!", funcName);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_BASE_H

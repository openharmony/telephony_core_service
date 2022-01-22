/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "iremote_broker.h"

#include "hril_base_parcel.h"
#include "hril_types.h"
#include "radio_event.h"
#include "observer_handler.h"
#include "tel_ril_common.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
struct TelRilRequest {
    int32_t serialId_ = 0;
    int32_t requestId_ = 0;
    AppExecFwk::InnerEvent::Pointer pointer_ = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);

    TelRilRequest(int32_t serialId, int32_t requestId, const AppExecFwk::InnerEvent::Pointer &pointer)
    {
        serialId_ = serialId;
        requestId_ = requestId;
        pointer_ = std::move(const_cast<AppExecFwk::InnerEvent::Pointer &>(pointer));
    }
};

class TelRilBase {
public:
    TelRilBase(int32_t slotId, sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);
    virtual ~TelRilBase() = default;

    /**
     * request list handler
     */
    static std::shared_ptr<TelRilRequest> CreateTelRilRequest(
        int32_t request, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Send Int32Event
     * @param: int32_t dispatchId.
     * @param: int32_t value.
     * @return: Returns the value of the send_result.
     */
    int32_t SendInt32Event(int32_t dispatchId, int32_t value);

    /**
     * @brief Send Int32Event
     * @param: int32_t dispatchId.
     * @param: int32_t value.
     * @return: Returns the value of the send_result.
     */
    int32_t SendInt32sEvent(int32_t dispatchId, int32_t argCount, ...);

    /**
     * @brief Send BufferEvent
     * @param: int32_t dispatchId
     * @param: user data &eventData
     * @return: Returns the value of the send_result.
     */
    template<typename T>
    int32_t SendBufferEvent(int32_t dispatchId, const T &eventData)
    {
        if (cellularRadio_ == nullptr) {
            TELEPHONY_LOGE("cellularRadio_ is nullptr!!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }

        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(slotId_);
        eventData.Marshalling(data);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        TELEPHONY_LOGI("Send event, dispatchId:%{public}d", dispatchId);
        return cellularRadio_->SendRequest(dispatchId, data, reply, option);
    }

    /**
     * @brief Send CommonBufferEvent
     *
     * @param: int32_t dispatchId.
     * @param: void *eventData.
     * @param: size_t dataLength.
     *
     * @return:Returns the value of the send_result.
     */
    int32_t SendCommonBufferEvent(int32_t dispatchId, const void *eventData, size_t dataLength);

    /**
     * @brief Proscess response done message
     * @param rr for response callback was called
     * @param responseInfo HRilRadioResponseInfo received in the callback
     */

    void ResetRemoteObject(sptr<IRemoteObject> rilAdapterObj);
    static std::shared_ptr<TelRilRequest> FindTelRilRequest(const HRilRadioResponseInfo &responseInfo);

    int32_t ErrorResponse(const int32_t serial, const HRilErrType err);
    int32_t ErrorResponse(std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo);
    int32_t TelRilOnlyReportResponseInfo(MessageParcel &data);
    template<typename T>
    int32_t NotifyObserver(int32_t what, MessageParcel &data);
    template<typename T>
    int32_t ProcessRespOrNotify(int32_t code, MessageParcel &data);

protected:
    // Data type definitions within the subdivision module.
    using EventHandler = OHOS::AppExecFwk::EventHandler;
    struct UserEvent {
        const char *funcName_;
        TelRilBase &this_;
        EventHandler &handler_;
        MessageParcel &data_;
        uint32_t eventId_;
        const HRilRadioResponseInfo &radioResponseInfo_;
        const TelRilRequest &telRilRequest_;
    };
    using UserSendEvent = int32_t (*)(UserEvent &event);
    using SendEvent = int32_t (TelRilBase::*)(const char *funcName, EventHandler &handler, MessageParcel &data,
        uint32_t eventId);

    // Respond to "request" events from the upper layer of tel_ril.
    template<typename... ValueTypes>
    int32_t Request(const char *funcName, const AppExecFwk::InnerEvent::Pointer &response, uint32_t requestId,
        ValueTypes &&...vals);
    // Respond to the "reply" event sent by the hril layer.
    int32_t Response(const char *funcName, MessageParcel &data, UserSendEvent send);
    // Respond to the "reply" event sent by the hril layer.
    template<typename T>
    int32_t Response(const char *funcName, MessageParcel &data);
    // Respond to "active reporting" events sent by the hril layer.
    template<typename T>
    int32_t Notify(const char *funcName, MessageParcel &data, RadioEvent notifyId);

    // std::any type: int32_t (T::*)(MessageParcel &data);
    std::map<uint32_t, std::any> memberFuncMap_;
    std::shared_ptr<ObserverHandler> observerHandler_;
    sptr<IRemoteObject> cellularRadio_;
    int32_t slotId_;

private:
    /* Output "null pointer" error log */
    void PrintErrorForEmptyPointer(void);
    static int32_t GetNextSerialId(void);

    /* Request */
    int32_t GetSerialId(const AppExecFwk::InnerEvent::Pointer &response, uint32_t requestId);
    /* Response */
    template<typename F>
    F GetReportFunc(uint32_t code);
    // Send data to "tel_ril" upper layer.
    template<typename T>
    int32_t SendData(const char *funcName, EventHandler &handler, MessageParcel &data, uint32_t eventId);
    const HRilRadioResponseInfo &GetHRilRadioResponse(MessageParcel &data);
    int32_t Response(const char *funcName, MessageParcel &data, SendEvent send);
    // Get the event pointer of the current thread: thread variable.
    SendEvent &SelfSendEvent(void);

private:
    static std::atomic_uint nextSerialId_;
    static std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> requestMap_;
    static std::mutex requestLock_;
};

template<typename... ValueTypes>
int32_t TelRilBase::Request(const char *funcName, const AppExecFwk::InnerEvent::Pointer &response,
    uint32_t requestId, ValueTypes &&...vals)
{
    int32_t serialId = GetSerialId(response, requestId);
    if (serialId >= 0) {
        MessageParcel data;
        MessageParcel reply;
        thread_local OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (BaseParcel::WriteVals(data, slotId_, serialId, std::forward<ValueTypes>(vals)...)) {
            int32_t ret = cellularRadio_->SendRequest(requestId, data, reply, option);
            TELEPHONY_LOGI("%{public}s() eventId=%{public}d, return: %{public}d", funcName, requestId, ret);
            return ret;
        }
        TELEPHONY_LOGE("%{public}s() write fail to parcel: eventid=%{public}d", funcName, requestId);
        return TELEPHONY_ERR_FAIL;
    }
    TELEPHONY_LOGE("%{public}s() get serial fail: eventid=%{public}d", funcName, requestId);
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

template<typename F>
F TelRilBase::GetReportFunc(uint32_t code)
{
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        return std::any_cast<F>(itFunc->second);
    }
    TELEPHONY_LOGE("Can not find report code in func map: %{public}d!", code);
    return nullptr;
}

template<typename T>
int32_t TelRilBase::ProcessRespOrNotify(int32_t code, MessageParcel &data)
{
    using ReportFunc = int32_t (T::*)(MessageParcel &data);
    auto func = GetReportFunc<ReportFunc>(code);
    if (func != nullptr) {
        return (static_cast<T *>(this)->*func)(data);
    }
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

template<typename T>
int32_t TelRilBase::NotifyObserver(int32_t what, MessageParcel &data)
{
    std::shared_ptr<T> info = std::make_shared<T>();
    info->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(what, info);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        PrintErrorForEmptyPointer();
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

template<typename T>
int32_t TelRilBase::Response(const char *funcName, MessageParcel &data)
{
    return Response(funcName, data, (SendEvent)&TelRilBase::SendData<T>);
}

template<typename T>
int32_t TelRilBase::SendData(const char *funcName, EventHandler &handler, MessageParcel &data, uint32_t eventId)
{
    std::shared_ptr<T> t = std::make_shared<T>();
    bool ret = t->ReadFromParcel(data);
    TELEPHONY_LOGI("%{public}s() response event %{public}d =[%{public}s], read ret=%{public}d, slotId:%{public}d",
        funcName, eventId, t->ToString(), ret, slotId_);
    return handler.SendEvent(eventId, t);
}

template<typename T>
int32_t TelRilBase::Notify(const char *funcName, MessageParcel &data, RadioEvent notifyId)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("%{public}s() observerHandler_ is nullptr", funcName);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<T> t = std::make_shared<T>();
    bool ret = t->ReadFromParcel(data);
    TELEPHONY_LOGI("%{public}s() notify event %{public}d =[%{public}s], read ret=%{public}d, slotId:%{public}d",
        funcName, notifyId, t->ToString(), ret, slotId_);
    observerHandler_->NotifyObserver(notifyId, t);
    return TELEPHONY_ERR_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_BASE_H

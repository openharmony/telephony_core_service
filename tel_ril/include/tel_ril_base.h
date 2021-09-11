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

#include <mutex>
#include "iremote_broker.h"
#include "telephony_log_wrapper.h"
#include "observer_handler.h"
#include "tel_ril_common.h"
#include "hril_types.h"

namespace OHOS {
namespace Telephony {
struct TelRilRequest {
    int32_t serialId_;
    int32_t requestId_;
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
    TelRilBase(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);
    ~TelRilBase() = default;

    /**
     * request list handler
     */
    static std::shared_ptr<TelRilRequest> CreateTelRilRequest(
        int request, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Send Int32Event
     * @param: int32_t dispatchId.
     * @param: int32_t value.
     * @return: Returns the value of the send_result.
     */
    int32_t SendInt32Event(int32_t dispatchId, int32_t value);

    /**
     * @brief Send StringEvent
     * @param: int32_t dispatchId.
     * @param: const char *value.
     * @return：Returns the value of the send_result.
     */
    int32_t SendStringEvent(int32_t dispatchId, const char *value);

    /**
     * @brief Send BufferEvent
     * @param: int32_t dispatchId
     * @param: MessageParcel &eventData
     * @return: Returns the value of the send_result.
     */
    int32_t SendBufferEvent(int32_t dispatchId, MessageParcel &eventData);

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
    static std::shared_ptr<TelRilRequest> FindTelRilRequest(const HRilRadioResponseInfo &responseInfo);

    void ErrorResponse(const int32_t serial, const HRilErrType err);

    void ErrorResponse(std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo);

    static int32_t GetNextSerialId()
    {
        return nextSerialId_++;
    }
    static std::atomic_int nextSerialId_;
    static std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> requestMap_;
    static std::mutex requestLock_;

protected:
    std::shared_ptr<ObserverHandler> observerHandler_;
    sptr<IRemoteObject> cellularRadio_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_BASE_H

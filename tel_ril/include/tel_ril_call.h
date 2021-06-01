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
#ifndef TEL_RIL_CALL_H
#define TEL_RIL_CALL_H

#include <memory>
#include <map>
#include <unordered_map>
#include "observer_handler.h"
#include "telephony_log.h"
#include "tel_ril_base.h"
#include "i_tel_ril_manager.h"

namespace OHOS {
class TelRilCall : public TelRilBase {
public:
    TelRilCall(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);

    ~TelRilCall() = default;

    /**
     * @brief Get current Calls
     */
    void GetCallList(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Calling Dial by UusInformation
     *
     * @param string address
     * @param int clirMode
     * @param UusInformation *uusInformation
     */
    void Dial(std::string address, int clirMode, struct UusInformation *uusInformation,
        const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief  Reject the Call
     */
    void Reject(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hang up the call
     *
     *  @param :int32_t gsmIndex
     */
    void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result);

    void Answer(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Call Status Change response
     *
     * @param data is HDF service callback message
     */
    void CallStateUpdated(OHOS::MessageParcel &data);

    /**
     * @brief Answering a call response
     *
     * @param data is HDF service callback message
     */
    void AnswerResponse(OHOS::MessageParcel &data);

    /**
     * @brief Get current call information
     *
     * @param data is HDF service callback message
     */
    void GetCallListResponse(OHOS::MessageParcel &data);

    /**
     * @brief Initiate call response
     *
     * @param data is HDF service callback message
     */
    void DialResponse(OHOS::MessageParcel &data);

    /**
     * @brief Hang up response
     *
     * @param data is HDF service callback message
     */
    void HangupResponse(OHOS::MessageParcel &data);

    /**
     * @brief Reject call response
     *
     * @param data is HDF service callback message
     */
    void RejectResponse(OHOS::MessageParcel &data);

    /**
     * @brief Get the last call failure reason response
     *
     * @param data is HDF service callback message
     */
    void GetLastCallErrorCodeResponse(OHOS::MessageParcel &data);

    bool IsCallRespOrNotify(uint32_t code);

    void ProcessCallRespOrNotify(uint32_t code, OHOS::MessageParcel &data);

private:
    bool IsCallResponse(uint32_t code);
    bool IsCallNotification(uint32_t code);
    void AddHandlerToMap();

private:
    bool testingEmergencyCall_ = false;
    using Func = void (TelRilCall::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace OHOS
#endif // TEL_RIL_CALL_H

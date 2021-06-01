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

#ifndef CELLULAR_CALL_INTERFACE_H
#define CELLULAR_CALL_INTERFACE_H
#include "cellular_call_types.h"
#include "i_call_status_callback.h"

namespace OHOS {
namespace CellularCall {
class CellularCallInterface : public IRemoteBroker {
public:
    // operation type
    enum {
        DIAL = 1,
        END = 2,
        REJECT = 3,
        ANSWER = 4,
        EMERGENCY_CALL = 5,
        REGISTER_CALLBACK = 6,
        UNREGISTER_CALLBACK = 7,
    };

    /**
     * Call management dial interface
     *
     * @param CellularCall, dial param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int Dial(const CellularCallInfo &dialInfo) = 0;

    /**
     * End.
     *
     * @param CallInfo, End param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int End(const CellularCallInfo &dialInfo) = 0;

    /**
     * Answer.
     *
     * @param CallInfo, Answer param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int Answer(const CellularCallInfo &dialInfo) = 0;

    /**
     * Reject.
     *
     * @param CallInfo, Reject param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int Reject(const CellularCallInfo &dialInfo) = 0;

    /**
     * Is it an emergency call
     * @param string &phoneNum
     * @param slotId
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int IsUrgentCall(const std::string &phoneNum, int32_t slotId) = 0;

    /**
     * Register CallBack
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int RegisterCallManagerCallBack(const sptr<TelephonyCallManager::ICallStatusCallback> &callback) = 0;

    /**
     * UnRegister CallBack
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    virtual int UnRegisterCallManagerCallBack() = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ipc.CellularCallInterface");
};
} // namespace CellularCall
} // namespace OHOS
#endif // CELLULAR_CALL_INTERFACE_H

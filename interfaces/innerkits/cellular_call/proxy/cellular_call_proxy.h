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

#ifndef CELLULAR_CALL_PROXY_H
#define CELLULAR_CALL_PROXY_H

#include "cellular_call_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace CellularCall {
class CellularCallProxy : public IRemoteProxy<CellularCallInterface> {
public:
    /**
     * CellularCallProxy
     *
     * @param impl
     */
    explicit CellularCallProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<CellularCallInterface>(impl) {}

    ~CellularCallProxy() = default;

    /**
     * Call management dial interface
     *
     * @param CellularCallInfo, dial param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int Dial(const CellularCallInfo &callInfo) override;

    /**
     * End.
     *
     * @param CellularCallInfo, End param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int End(const CellularCallInfo &callInfo) override;

    /**
     * Reject.
     *
     * @param CellularCallInfo, Reject param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int Reject(const CellularCallInfo &callInfo) override;

    /**
     * Answer.
     *
     * @param CellularCallInfo, Answer param.
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int Answer(const CellularCallInfo &callInfo) override;

    /**
     * @brief Is it an emergency call
     * @param string &phoneNum
     * @param slotId
     * @return bool
     */
    int IsUrgentCall(const std::string &phoneNum, int32_t slotId) override;

    /**
     * RegisterCallBack
     *
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int RegisterCallManagerCallBack(const sptr<TelephonyCallManager::ICallStatusCallback> &callback) override;

    /**
     * UnRegister CallBack
     * @return Returns TELEPHONY_NO_ERROR on success, others on failure.
     */
    int UnRegisterCallManagerCallBack() override;

private:
    static inline BrokerDelegator<CellularCallProxy> delegator_;
};
} // namespace CellularCall
} // namespace OHOS
#endif // CELLULAR_CALL_PROXY_H

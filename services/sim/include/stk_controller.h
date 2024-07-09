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

#ifndef OHOS_STK_CONTROLLER_H
#define OHOS_STK_CONTROLLER_H

#include "i_tel_ril_manager.h"
#include "inner_event.h"
#include "sim_state_manager.h"
#include "tel_event_handler.h"
#include "want.h"

#define STK_CMD_TYPE_INDEX 10
#define STK_CMD_TYPE_LEN 2
#define STK_BIP_CMD_OPEN_CHANNEL "40"
#define STK_BIP_CMD_SEND_DATA "43"
#define STK_BIP_CMD_RECEVIE_DATA "42"
#define STK_BIP_CMD_GET_CHANNEL_STATUS "44"
#define STK_BIP_CMD_CLOSE_CHANNEL "41"

namespace OHOS {
namespace Telephony {
class StkController : public TelEventHandler {
public:
    explicit StkController(const std::weak_ptr<Telephony::ITelRilManager> &telRilManager,
        const std::weak_ptr<Telephony::SimStateManager> &simStateManager, int32_t slotId);
    virtual ~StkController() = default;
    void Init();
    std::string initStkBudleName();
    int32_t SendTerminalResponseCmd(const std::string &strCmd);
    int32_t SendEnvelopeCmd(const std::string &strCmd);
    int32_t SendCallSetupRequestResult(bool accept);
    void UnRegisterEvents();

public:
    enum {
        RETRY_SEND_RIL_PROACTIVE_COMMAND = 0,
    };

private:
    void RegisterEvents();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void OnIccStateChanged(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendRilSessionEnd(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendRilProactiveCommand(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendRilAlphaNotify(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendRilEventNotify(const AppExecFwk::InnerEvent::Pointer &event);
    void OnIccRefresh(const AppExecFwk::InnerEvent::Pointer &event);
    bool PublishStkEvent(AAFwk::Want &want);
    void OnSendTerminalResponseResult(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendEnvelopeCmdResult(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendCallSetupRequestResult(const AppExecFwk::InnerEvent::Pointer &event);
    bool CheckIsSystemApp(const std::string &bundleName);
    bool CheckIsBipCmd(const std::string &cmdData);
    sptr<OHOS::IRemoteObject> GetBundleMgr();
    void RetrySendRilProactiveCommand();

private:
    std::weak_ptr<Telephony::ITelRilManager> telRilManager_;
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    int slotId_ = 0;
    int32_t iccCardState_ = 0;
    int32_t envelopeResponseResult_ = 0;
    int32_t terminalResponseResult_ = 0;
    int32_t callSetupResponseResult_ = 0;
    bool responseFinished_ = false;
    std::string stkBundleName_ = "";
    std::mutex stkMutex_;
    std::condition_variable stkCv_;
    AAFwk::Want retryWant_;
    int32_t remainTryCount_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_STK_CONTROLLER_H

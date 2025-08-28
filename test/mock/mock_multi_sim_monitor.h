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

#ifndef OHOS_MULTI_SIM_MONITOR_MOCK_H
#define OHOS_MULTI_SIM_MONITOR_MOCK_H

#include <list>
#include <ffrt.h>

#include <gmock/gmock.h>
#include "common_event_subscriber.h"
#include "iservice_registry.h"
#include "multi_sim_controller.h"
#include "os_account_manager_wrapper.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"
#include "telephony_state_registry_client.h"
#include "multi_sim_monitor.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
class MultiSimMonitorMock : public MultiSimMonitor {
public:
    explicit MultiSimMonitorMock(const std::shared_ptr<MultiSimController> &controller,
        std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
        std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager);
    ~MultiSimMonitorMock();

    MOCK_METHOD0(Init, void());
    MOCK_METHOD2(AddExtraManagers, void(std::shared_ptr<Telephony::SimStateManager> simStateManager,
        std::shared_ptr<Telephony::SimFileManager> simFileManager));
    MOCK_METHOD3(
        RegisterCoreNotify, void(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what));
    MOCK_METHOD2(RegisterSimAccountCallback, int32_t(const int32_t tokenId, const sptr<SimAccountCallback> &callback));
    MOCK_METHOD1(UnregisterSimAccountCallback, int32_t(const sptr<SimAccountCallback> &callback));
    MOCK_METHOD0(NotifySimAccountChanged, void());
    MOCK_METHOD0(RegisterSimNotify, void());
    MOCK_METHOD1(RegisterSimNotify, void(int32_t slotId));
    MOCK_METHOD0(UnRegisterSimNotify, void());
    MOCK_METHOD1(ResetSimLoadAccount, int32_t(int32_t slotId));
    MOCK_METHOD1(IsVSimSlotId, bool(int32_t slotId));
    MOCK_METHOD1(ProcessEvent, void(const AppExecFwk::InnerEvent::Pointer &event));
    MOCK_METHOD1(RefreshData, void(int32_t slotId));
    MOCK_METHOD1(InitData, void(int32_t slotId));
    MOCK_METHOD0(InitEsimData, void());
    MOCK_METHOD1(IsValidSlotId, bool(int32_t slotId));
    MOCK_METHOD0(GetSimAccountCallbackRecords, std::list<SimAccountCallbackRecord>());
    MOCK_METHOD0(InitListener, void());
    MOCK_METHOD0(SubscribeDataShareReady, void());
    MOCK_METHOD0(SubscribeUserSwitch, void());
    MOCK_METHOD0(SubscribeBundleScanFinished, void());
    MOCK_METHOD0(UnSubscribeListeners, void());
    MOCK_METHOD1(CheckOpcNeedUpdata, void(const bool isDataShareError));
    MOCK_METHOD0(CheckUpdateOpcVersion, int32_t());
    MOCK_METHOD0(UpdateAllOpkeyConfigs, void());
    MOCK_METHOD0(CheckDataShareError, void());
    MOCK_METHOD0(CheckSimNotifyRegister, void());
    MOCK_METHOD1(SetRemainCount, void(int remainCount));
    MOCK_METHOD1(SetBlockLoadOperatorConfig, void(bool isBlockLoadOperatorConfig));
    MOCK_METHOD0(GetBlockLoadOperatorConfig, void());
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_MULTI_SIM_MONITOR_MOCK_H
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
#ifndef OHOS_NS_MANAGER_H
#define OHOS_NS_MANAGER_H
#include <memory>
#include "phone_manager.h"
#include "i_network_search.h"
#include "network_search_notify.h"
#include "observer_handler.h"
#include "network_search_state.h"
#include "network_search_handler.h"

namespace OHOS {
enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };
class NetworkSearchManager : public INetworkSearch, public std::enable_shared_from_this<NetworkSearchManager> {
public:
    NetworkSearchManager();
    virtual ~NetworkSearchManager() = default;
    void Init() override;
    std::shared_ptr<NetworkSearchState> GetNetworkSearchState() const;

    /**
     * Set radio state
     * 27007-410_2001 8.2 Set phone functionality +CFUN
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void SetHRilRadioState(bool isOn) override;
    ModemPowerState GetRilHRilRadioState();
    int32_t GetPsRadioTech(int32_t slotId) override;
    int32_t GetCsRadioTech(int32_t slotId) override;
    std::u16string GetOperatorNumeric(int32_t slotId) override;
    std::u16string GetOperatorName(int32_t slotId) override;
    sptr<NetworkState> GetNetworkStatus(int32_t slotId) override;
    bool GetRadioState(int32_t slotId) override;
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) override;
    void RegisterForPSConnectionAttached(const HANDLE &handler) override;
    void UnregisterForPSConnectionAttached(const HANDLE &handler) override;
    void RegisterForPSConnectionDetached(const HANDLE &handler) override;
    void UnregisterForPSConnectionDetached(const HANDLE &handler) override;
    void NotifyPSConnectionAttachedChanged();
    void NotifyPSConnectionDetachedChanged();

private:
    std::shared_ptr<NetworkSearchState> networkSearchState_;
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_;
    std::shared_ptr<SIM::ISimFileManager> simFileManager_;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_;
    std::unique_ptr<ObserverHandler> observerHandler_;
    HandleRunningState state_;
};
} // namespace OHOS
#endif // OHOS_NS_MANAGER_H

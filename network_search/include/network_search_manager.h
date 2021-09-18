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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H

#include <memory>
#include "i_network_search.h"
#include "network_search_notify.h"
#include "observer_handler.h"
#include "network_search_state.h"
#include "network_search_handler.h"
#include "network_search_result.h"
#include "event_handler.h"

namespace OHOS {
namespace Telephony {
struct NetworkSearchCallbackInfo {
    int32_t param_;
    sptr<INetworkSearchCallback> networkSearchCacheItem_;

    NetworkSearchCallbackInfo(int32_t param, sptr<INetworkSearchCallback> networkSearchItem)
    {
        param_ = param;
        networkSearchCacheItem_ = networkSearchItem;
    }
};

enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };
class NetworkSearchManager : public INetworkSearch, public std::enable_shared_from_this<NetworkSearchManager> {
public:
    NetworkSearchManager(std::shared_ptr<IRilManager> rilManager,
        std::shared_ptr<ISimStateManager> simStateManager, std::shared_ptr<ISimFileManager> simFileManager);
    virtual ~NetworkSearchManager() = default;
    void Init() override;
    std::shared_ptr<NetworkSearchState> GetNetworkSearchState() const;
    std::shared_ptr<ISimFileManager> GetSimFileManager() const;
    std::shared_ptr<IRilManager> GetRilManager() const;
    std::shared_ptr<ISimStateManager> GetSimStateManager() const;

    /**
     * Set radio state
     * 27007-410_2001 8.2 Set phone functionality +CFUN
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void SetRadioState(bool isOn, int32_t rst) override;
    bool SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback) override;
    int32_t GetRadioState() const override;
    bool GetRadioState(const sptr<INetworkSearchCallback> &callback) override;
    int32_t GetPsRadioTech(int32_t slotId) const override;
    int32_t GetCsRadioTech(int32_t slotId) const override;
    std::u16string GetOperatorNumeric(int32_t slotId) const override;
    std::u16string GetOperatorName(int32_t slotId) const override;
    sptr<NetworkState> GetNetworkStatus(int32_t slotId) const override;
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) const override;
    void RegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) override;
    void UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what) override;
    void NotifyPSRoamingOpenChanged();
    void NotifyPSRoamingCloseChanged();
    void NotifyPSConnectionAttachedChanged();
    void NotifyPSConnectionDetachedChanged();
    bool GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    void SetNetworkSearchResultValue(int32_t listSize, std::vector<NetworkInformation> &operatorInfo);
    sptr<NetworkSearchResult> GetNetworkSearchResultValue() const;
    int32_t GetNetworkSelectionMode(int32_t slotId) const;
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override;
    void SetRadioStatusValue(ModemPowerState radioStatus);
    ModemPowerState GetRadioStatusValue() const;
    void SetNetworkSelectionValue(SelectionMode selection);
    bool AddNetworkSearchCallBack(int64_t, std::shared_ptr<NetworkSearchCallbackInfo> &callback);
    std::shared_ptr<NetworkSearchCallbackInfo> FindNetworkSearchCallback(int64_t index);
    bool RemoveCallbackFromMap(int64_t index);
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) const override;

private:
    int64_t GetCallbackIndex64bit();

private:
    const int MCC_LEN = 3;
    const int64_t MAX_INDEX = 100000000;
    std::shared_ptr<IRilManager> rilManager_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    HandleRunningState state_ = HandleRunningState::STATE_NOT_START;
    std::unique_ptr<NetworkSearchResult> networkSearchResult_ = nullptr;
    SelectionMode selection_ = MODE_TYPE_UNKNOWN;
    ModemPowerState radioStatus_ = CORE_SERVICE_POWER_OFF;
    std::unordered_map<int64_t, std::shared_ptr<NetworkSearchCallbackInfo>> networkSearchCacheMap_;
    std::mutex callbackMapMutex_;
    std::atomic<int64_t> callbackIndex64bit_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H

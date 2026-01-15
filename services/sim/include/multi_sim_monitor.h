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

#ifndef OHOS_MULTI_SIM_MONITOR_H
#define OHOS_MULTI_SIM_MONITOR_H

#include <list>
#include <ffrt.h>

#include "iservice_registry.h"
#include "i_operator_config_hisysevent.h"
#include "multi_sim_controller.h"
#include "os_account_manager_wrapper.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"
#include "telephony_state_registry_client.h"
#include "core_service_common_event_callback.h"

namespace OHOS {
namespace Telephony {
typedef void (*ParameterChgPtr)(const char *, const char *, void *);
class MultiSimMonitor : public TelEventHandler {
public:
    explicit MultiSimMonitor(const std::shared_ptr<MultiSimController> &controller,
        std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
        std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager);
    ~MultiSimMonitor();

    void Init();
    void AddExtraManagers(std::shared_ptr<Telephony::SimStateManager> simStateManager,
        std::shared_ptr<Telephony::SimFileManager> simFileManager);
    void RegisterCoreNotify(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    int32_t RegisterSimAccountCallback(const int32_t tokenId, const sptr<SimAccountCallback> &callback);
    int32_t UnregisterSimAccountCallback(const sptr<SimAccountCallback> &callback);
    void NotifySimAccountChanged();
    void RegisterSimNotify();
    void RegisterSimNotify(int32_t slotId);
    void UnRegisterSimNotify();
    int32_t ResetSimLoadAccount(int32_t slotId);
    bool IsVSimSlotId(int32_t slotId);
    void SetLastUserId(int32_t userId);
    void UpdateAllSimData(int32_t userId);
    void OnUserSwitched(int32_t userId);
    void CheckSimPresentWhenReboot();
    inline void SetOperatorConfigHisysevent(std::weak_ptr<IOperatorConfigHisysevent> operatorConfigHisysevent)
    {
        operatorConfigHisysevent_ = operatorConfigHisysevent;
    };

public:
    enum {
        REGISTER_SIM_NOTIFY_EVENT = 0,
        RESET_OPKEY_CONFIG,
        REGISTER_SIM_NOTIFY_RETRY_EVENT,
        INIT_DATA_RETRY_EVENT,
        RETRY_RESET_OPKEY_CONFIG,
        INIT_ESIM_DATA_RETRY_EVENT,
        INIT_ESIM_DATA_EVENT,
        INIT_REBOOT_DETECT_DATA_EVENT,
        INIT_REBOOT_DETECT_DATA_RETRY_EVENT,
    };

private:
    struct SimAccountCallbackRecord {
        int32_t tokenId = 0;
        sptr<SimAccountCallback> simAccountCallback = nullptr;
    };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};

private:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessEventEx(const AppExecFwk::InnerEvent::Pointer &event);
    void RefreshData(int32_t slotId);
    void InitData(int32_t slotId);
    void InitEsimData();
    bool IsValidSlotId(int32_t slotId);
    std::list<SimAccountCallbackRecord> GetSimAccountCallbackRecords();
    void InitListener();
    void SubscribeDataShareReady();
    void SubscribeUserSwitch();
    void SubscribeBundleScanFinished();
    void UnSubscribeListeners();
    void CheckOpcNeedUpdata(const bool isDataShareError);
    int32_t CheckUpdateOpcVersion();
    void UpdateAllOpkeyConfigs();
    void CheckDataShareError();
    void CheckSimNotifyRegister();
    void SetRemainCount(int remainCount);
    void SetBlockLoadOperatorConfig(bool isBlockLoadOperatorConfig);
    bool GetBlockLoadOperatorConfig();
    void UpdateSimStateToStateRegistry();
    void RegisterRebootDetectCallback();
    void UnregisterRebootDetectCallback();
    void SetMatchSimStateTracker(MatchSimState matchSimStateTracker);

private:
    class DataShareEventSubscriber : public CoreServiceCommonEventCallback {
    public:
        explicit DataShareEventSubscriber(std::shared_ptr<AppExecFwk::EventHandler> handler)
            : handler_(handler) {};
        ~DataShareEventSubscriber() = default;
        void OnDataShareReady() override;
        std::weak_ptr<AppExecFwk::EventHandler> handler_;
    };

    class UserSwitchEventSubscriber : public CoreServiceCommonEventCallback {
    public:
        explicit UserSwitchEventSubscriber(std::shared_ptr<AppExecFwk::EventHandler> handler)
            : handler_(handler) {};
        ~UserSwitchEventSubscriber() = default;
        void OnUserSwitched(int32_t userId) override;
        std::weak_ptr<AppExecFwk::EventHandler> handler_;
    };

    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(std::shared_ptr<AppExecFwk::EventHandler> handler)
            : handler_(handler) {};
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    
    private:
        std::weak_ptr<AppExecFwk::EventHandler> handler_;
    };

private:
    static constexpr const int SLOT_COUNT = 2;
    bool hasCheckedSimPresent_[SLOT_COUNT] = {false, false};
    std::vector<int> initRebootDetectRemainCount_;
    std::shared_ptr<MultiSimController> controller_ = nullptr;
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_;
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager_;
    std::vector<int> isSimAccountLoaded_;
    bool isAllSimAccountLoaded_ = false;
    std::vector<int> initDataRemainCount_;
    int initEsimDataRemainCount_ = 0;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    std::list<SimAccountCallbackRecord> listSimAccountCallbackRecord_;
    std::shared_ptr<DataShareEventSubscriber> dataShareSubscriber_ = nullptr;
    std::shared_ptr<UserSwitchEventSubscriber> userSwitchSubscriber_ = nullptr;
    std::weak_ptr<IOperatorConfigHisysevent> operatorConfigHisysevent_{};
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    ParameterChgPtr parameterChgPtr_ = nullptr;
    std::mutex mutexInner_;
    std::mutex mutexForData_;
    std::atomic<int32_t> remainCount_ = 15;
    int32_t maxSlotCount_ = 0;
    bool isDataShareReady_ = false;
    bool isForgetAllDataDone_ = false;
    ffrt::shared_mutex simStateMgrMutex_;
    std::atomic<int32_t> lastUserId_ = -1;
    bool isUserSwitch_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIM_MONITOR_H

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

#include <tuple>
#include <map>
#include <any>
#include <string>

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
    sptr<INetworkSearchCallback> networkSearchItem_;

    NetworkSearchCallbackInfo(int32_t param, sptr<INetworkSearchCallback> callback)
    {
        param_ = param;
        networkSearchItem_ = callback;
    }
};

enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };

enum class PreferredNetwork {
    CORE_NETWORK_MODE_AUTO,
    CORE_NETWORK_MODE_GSM,
    CORE_NETWORK_MODE_WCDMA,
    CORE_NETWORK_MODE_LTE,
    CORE_NETWORK_MODE_LTE_WCDMA,
    CORE_NETWORK_MODE_LTE_WCDMA_GSM,
    CORE_NETWORK_MODE_WCDMA_GSM
};

/**
 * @brief manager class of network search module .The main entrance to the module.
 *
 */
class NetworkSearchManager : public INetworkSearch, public std::enable_shared_from_this<NetworkSearchManager> {
public:
    NetworkSearchManager(std::shared_ptr<ITelRilManager> telRilManager,
        std::shared_ptr<ISimStateManager> simStateManager, std::shared_ptr<ISimFileManager> simFileManager);
    virtual ~NetworkSearchManager() = default;
    void Init() override;
    std::shared_ptr<NetworkSearchState> GetNetworkSearchState() const;
    std::shared_ptr<ISimFileManager> GetSimFileManager() const;
    std::shared_ptr<ITelRilManager> GetRilManager() const;
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
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what) override;
    void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what) override;
    void NotifyPsRoamingOpenChanged();
    void NotifyPsRoamingCloseChanged();
    void NotifyPsConnectionAttachedChanged();
    void NotifyPsConnectionDetachedChanged();
    void NotifyPsRatChanged();
    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    void NotifyImsRegStateChanged();
    void SetNetworkSearchResultValue(int32_t listSize, std::vector<NetworkInformation> &operatorInfo);
    sptr<NetworkSearchResult> GetNetworkSearchInformationValue() const;
    int32_t GetNetworkSelectionMode(int32_t slotId);
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) override;
    void SetRadioStateValue(ModemPowerState radioState);
    ModemPowerState GetRadioStateValue() const;
    void SetNetworkSelectionValue(SelectionMode selection);
    bool AddNetworkSearchCallBack(int64_t, std::shared_ptr<NetworkSearchCallbackInfo> &callback);
    std::shared_ptr<NetworkSearchCallbackInfo> FindNetworkSearchCallback(int64_t index);
    bool RemoveCallbackFromMap(int64_t index);
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) const override;
    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) override;
    bool SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) override;
    bool GetPreferredNetwork(int32_t slotId);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode);
    void SavePreferredNetworkValue(int32_t slotId, int32_t networkMode);
    int32_t GetPreferredNetworkValue(int32_t slotId) const;
    void UpdatePhone(RadioTech csRadioTech) const;
    int32_t GetPsRegState(int32_t slotId) const override;
    int32_t GetPsRoamingState(int32_t slotId) const override;
    void SetImei(std::u16string imei);
    std::u16string GetImei(int32_t slotId) override;
    bool SetPsAttachStatus(
        int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback) override;
    bool GetImsRegStatus() override;
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) override;
    bool SendUpdateCellLocationRequest() override;
    void UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac);
    void InitMsgNum()
    {
        msgNum_ = MSG_NUM;
    }
    bool CheckIsNeedNotify()
    {
        return msgNum_ == 0 ? true : false;
    }
    void decMsgNum()
    {
        msgNum_--;
    }

private:
    int64_t GetCallbackIndex64bit();

private:
    const int32_t MCC_LEN = 3;
    const int64_t MAX_INDEX = 100000000;
    const int32_t MSG_NUM = 3;
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    HandleRunningState state_ = HandleRunningState::STATE_NOT_START;
    std::unique_ptr<NetworkSearchResult> networkSearchResult_ = nullptr;
    SelectionMode selection_ = SelectionMode::MODE_TYPE_UNKNOWN;
    ModemPowerState radioState_ = ModemPowerState::CORE_SERVICE_POWER_OFF;
    std::unordered_map<int64_t, std::shared_ptr<NetworkSearchCallbackInfo>> networkSearchCacheMap_;
    std::mutex callbackMapMutex_;
    std::atomic<int64_t> callbackIndex64bit_ = 0;
    const std::string KEY_DEFAULT_PREFERRED_NETWORK_MODE = "preferred_network_mode";
    std::u16string imei_;
    int32_t msgNum_ = 0;

    /**
     * @brief Get the Event object
     *
     * @param handlerId see ObserverHandler
     * @param param parameter of class NetworkSearchCallbackInfo
     * @param callback strong pointer class to class INetworkSearchCallback
     * @return AppExecFwk::InnerEvent::Pointer
     */
    AppExecFwk::InnerEvent::Pointer GetEvent(
        ObserverHandler::ObserverHandlerId handlerId, int32_t param, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief function pointer of class ITelRilManager.
     *
     */
    using RilFuncPointer1 = void (ITelRilManager::*)(const AppExecFwk::InnerEvent::Pointer &);
    using RilFuncPointer2 = void (ITelRilManager::*)(int32_t, const AppExecFwk::InnerEvent::Pointer &);
    using RilFuncPointer3 = void (ITelRilManager::*)(int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &);
    using RilFuncPointer4 = void (ITelRilManager::*)(int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &);

    /**
     * @brief Mode of getting event .HandlerId is necessary , index and param are optional.see details in
     * AppExecFwk::InnerEvent::Get().
     *
     */
    enum class EventGetMode {
        /**
         * @brief AppExecFwk::InnerEvent::Get(handlerId)
         *
         */
        GET_EVENT_BY_HANDLERID,
        /**
         * @brief AppExecFwk::InnerEvent::Get(handlerId,index)
         *
         */
        GET_EVENT_BY_INDEX,
        /**
         * @brief AppExecFwk::InnerEvent::Get(handlerId,param)
         *
         */
        GET_EVENT_BY_PARAM,
    };

    /**
     * @brief Send event to model of TelRilManager
     *
     * @tparam eventGetMode see EventGetType.
     * @tparam T pointer  type of class ITelRilManager's function. see
     * RilFuncPointer1,RilFuncPointer2,RilFuncPointer3,RilFuncPointer4.
     * @tparam Args Variable parameters types.
     * @param parameters tuple of input parameters.
     * @param args parameters for function calling.
     * @return true success
     * @return false fail
     */
    template<EventGetMode eventGetMode, typename T, typename... Args>
    bool SendEventToRil(
        std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, T> &parameters,
        Args... args)
    {
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager nullptr");
            return false;
        }
        ObserverHandler::ObserverHandlerId handlerId = ObserverHandler::ObserverHandlerId::RADIO_STATE_CHANGED;
        int32_t param = 0;
        const sptr<INetworkSearchCallback> *callback = nullptr;
        T rilFuncPointer = nullptr;
        std::tie(handlerId, param, callback, rilFuncPointer) = parameters;
        if (rilFuncPointer == nullptr) {
            TELEPHONY_LOGE("rilFuncPointer nullptr");
            return false;
        }
        AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
        switch (eventGetMode) {
            case EventGetMode::GET_EVENT_BY_HANDLERID: {
                event = AppExecFwk::InnerEvent::Get(static_cast<int32_t>(handlerId));
                break;
            }
            case EventGetMode::GET_EVENT_BY_INDEX: {
                if (callback == nullptr) {
                    TELEPHONY_LOGE("callback nullptr");
                    return false;
                }
                event = GetEvent(handlerId, param, *callback);
                break;
            }
            case EventGetMode::GET_EVENT_BY_PARAM: {
                event = AppExecFwk::InnerEvent::Get(static_cast<int32_t>(handlerId), param);
                break;
            }
            default:
                return false;
        }
        if (event == nullptr) {
            TELEPHONY_LOGE("event nullptr");
            return false;
        }
        event->SetOwner(networkSearchHandler_);
        (telRilManager_.get()->*rilFuncPointer)(args..., event);
        return true;
    };

    /**
     * @brief send event to RilBaseManager
     *
     * @param handlerId see ObserverHandler
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId);
    /**
     * @brief send event to RilBaseManager
     *
     * @param handlerId see ObserverHandler
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, int32_t param);
    /**
     * @brief send event to RilBaseManager
     *
     * @param handlerId see ObserverHandler
     * @param param1 used for get event and call function
     * @param param2 used for call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, int32_t param1, int32_t param2);
    /**
     * @brief send event to RilBaseManager
     *
     * @param handlerId see ObserverHandler
     * @param param1 used for get event and call function
     * @param param2 used for call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, int32_t param1, std::string param2);

    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param handlerId see ObserverHandler
     * @param callback pointer to callback interface
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback(
        ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback);
    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param handlerId see ObserverHandler
     * @param callback pointer to callback interface
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback(
        ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback, int32_t param);
    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param handlerId see ObserverHandler
     * @param callback pointer to callback interface
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback2(
        ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback, int32_t param);
    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param handlerId see ObserverHandler
     * @param callback pointer to callback interface
     * @param param1 used for get event and param of fun
     * @param param2 param of fun
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
        const sptr<INetworkSearchCallback> *callback, int32_t param1, int32_t param2);
    /**
     * @brief
     *
     * @param handlerId see ObserverHandler
     * @param callback pointer to callback interface
     * @param param1 param of fun
     * @param param2 param of fun
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
        const sptr<INetworkSearchCallback> *callback, int32_t param1, std::string param2);

    /**
     * @brief map of function pointer
     *
     */
    std::map<ObserverHandler::ObserverHandlerId, std::any> mapRilFunctionPointer_;
    /**
     * @brief initialization map of TelRilManager's function pointer
     *
     */
    void InitRilFunctionPointerMap();
    /**
     * @brief Get the Ril Function Pointer From Map
     *
     * @tparam T function pointer type. see RilFuncPointer1, RilFuncPointer2, RilFuncPointer3, RilFuncPointer4
     * @param handlerId see ObserverHandler
     * @return T function pointer . if not found , it is nullptr
     */
    template<typename T>
    T GetRilFunctionPointer(ObserverHandler::ObserverHandlerId handlerId)
    {
        auto itFunc = mapRilFunctionPointer_.find(handlerId);
        if (itFunc != mapRilFunctionPointer_.end()) {
            return std::any_cast<T>(itFunc->second);
        }
        return nullptr;
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H

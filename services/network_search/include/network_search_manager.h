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
#include "i_tel_ril_manager.h"
#include "network_search_notify.h"
#include "observer_handler.h"
#include "network_search_state.h"
#include "network_search_handler.h"
#include "network_search_result.h"
#include "event_handler.h"
#include "resource_utils.h"

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
    CORE_NETWORK_MODE_AUTO = 0,
    CORE_NETWORK_MODE_GSM = 1,
    CORE_NETWORK_MODE_WCDMA = 2,
    CORE_NETWORK_MODE_LTE = 3,
    CORE_NETWORK_MODE_LTE_WCDMA = 4,
    CORE_NETWORK_MODE_LTE_WCDMA_GSM = 5,
    CORE_NETWORK_MODE_WCDMA_GSM = 6,
    CORE_NETWORK_MODE_CDMA = 7,
    CORE_NETWORK_MODE_EVDO = 8,
    CORE_NETWORK_MODE_EVDO_CDMA = 9,
    CORE_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA = 10,
    CORE_NETWORK_MODE_LTE_EVDO_CDMA = 11,
    CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA = 12,
    CORE_NETWORK_MODE_TDSCDMA = 13,
    CORE_NETWORK_MODE_TDSCDMA_GSM = 14,
    CORE_NETWORK_MODE_TDSCDMA_WCDMA = 15,
    CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM = 16,
    CORE_NETWORK_MODE_LTE_TDSCDMA = 17,
    CORE_NETWORK_MODE_LTE_TDSCDMA_GSM = 18,
    CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA = 19,
    CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM = 20,
    CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 21,
    CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 22,
    CORE_NETWORK_MODE_NR = 31,
    CORE_NETWORK_MODE_NR_LTE = 32,
    CORE_NETWORK_MODE_NR_LTE_WCDMA = 33,
    CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM = 34,
    CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA = 35,
    CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA = 36,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA = 37,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM = 38,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA = 39,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM = 40,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 41,
    CORE_NETWORK_MODE_MAX_VALUE = 99,
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
    static inline ResourceUtils *GetResourceUtils()
    {
        static ResourceUtils utils_;
        if (!utils_.Init(RESOURCE_INDEX_PATH)) {
            TELEPHONY_LOGE("NetworkSearchManager::GetResourceUtils init failed.");
        }
        return &utils_;
    };
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

    void RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) override;

    void NotifyPsRoamingOpenChanged();
    void NotifyPsRoamingCloseChanged();
    void NotifyPsConnectionAttachedChanged();
    void NotifyPsConnectionDetachedChanged();
    void NotifyPsRatChanged();
    void NotifyEmergencyOpenChanged();
    void NotifyEmergencyCloseChanged();
    void NotifyNrStateChanged();
    void NotifyNrFrequencyChanged();
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
    void UpdatePhone(RadioTech csRadioTech);
    int32_t GetPsRegState(int32_t slotId) const override;
    int32_t GetCsRegState(int32_t slotId) const override;
    int32_t GetPsRoamingState(int32_t slotId) const override;
    void SetImei(std::u16string imei);
    std::u16string GetImei(int32_t slotId) override;
    bool SetPsAttachStatus(
        int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback) override;
    bool GetImsRegStatus() override;
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) override;
    bool SendUpdateCellLocationRequest() override;
    sptr<CellLocation> GetCellLocation(int32_t slotId) const override;
    void UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac);
    PhoneType GetPhoneType() const override;
    inline bool GetAirplaneMode()
    {
        return AirplaneMode_;
    }
    inline void InitMsgNum()
    {
        msgNum_ = MSG_NUM;
    }
    inline bool CheckIsNeedNotify()
    {
        return msgNum_ == 0 ? true : false;
    }
    inline void decMsgNum()
    {
        msgNum_--;
    }
    void SetMeid(std::u16string meid);
    std::u16string GetMeid(int32_t slotId) override;
    std::u16string GetUniqueDeviceId(int32_t slotId) const override;
    bool IsNrSupported() override;
    inline void SetCapability(int32_t slotId, RadioCapabilityInfo &radioCapability)
    {
        radioCapability_ = radioCapability;
    }
    int32_t GetRadioCapability(int32_t slotId);
    bool SetRadioCapability(int32_t slotId, RadioCapabilityInfo &radioCapability);
    void SetNrOptionMode(NrMode mode);
    NrMode GetNrOptionMode(int32_t slotId) const override;
    void SetFrequencyType(FrequencyType type);
    FrequencyType GetFrequencyType(int32_t slotId) const override;
    NrState GetNrState(int32_t slotId) const override;
    void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive) override;
    void GetVoiceTech();
    
    sptr<NetworkSearchCallBackBase> GetCellularDataCallBack()
    {
        return cellularDataCallBack_;
    }
    sptr<NetworkSearchCallBackBase> GetCellularCallCallBack()
    {
        return cellularCallCallBack_;
    }
private:
    int64_t GetCallbackIndex64bit();
    bool InitPointer();

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
    ModemPowerState radioState_ = CORE_SERVICE_POWER_OFF;
    bool AirplaneMode_ = false;
    std::unordered_map<int64_t, std::shared_ptr<NetworkSearchCallbackInfo>> networkSearchCacheMap_;
    std::mutex callbackMapMutex_;
    std::atomic<int64_t> callbackIndex64bit_ = 0;
    const std::string KEY_DEFAULT_PREFERRED_NETWORK_MODE = "preferred_network_mode";
    std::u16string imei_;
    int32_t msgNum_ = 0;
    std::u16string meid_;
    NrMode nrMode_ = NrMode::NR_MODE_UNKNOWN;
    FrequencyType freqType_ = FrequencyType::FREQ_TYPE_UNKNOWN;
    sptr<NetworkSearchCallBackBase> cellularDataCallBack_;
    sptr<NetworkSearchCallBackBase> cellularCallCallBack_;
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
    using RilFunc_Event = void (ITelRilManager::*)(const AppExecFwk::InnerEvent::Pointer &);
    using RilFunc_Int_Event = void (ITelRilManager::*)(int32_t, const AppExecFwk::InnerEvent::Pointer &);
    using RilFunc_Int_Int_Event = void (ITelRilManager::*)(
        int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &);
    using RilFunc_Int_String_Event = void (ITelRilManager::*)(
        int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &);
    using RilFunc_Capability_Event = void (ITelRilManager::*)(
        RadioCapabilityInfo &, const AppExecFwk::InnerEvent::Pointer &);

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
     * RilFunc_Event,RilFunc_Int_Event,RilFunc_Int_Int_Event,RilFunc_Int_String_Event,RilFunc_Capability_Event.
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
            TELEPHONY_LOGE("NetworkSearchManager::SendEventToRil telRilManager is null.");
            return false;
        }
        ObserverHandler::ObserverHandlerId handlerId = ObserverHandler::ObserverHandlerId::RADIO_STATE_CHANGED;
        int32_t param = 0;
        const sptr<INetworkSearchCallback> *callback = nullptr;
        T rilFuncPointer = nullptr;
        std::tie(handlerId, param, callback, rilFuncPointer) = parameters;
        if (rilFuncPointer == nullptr) {
            TELEPHONY_LOGE("NetworkSearchManager::SendEventToRil rilFuncPointer is null.");
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
                TELEPHONY_LOGE("NetworkSearchManager::SendEventToRil eventGetMode error.");
                return false;
        }
        if (event == nullptr) {
            TELEPHONY_LOGE("NetworkSearchManager::SendEventToRil event is null.");
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
     * @param param used for call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, RadioCapabilityInfo &param);

    /**
     * @brief send event to RilBaseManager
     *
     * @param handlerId see ObserverHandler
     * @param firstParam used for get event and call function
     * @param secondParam used for call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, int32_t firstParam, int32_t secondParam);

    /**
     * @brief send event to RilBaseManager
     *
     * @param handlerId see ObserverHandler
     * @param firstParam used for get event and call function
     * @param secondParam used for call function
     * @return true success
     * @return false fail
     */
    bool SendEventToRilBase(
        ObserverHandler::ObserverHandlerId handlerId, int32_t firstParam, std::string secondParam);

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
    bool SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
        const sptr<INetworkSearchCallback> *callback, RadioCapabilityInfo &param);

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
     * @param firstParam used for get event and param of fun
     * @param secondParam param of fun
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
        const sptr<INetworkSearchCallback> *callback, int32_t firstParam, int32_t secondParam);
    /**
     * @brief
     *
     * @param handlerId see ObserverHandler
     * @param callback pointer to callback interface
     * @param firstParam param of fun
     * @param secondParam param of fun
     * @return true success
     * @return false fail
     */
    bool SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
        const sptr<INetworkSearchCallback> *callback, int32_t firstParam, std::string secondParam);

    /**
     * @brief map of function pointer
     *
     */
    static const std::map<ObserverHandler::ObserverHandlerId, std::any> mapRilFunctionPointer_;

    /**
     * @brief Get the Ril Function Pointer From Map
     *
     * @tparam T function pointer type. see RilFunc_Event, RilFunc_Int_Event, RilFunc_Int_Int_Event,
     * RilFunc_Int_String_Event
     * @param handlerId see ObserverHandler
     * @return T function pointer . if not found , it is nullptr
     */
    template<typename T>
    static T GetRilFunctionPointer(ObserverHandler::ObserverHandlerId handlerId)
    {
        auto itFunc = mapRilFunctionPointer_.find(handlerId);
        if (itFunc != mapRilFunctionPointer_.end()) {
            TELEPHONY_LOGI("GetRilFunctionPointer find");
            return std::any_cast<T>(itFunc->second);
        }
        TELEPHONY_LOGI("GetRilFunctionPointer nullptr");
        return nullptr;
    }

    static const std::string RESOURCE_HAP_BUNDLE_NAME;
    static const std::string RESOURCE_INDEX_PATH;
    RadioCapabilityInfo radioCapability_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H

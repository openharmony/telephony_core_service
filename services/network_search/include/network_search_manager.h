/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <any>
#include <cinttypes>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <tuple>

#include "device_state_handler.h"
#include "device_state_observer.h"
#include "event_handler.h"
#include "i_network_search.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "iremote_stub.h"
#include "network_search_handler.h"
#include "network_search_notify.h"
#include "network_search_result.h"
#include "network_search_state.h"
#include "network_utils.h"
#include "observer_handler.h"
#include "radio_event.h"
#include "setting_utils.h"

namespace OHOS {
namespace Telephony {
enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };
/**
 * @brief inner objects for network search manager
 *
 */
struct NetworkSearchManagerInner {
    static const int32_t MSG_NUM = 3;
    int32_t msgNum_ = MSG_NUM;
    static const int32_t DEFAULT_RAF = 0xffff;
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    std::shared_ptr<DeviceStateHandler> deviceStateHandler_ = nullptr;
    std::shared_ptr<DeviceStateObserver> deviceStateObserver_ = nullptr;
    sptr<AutoTimeObserver> settingAutoTimeObserver_ = nullptr;
    sptr<AutoTimezoneObserver> settingAutoTimezoneObserver_ = nullptr;
    sptr<AirplaneModeObserver> airplaneModeObserver_ = nullptr;
    HandleRunningState state_ = HandleRunningState::STATE_NOT_START;
    std::unique_ptr<NetworkSearchResult> networkSearchResult_ = nullptr;
    SelectionMode selection_ = SelectionMode::MODE_TYPE_UNKNOWN;
    ModemPowerState radioState_ = ModemPowerState::CORE_SERVICE_POWER_OFF;
    std::u16string imei_ = u"";
    std::u16string meid_ = u"";
    std::string basebandVersion_ = "";
    NrMode nrMode_ = NrMode::NR_MODE_UNKNOWN;
    int32_t rrcConnectionStatus_ = 0;
    FrequencyType freqType_ = FrequencyType::FREQ_TYPE_UNKNOWN;
    std::mutex mutex_;
    bool isRadioFirstPowerOn_ = true;
    bool airplaneMode_ = false;

    bool RegisterSetting();
    bool UnRegisterSetting();
    bool RegisterDeviceStateObserver();
    bool UnRegisterDeviceStateObserver();
    bool Init()
    {
        if (networkSearchState_ != nullptr) {
            if (!networkSearchState_->Init()) {
                return false;
            }
        }
        if (networkSearchHandler_ != nullptr) {
            if (!networkSearchHandler_->Init()) {
                return false;
            }
            if (!RegisterSetting()) {
                return false;
            }
        }
        if (deviceStateHandler_ != nullptr) {
            if (!RegisterDeviceStateObserver()) {
                return false;
            }
        }
        if (eventLoop_ != nullptr) {
            eventLoop_->Run();
        }
        state_ = HandleRunningState::STATE_RUNNING;
        return true;
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
};

/**
 * @brief manager class of network search module .The main entrance to the module.
 *
 */
class NetworkSearchManager : public INetworkSearch, public std::enable_shared_from_this<NetworkSearchManager> {
public:
    NetworkSearchManager(std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<ISimManager> simManager);
    virtual ~NetworkSearchManager();

    bool OnInit() override;
    void SetRadioState(int32_t slotId, bool isOn, int32_t rst) override;
    int32_t SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback) override;
    int32_t GetRadioState(int32_t slotId) override;
    int32_t GetRadioState(int32_t slotId, NSCALLBACK &callback) override;
    int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech) override;
    int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech) override;
    std::u16string GetOperatorNumeric(int32_t slotId) override;
    int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName) override;
    int32_t GetNetworkStatus(int32_t slotId, sptr<NetworkState> &networkState) override;
    int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals) override;
    void RegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what) override;
    void UnRegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what) override;
    void RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    int32_t GetNetworkSearchInformation(int32_t slotId, NSCALLBACK &callback) override;
    int32_t GetNetworkSelectionMode(int32_t slotId, NSCALLBACK &callback) override;
    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection, NSCALLBACK &callback) override;
    int32_t GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback) override;
    int32_t SetPreferredNetwork(int32_t slotId, int32_t networkMode, NSCALLBACK &callback) override;
    int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode) override;
    int32_t GetImei(int32_t slotId, std::u16string &imei) override;
    int32_t GetPsRegState(int32_t slotId) override;
    int32_t GetCsRegState(int32_t slotId) override;
    int32_t GetPsRoamingState(int32_t slotId) override;
    int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo) override;
    int32_t SendUpdateCellLocationRequest(int32_t slotId) override;
    sptr<CellLocation> GetCellLocation(int32_t slotId) override;
    int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) override;
    PhoneType GetPhoneType(int32_t slotId) override;
    int32_t GetMeid(int32_t slotId, std::u16string &meid) override;
    int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId) override;
    bool IsNrSupported(int32_t slotId) override;
    FrequencyType GetFrequencyType(int32_t slotId) override;
    NrState GetNrState(int32_t slotId) override;
    void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive) override;
    int32_t HandleNotifyStateChangeWithDelay(int32_t slotId, bool isNeedDelay) override;
    bool IsNeedDelayNotify(int32_t slotId);
    int32_t GetNrOptionMode(int32_t slotId, NrMode &mode) override;
    int32_t RegisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType, const std::string &bundleName,
        const sptr<ImsRegInfoCallback> &callback) override;
    int32_t UnregisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const std::string &bundleName) override;
    int32_t GetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState) override;
    int32_t SetNetworkCapability(
        int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState) override;

    void NotifyPsRoamingOpenChanged(int32_t slotId);
    void NotifyPsRoamingCloseChanged(int32_t slotId);
    void NotifyPsConnectionAttachedChanged(int32_t slotId);
    void NotifyPsConnectionDetachedChanged(int32_t slotId);
    void NotifyPsRatChanged(int32_t slotId);
    void NotifyEmergencyOpenChanged(int32_t slotId);
    void NotifyEmergencyCloseChanged(int32_t slotId);
    void NotifyNrStateChanged(int32_t slotId);
    void NotifyNrFrequencyChanged(int32_t slotId);
    std::shared_ptr<NetworkSearchState> GetNetworkSearchState(int32_t slotId);
    void TriggerSimRefresh(int32_t slotId);
    void TriggerTimezoneRefresh(int32_t slotId);
    void SetNetworkSearchResultValue(
        int32_t slotId, int32_t listSize, const std::vector<NetworkInformation> &operatorInfo);
    sptr<NetworkSearchResult> GetNetworkSearchInformationValue(int32_t slotId);
    int32_t GetNetworkSelectionMode(int32_t slotId);
    bool SetNetworkSelectionMode(
        int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection);
    void SetRadioStateValue(int32_t slotId, ModemPowerState radioState);
    void SetNetworkSelectionValue(int32_t slotId, SelectionMode selection);
    bool GetPreferredNetwork(int32_t slotId);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode);
    void SavePreferredNetworkValue(int32_t slotId, int32_t networkMode);
    int32_t GetPreferredNetworkValue(int32_t slotId) const;
    void UpdatePhone(int32_t slotId, RadioTech csRadioTech, const RadioTech &psRadioTech);
    void SetImei(int32_t slotId, std::u16string imei);
    void UpdateCellLocation(int32_t slotId, int32_t techType, int32_t cellId, int32_t lac);
    void SetMeid(int32_t slotId, std::u16string meid);
    int32_t SetNrOptionMode(int32_t slotId, NrMode mode);
    void SetFrequencyType(int32_t slotId, FrequencyType type);
    void GetVoiceTech(int32_t slotId);
    std::shared_ptr<NetworkSearchManagerInner> FindManagerInner(int32_t slotId);
    void SetLocateUpdate(int32_t slotId);
    int32_t GetAirplaneMode(bool &airplaneMode) override;
    bool IsRadioFirstPowerOn(int32_t slotId);
    void SetRadioFirstPowerOn(int32_t slotId, bool isFirstPowerOn);
    void NotifyImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info);
    void InitSimRadioProtocol(int32_t slotId);
    int32_t SetLocalAirplaneMode(int32_t slotId, bool state);
    int32_t GetLocalAirplaneMode(int32_t slotId, bool &state);
    void SetBasebandVersion(int32_t slotId, std::string version);
    int32_t GetBasebandVersion(int32_t slotId, std::string &version) override;
    int32_t JudgeNetworkMode(int32_t preferredNetwork);
    int32_t UpdateNrOptionMode(int32_t slotId, NrMode mode);
    int32_t UpdateRadioOn(int32_t slotId) override;
    int32_t UpdateNrConfig(int32_t slotId, int32_t status);
    int32_t GetRrcConnectionState(int32_t slotId, int32_t &status) override;
    int32_t UpdateRrcConnectionState(int32_t slotId, int32_t &status);

    inline void InitMsgNum(int32_t slotId)
    {
        auto inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            inner->InitMsgNum();
        }
    }
    inline bool CheckIsNeedNotify(int32_t slotId)
    {
        auto inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            return inner->CheckIsNeedNotify();
        }
        return false;
    }
    inline void decMsgNum(int32_t slotId)
    {
        auto inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            inner->decMsgNum();
        }
    }
    inline sptr<NetworkSearchCallBackBase> GetCellularDataCallBack()
    {
        return cellularDataCallBack_;
    }
    inline sptr<NetworkSearchCallBackBase> GetCellularCallCallBack()
    {
        return cellularCallCallBack_;
    }
    inline std::shared_ptr<ISimManager> GetSimManager() const
    {
        return simManager_;
    }

private:
    bool InitPointer(std::shared_ptr<NetworkSearchManagerInner> &inner, int32_t slotId);
    void ClearManagerInner();
    void AddManagerInner(int32_t slotId, const std::shared_ptr<NetworkSearchManagerInner> &inner);
    bool RemoveManagerInner(int32_t slotId);
    int32_t GetDelayNotifyTime(int32_t slotId);

private:
    struct ImsRegInfoCallbackRecord {
        int32_t slotId;
        ImsServiceType imsSrvType;
        std::string bundleName;
        sptr<ImsRegInfoCallback> imsCallback;
    };

    sptr<NetworkSearchCallBackBase> cellularDataCallBack_ = nullptr;
    sptr<NetworkSearchCallBackBase> cellularCallCallBack_ = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimManager> simManager_ = nullptr;
    std::unique_ptr<EventSender> eventSender_ = nullptr;
    std::map<int32_t, std::shared_ptr<NetworkSearchManagerInner>> mapManagerInner_;
    std::list<ImsRegInfoCallbackRecord> listImsRegInfoCallbackRecord_;
    std::mutex mutexInner_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H

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
#include <cinttypes>
#include <mutex>

#include "i_network_search.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "network_search_notify.h"
#include "observer_handler.h"
#include "network_search_state.h"
#include "network_search_handler.h"
#include "network_search_result.h"
#include "event_handler.h"
#include "network_utils.h"
#include "radio_event.h"

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
    HandleRunningState state_ = HandleRunningState::STATE_NOT_START;
    std::unique_ptr<NetworkSearchResult> networkSearchResult_ = nullptr;
    SelectionMode selection_ = SelectionMode::MODE_TYPE_UNKNOWN;
    ModemPowerState radioState_ = ModemPowerState::CORE_SERVICE_POWER_OFF;
    std::u16string imei_;
    std::u16string meid_;
    NrMode nrMode_ = NrMode::NR_MODE_UNKNOWN;
    FrequencyType freqType_ = FrequencyType::FREQ_TYPE_UNKNOWN;
    RadioCapabilityInfo radioCapability_;
    std::mutex mutex_;

    bool Init()
    {
        radioCapability_.ratFamily = DEFAULT_RAF;
        if (networkSearchState_ != nullptr) {
            if (!networkSearchState_->Init()) {
                return false;
            }
        }
        if (networkSearchHandler_ != nullptr) {
            if (!networkSearchHandler_->Init()) {
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
    virtual ~NetworkSearchManager() = default;

    bool OnInit() override;
    void SetRadioState(int32_t slotId, bool isOn, int32_t rst) override;
    bool SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback) override;
    int32_t GetRadioState(int32_t slotId) override;
    bool GetRadioState(int32_t slotId, NSCALLBACK &callback) override;
    int32_t GetPsRadioTech(int32_t slotId) override;
    int32_t GetCsRadioTech(int32_t slotId) override;
    std::u16string GetOperatorNumeric(int32_t slotId) override;
    std::u16string GetOperatorName(int32_t slotId) override;
    sptr<NetworkState> GetNetworkStatus(int32_t slotId) override;
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) override;
    void RegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what) override;
    void UnRegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what) override;
    void RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    void UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) override;
    bool GetNetworkSearchInformation(int32_t slotId, NSCALLBACK &callback) override;
    bool GetNetworkSelectionMode(int32_t slotId, NSCALLBACK &callback) override;
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection, NSCALLBACK &callback) override;
    bool GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback) override;
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode, NSCALLBACK &callback) override;
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) override;
    std::u16string GetImei(int32_t slotId) override;
    int32_t GetPsRegState(int32_t slotId) override;
    int32_t GetCsRegState(int32_t slotId) override;
    int32_t GetPsRoamingState(int32_t slotId) override;
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) override;
    bool SendUpdateCellLocationRequest(int32_t slotId) override;
    sptr<CellLocation> GetCellLocation(int32_t slotId) override;
    bool GetImsRegStatus(int32_t slotId) override;
    PhoneType GetPhoneType(int32_t slotId) override;
    std::u16string GetMeid(int32_t slotId) override;
    std::u16string GetUniqueDeviceId(int32_t slotId) override;
    bool IsNrSupported(int32_t slotId) override;
    FrequencyType GetFrequencyType(int32_t slotId) override;
    NrState GetNrState(int32_t slotId) override;
    void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive) override;
    NrMode GetNrOptionMode(int32_t slotId) override;

    void NotifyPsRoamingOpenChanged(int32_t slotId);
    void NotifyPsRoamingCloseChanged(int32_t slotId);
    void NotifyPsConnectionAttachedChanged(int32_t slotId);
    void NotifyPsConnectionDetachedChanged(int32_t slotId);
    void NotifyPsRatChanged(int32_t slotId);
    void NotifyEmergencyOpenChanged(int32_t slotId);
    void NotifyEmergencyCloseChanged(int32_t slotId);
    void NotifyNrStateChanged(int32_t slotId);
    void NotifyNrFrequencyChanged(int32_t slotId);
    void NotifyImsRegStateChanged(int32_t slotId);
    std::shared_ptr<NetworkSearchState> GetNetworkSearchState(int32_t slotId);
    void TriggerSimRefresh(int32_t slotId);
    void TriggerTimezoneRefresh(int32_t slotId);
    void SetNetworkSearchResultValue(
        int32_t slotId, int32_t listSize, std::vector<NetworkInformation> &operatorInfo);
    sptr<NetworkSearchResult> GetNetworkSearchInformationValue(int32_t slotId);
    int32_t GetNetworkSelectionMode(int32_t slotId);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection);
    void SetRadioStateValue(int32_t slotId, ModemPowerState radioState);
    void SetNetworkSelectionValue(int32_t slotId, SelectionMode selection);
    bool GetPreferredNetwork(int32_t slotId);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode);
    void SavePreferredNetworkValue(int32_t slotId, int32_t networkMode);
    int32_t GetPreferredNetworkValue(int32_t slotId) const;
    void UpdatePhone(int32_t slotId, RadioTech csRadioTech);
    void SetImei(int32_t slotId, std::u16string imei);
    void UpdateCellLocation(int32_t slotId, int32_t techType, int32_t cellId, int32_t lac);
    void SetMeid(int32_t slotId, std::u16string meid);
    int32_t GetRadioCapability(int32_t slotId);
    void SetNrOptionMode(int32_t slotId, NrMode mode);
    void SetFrequencyType(int32_t slotId, FrequencyType type);
    void GetVoiceTech(int32_t slotId);
    std::shared_ptr<NetworkSearchManagerInner> FindManagerInner(int32_t slotId);
    void SetLocateUpdate(int32_t slotId);

    inline bool GetAirplaneMode()
    {
        return AirplaneMode_;
    }
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
    inline void SetCapability(int32_t slotId, RadioCapabilityInfo &radioCapability)
    {
        auto inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            inner->radioCapability_ = radioCapability;
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
    void AddManagerInner(int32_t slotId, std::shared_ptr<NetworkSearchManagerInner> inner);
    bool RemoveManagerInner(int32_t slotId);

private:
    bool AirplaneMode_ = false;
    sptr<NetworkSearchCallBackBase> cellularDataCallBack_ = nullptr;
    sptr<NetworkSearchCallBackBase> cellularCallCallBack_ = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimManager> simManager_ = nullptr;
    std::unique_ptr<EventSender> eventSender_ = nullptr;
    std::map<int32_t, std::shared_ptr<NetworkSearchManagerInner>> mapManagerInner_;
    std::mutex mutexInner_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_MANAGER_H

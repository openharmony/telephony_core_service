/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_HANDLER_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_HANDLER_H

#include <memory>

#include "cell_info.h"
#include "i_sim_manager.h"
#include "i_tel_ril_manager.h"
#include "network_register.h"
#include "network_selection.h"
#include "network_type.h"
#include "nitz_update.h"
#include "nr_ssb_info.h"
#include "operator_name.h"
#include "radio_event.h"
#include "radio_info.h"
#include "satellite_core_callback.h"
#include "signal_info.h"
#include "system_ability_status_change_stub.h"
#include "tel_event_handler.h"
#include "tel_ril_types.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NetworkSearchHandler : public TelEventHandler {
public:
    using NsHandlerFunc = void (NetworkSearchHandler::*)(const AppExecFwk::InnerEvent::Pointer &);
    explicit NetworkSearchHandler(const std::weak_ptr<NetworkSearchManager> &networkSearchManager,
        const std::weak_ptr<ITelRilManager> &telRilManager, const std::weak_ptr<ISimManager> &simManager,
        int32_t slotId);
    virtual ~NetworkSearchHandler();
    bool Init();
    void RegisterEvents();
    void UnregisterEvents();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void GetSignalInfo(std::vector<sptr<SignalInformation>> &signals);
    void UpdatePhone(RadioTech csRadioTech, const RadioTech &psRadioTech) const;
    int32_t GetCellInfoList(std::vector<sptr<CellInformation>> &cells);
    void DcPhysicalLinkActiveUpdate(const AppExecFwk::InnerEvent::Pointer &event);
    void NotifyStateChange(const AppExecFwk::InnerEvent::Pointer &event);
    void HandleDelayNotifyEvent(const AppExecFwk::InnerEvent::Pointer &event);
    int32_t HandleRrcStateChanged(int32_t status);
    int32_t RevertLastTechnology();
    void UpdateImsServiceStatus(const AppExecFwk::InnerEvent::Pointer &event);
    void UpdateImsRegisterState(const AppExecFwk::InnerEvent::Pointer &event);
    void RegisterSatelliteCallback();
    void UnregisterSatelliteCallback();
    int32_t SendUpdateCellLocationRequest();
    PhoneType GetPhoneType();
    int32_t GetNrSsbId(const std::shared_ptr<NrSsbInformation> &nrCellSsbIdsInfo);

    /**
     * Get signal quality
     * 27007-410_2001 8.5 Signal quality +CSQ
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilSignalIntensity(bool checkTime = true);

    /**
     * querying the status of all GSM/UMTS operators detected in the area.
     * 27007-410_2001 7.3 PLMN selection +COPS
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilOperatorInfo(int64_t serialNum, bool checkTime = true);

    /**
     * Get PS network registration status
     * 27007-410_2001 10.1.19	GPRS network registration status +CGREG
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilPsRegistration(int64_t serialNum, bool checkTime = true);

    /**
     * Get CS network registration status
     * 27007-410_2001 7.2 Network registration +CREG
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilCsRegistration(int64_t serialNum, bool checkTime = true);

    void UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac);
    sptr<CellLocation> GetCellLocation();
    void TimezoneRefresh();
    void SetCellRequestMinInterval(uint32_t minInterval);
    int32_t GetRegServiceState(RegServiceState &regState);
    bool IsPowerOnPrimaryRadioWhenNoSim() const;
    void ProcessSignalIntensity(int32_t slotId, const Rssi &signalIntensity);
    void RadioOnState();

private:
    void RadioOffOrUnavailableState(int32_t radioState) const;
    void GetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SimStateChange(const AppExecFwk::InnerEvent::Pointer &);
    void ImsiLoadedReady(const AppExecFwk::InnerEvent::Pointer &event);
    void SimRecordsLoaded(const AppExecFwk::InnerEvent::Pointer &);
    void RadioStateChange(const AppExecFwk::InnerEvent::Pointer &event);
    void GetNetworkStateInfo(const AppExecFwk::InnerEvent::Pointer &);
    void RadioRestrictedState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioRilDataRegState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioRilVoiceRegState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioSignalStrength(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioRilOperator(const AppExecFwk::InnerEvent::Pointer &event);
    bool TimeOutCheck(int64_t &lastTime, bool checkTime = true);
    void NetworkSearchResult(const AppExecFwk::InnerEvent::Pointer &event);
    void GetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void InitGetNetworkSelectionMode();
    void InitNetworkSearchResult();
    void GetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioGetImei(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioGetImeiSv(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioGetMeid(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioGetNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioGetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioCurrentCellInfoUpdate(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioChannelConfigInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event);
    void AutoTimeChange(const AppExecFwk::InnerEvent::Pointer &);
    void AutoTimeZoneChange(const AppExecFwk::InnerEvent::Pointer &);
    void AirplaneModeChange(const AppExecFwk::InnerEvent::Pointer &);
    void RadioGetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &event);
    void SetNrOptionModeResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void GetNrOptionModeResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioGetRrcConnectionState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioResidentNetworkChange(const AppExecFwk::InnerEvent::Pointer &event);
    void SatelliteStatusChanged(const AppExecFwk::InnerEvent::Pointer &event);
    bool InitOperatorName();
    int32_t IsSatelliteSupported();
    void GetNrSsbIdResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SyncGetSsbInfoResponse();
    bool SubModuleInit();

private:
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::unique_ptr<NetworkRegister> networkRegister_ = nullptr;
    std::shared_ptr<OperatorName> operatorName_ = nullptr;
    std::unique_ptr<RadioInfo> radioInfo_ = nullptr;
    std::unique_ptr<SignalInfo> signalInfo_ = nullptr;
    std::unique_ptr<NetworkSelection> networkSelection_ = nullptr;
    std::weak_ptr<ITelRilManager> telRilManager_;
    std::weak_ptr<ISimManager> simManager_;
    std::unique_ptr<NetworkType> networkType_ = nullptr;
    std::unique_ptr<NitzUpdate> nitzUpdate_ = nullptr;
    std::unique_ptr<CellInfo> cellInfo_ = nullptr;
    std::unique_ptr<NrSsbInfo> nrSsbInfo_ = nullptr;
    static const std::map<uint32_t, NsHandlerFunc> memberFuncMap_;
    int64_t lastTimeSignalReq_ = 0;
    int64_t lastTimeOperatorReq_ = 0;
    int64_t lastTimePsRegistrationReq_ = 0;
    int64_t lastTimeCsRegistrationReq_ = 0;
    bool firstInit_ = true;
    int32_t slotId_ = 0;
    uint32_t cellRequestMinInterval_ = 2; // This is the minimum interval in seconds for cell requests
    uint32_t lastCellRequestTime_ = 0;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    sptr<ISatelliteCoreCallback> satelliteCallback_ = nullptr;
    const int32_t INVALID_SLOT_ID = -1;

private:
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(std::shared_ptr<OperatorName> &operatorName);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    private:
        std::shared_ptr<OperatorName> opName_ = nullptr;
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_HANDLER_H

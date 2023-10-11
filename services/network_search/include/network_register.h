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
#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_REGISTER_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_REGISTER_H
#include <memory>
#include <string>
#include <vector>
#include <map>
#include "event_handler.h"

#include "hril_network_parcel.h"
#include "network_search_state.h"

namespace OHOS {
namespace Telephony {
class NetworkRegister {
public:
    NetworkRegister(std::shared_ptr<NetworkSearchState> networkSearchState,
        std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~NetworkRegister() = default;
    void InitNrConversionConfig();
    void ProcessPsRegister(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessCsRegister(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessRestrictedState(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessChannelConfigInfo(const AppExecFwk::InnerEvent::Pointer &event);
    int32_t RevertLastTechnology();
    int32_t NotifyStateChange();
    void DcPhysicalLinkActiveUpdate(bool isActive);
    void UpdateCfgTech();
    int32_t HandleRrcStateChanged(int32_t status);
    RegServiceState GetRegServiceState() const;

    enum class RilRegister {
        REG_STATE_NOT_REG = 0,
        REG_STATE_HOME_ONLY = 1,
        REG_STATE_SEARCH = 2,
        REG_STATE_NO_SERVICE = 3,
        REG_STATE_INVALID = 4,
        REG_STATE_ROAMING = 5,
        REG_STATE_EMERGENCY_ONLY = 6
    };
    enum class ConnectServiceCell {
        /** Connection status is unknown. */
        CONNECTION_UNKNOWN = 0,
        /** UE has connection to primary cell cell(3GPP 36.331).*/
        CONNECTION_PRIMARY_CELL = 1,
        /** UE has connectionto secondary cell cell(3GPP 36.331).*/
        CONNECTION_SECONDARY_CELL = 2
    };

private:
    RegServiceState ConvertRegFromRil(RilRegister code) const;
    RadioTech ConvertTechFromRil(HRilRadioTech code) const;
    void UpdateNrState();
    void NotifyNrFrequencyChanged();
    int32_t GetRrcConnectionState(int32_t &rrcState);
    bool IsValidConfig(const std::string &config);
    RadioTech GetTechnologyByNrConfig(RadioTech tech);
    int32_t GetSystemPropertiesConfig(std::string &config);
    void UpdateNetworkSearchState(RegServiceState regStatus, RadioTech tech, RoamingType roam, DomainType type);

private:
    std::shared_ptr<NetworkSearchState> networkSearchState_ = nullptr;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    /**
     * Indicates that if E-UTRA-NR Dual Connectivity (EN-DC) is supported by the primary serving
     * cell.
     *
     * Reference: 3GPP TS 36.331 V16.6.0 6.3.1 System information blocks.
     */
    bool endcSupport_ = false;
    /**
     * Indicates if the use of dual connectivity with NR is restricted.
     * Reference: 3GPP TS 24.301 V17.4.0 section 9.9.3.12A.
     */
    bool dcNrRestricted_ = false;
    /**
     * Indicates if NR is supported by the selected PLMN.
     * Reference: 3GPP TS 36.331 V16.6.0 section 6.3.1 PLMN-InfoList-r15.
     *            3GPP TS 36.331 V16.6.0 section 6.2.2 SystemInformationBlockType1 message.
     */
    bool nrSupport_ = false;
    FrequencyType freqType_ = FrequencyType::FREQ_TYPE_UNKNOWN;
    bool isNrSecondaryCell_ = false;
    bool isPhysicalLinkActive_ = false;
    NrState nrState_ = NrState::NR_STATE_NOT_SUPPORT;
    std::vector<PhysicalChannelConfig> channelConfigInfos_;
    std::map<NrState, RadioTech> nrConfigMap_;

    int32_t slotId_ = 0;
    bool isCsCapable_ = true;
    std::string currentNrConfig_ = "";
    std::string systemPropertiesConfig_ = "ConfigD";
    RegServiceState regStatusResult_ = RegServiceState::REG_STATE_UNKNOWN;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_REGISTER_H

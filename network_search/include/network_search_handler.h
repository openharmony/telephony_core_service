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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_HANDLER_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_HANDLER_H

#include <memory>
#include "i_tel_ril_manager.h"
#include "event_handler.h"
#include "i_sim_file_manager.h"
#include "i_sim_state_manager.h"
#include "radio_info.h"
#include "signal_info.h"
#include "operator_name.h"
#include "network_register.h"
#include "network_selection.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NetworkSearchHandler : public AppExecFwk::EventHandler {
public:
    NetworkSearchHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::weak_ptr<NetworkSearchManager> &networkSearchManager);
    virtual ~NetworkSearchHandler();
    void Init();
    void RegisterEvents();
    void UnregisterEvents();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void GetSignalInfo(std::vector<sptr<SignalInformation>> &signals);
    void RadioOffState() const;

    /**
     * Get signal quality
     * 27007-410_2001 8.5 Signal quality +CSQ
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilSignalIntensity();

    /**
     * querying the status of all GSM/UMTS operators detected in the area.
     * 27007-410_2001 7.3 PLMN selection +COPS
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilOperatorInfo();

    /**
     * Get PS network registration status
     * 27007-410_2001 10.1.19	GPRS network registration status +CGREG
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilPsRegistration();

    /**
     * Get CS network registration status
     * 27007-410_2001 7.2 Network registration +CREG
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetRilCsRegistration();

protected:
    void RadioOnState();
    void GetRadioStatusResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetRadioStatusResponse(const AppExecFwk::InnerEvent::Pointer &event);
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
    bool TimeOutCheck(int64_t &lastTime);
    void NetworkSearchResult(const AppExecFwk::InnerEvent::Pointer &event);
    void GetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void SetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event);
    void InitGetNetworkSelectionMode();
    void InitNetworkSearchResult();

private:
    static const int REQ_INTERVAL = 30;
    using NsHandlerFunc = void (NetworkSearchHandler::*)(const AppExecFwk::InnerEvent::Pointer &);
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::unique_ptr<NetworkRegister> networkRegister_ = nullptr;
    std::unique_ptr<OperatorName> operatorName_ = nullptr;
    std::unique_ptr<RadioInfo> radioInfo_ = nullptr;
    std::unique_ptr<SignalInfo> signalInfo_ = nullptr;
    std::unique_ptr<NetworkSelection> networkSelection_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<IRilManager> rilManager_ = nullptr;
    std::map<uint32_t, NsHandlerFunc> memberFuncMap_;
    int64_t lastTimeSignalReq_ = 0;
    int64_t lastTimeOperatorReq_ = 0;
    int64_t lastTimePsRegistrationReq_ = 0;
    int64_t lastTimeCsRegistrationReq_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SEARCH_HANDLER_H

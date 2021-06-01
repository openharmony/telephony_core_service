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
#ifndef OHOS_NS_NETWORK_HANDLER_H
#define OHOS_NS_NETWORK_HANDLER_H
#include <memory>
#include "../../interfaces/innerkits/common/i_tel_ril_manager.h"
#include "event_handler.h"
#include "i_sim_file_manager.h"
#include "i_sim_state_manager.h"
#include "radio_info_state.h"
#include "signal_info.h"
#include "sim_constant.h"
#include "operator_name.h"
#include "network_register.h"

namespace OHOS {
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

    /**
     * querying the status of all GSM/UMTS operators detected in the area.
     * 27007-410_2001 7.3 PLMN selection +COPS
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void GetOperatorInfo();

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
    void GetSignalInfo(std::vector<sptr<SignalInformation>> &signals);
    void RadioOffState() const;

protected:
    /**
     * Get signal quality
     * 27007-410_2001 8.5 Signal quality +CSQ
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    void QueryNextSignalIntensity();
    void RadioOnState();
    void SimStateChange(const AppExecFwk::InnerEvent::Pointer &);
    void ImsiLoadedReady(const AppExecFwk::InnerEvent::Pointer &event);
    void SimRecordsLoaded(const AppExecFwk::InnerEvent::Pointer &);
    void RadioState(const AppExecFwk::InnerEvent::Pointer &);
    void GetNetworkStateInfo(const AppExecFwk::InnerEvent::Pointer &);
    void RadioRestrictedState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioRilDataRegState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioRilVoiceRegState(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioSignalStrength(const AppExecFwk::InnerEvent::Pointer &event);
    void RadioRilOperator(const AppExecFwk::InnerEvent::Pointer &event);
    bool TimeOutCheck(uint64_t &lastTime);

private:
    static const int REQ_INTERVAL = 5;
    using NsHandlerFunc = void (NetworkSearchHandler::*)(const AppExecFwk::InnerEvent::Pointer &);
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::unique_ptr<NetworkRegister> networkRegister_;
    std::unique_ptr<OperatorName> operatorName_;
    std::unique_ptr<RadioInfoState> radioState_;
    std::unique_ptr<SignalInfo> signalInfo_;
    std::shared_ptr<SIM::ISimFileManager> simFileManager_;
    std::shared_ptr<SIM::ISimStateManager> simStateManager_;
    IRilManager *rilManager_;
    bool flagAutoQuerySignalIntensity_;
    std::map<uint32_t, NsHandlerFunc> memberFuncMap_;
    uint64_t lastTimeSignalReq = 0;
    uint64_t lastTimeOperatorReq = 0;
    uint64_t lastTimePsRegistrationReq = 0;
    uint64_t lastTimeCsRegistrationReq = 0;
};
} // namespace OHOS
#endif // OHOS_NS_NETWORK_HANDLER_H

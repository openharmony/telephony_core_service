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

#ifndef NETWORK_SEARCH_INCLUDE_SIGNAL_INFO_H
#define NETWORK_SEARCH_INCLUDE_SIGNAL_INFO_H

#include "event_handler.h"
#include "tel_ril_types.h"
#include "signal_information.h"

namespace OHOS {
namespace Telephony {
class SignalInfo {
public:
    SignalInfo() = default;
    virtual ~SignalInfo() = default;
    void Reset();
    void InitSignalBar(const int32_t bar = 5) const;
    void GetSignalInfoList(std::vector<sptr<SignalInformation>> &signals);
    void ProcessSignalIntensity(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSignalIntensity(int32_t slotId, const Rssi *signalIntensity);

private:
    bool ProcessGsm(const GsmRssi &gsmSignal);
    bool ProcessCdma(const CdmaRssi &cdmaSignal);
    bool ProcessLte(const LteRssi &lteSignal);
    bool ProcessWcdma(const WCdmaRssi &wcdmaSignal);
    bool ProcessTdScdma(const TdScdmaRssi &tdScdmaSignal);
    bool ProcessNr(const NrRssi &nrSignal);

private:
    std::mutex mutex_;
    struct SignalInformations {
        SignalInformations()
        {
            Init();
        }
        void Init()
        {
            gsm.SetValue();
            cdma.SetValue();
            lte.SetValue();
            wcdma.SetValue();
            tdScdma.SetValue();
            nr.SetValue();
        }
        GsmSignalInformation gsm;
        CdmaSignalInformation cdma;
        LteSignalInformation lte;
        WcdmaSignalInformation wcdma;
        TdScdmaSignalInformation tdScdma;
        NrSignalInformation nr;
    };
    SignalInformations cache_;
    SignalInformations cur_;
};
} // namespace Telephony
} // namespace OHOS

#endif // NETWORK_SEARCH_INCLUDE_SIGNAL_INFO_H

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

#include "signal_info.h"

#include "core_service_hisysevent.h"
#include "network_search_notify.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
void SignalInfo::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.Init();
    cur_.Init();
}

void SignalInfo::InitSignalBar(const int32_t bar) const
{
    SignalInformation::InitSignalBar(bar);
}

bool SignalInfo::ProcessGsm(const GsmRssi &gsmSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cur_.gsm.SetValue(gsmSignal.rxlev, gsmSignal.ber);
    bool ret = (cur_.gsm == cache_.gsm);
    cache_.gsm = cur_.gsm;
    return ret;
}

bool SignalInfo::ProcessCdma(const CdmaRssi &cdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cur_.cdma.SetValue(cdmaSignal.absoluteRssi, cdmaSignal.ecno);
    bool ret = (cur_.cdma == cache_.cdma);
    cache_.cdma = cur_.cdma;
    return ret;
}

bool SignalInfo::ProcessLte(const LteRssi &lteSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cur_.lte.SetValue(lteSignal.rxlev, lteSignal.rsrp, lteSignal.rsrq, lteSignal.snr);
    bool ret = (cur_.lte == cache_.lte);
    cache_.lte = cur_.lte;
    return ret;
}

bool SignalInfo::ProcessWcdma(const WCdmaRssi &wcdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cur_.wcdma.SetValue(wcdmaSignal.rxlev, wcdmaSignal.rscp, wcdmaSignal.ecio, wcdmaSignal.ber);
    bool ret = (cur_.wcdma == cache_.wcdma);
    cache_.wcdma = cur_.wcdma;
    return ret;
}

bool SignalInfo::ProcessTdScdma(const TdScdmaRssi &tdScdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cur_.tdScdma.SetValue(tdScdmaSignal.rscp);
    bool ret = (cur_.tdScdma == cache_.tdScdma);
    cache_.tdScdma = cur_.tdScdma;
    return ret;
}

bool SignalInfo::ProcessNr(const NrRssi &nrSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cur_.nr.SetValue(nrSignal.rsrp, nrSignal.rsrq, nrSignal.sinr);
    bool ret = (cur_.nr == cache_.nr);
    cache_.nr = cur_.nr;
    return ret;
}

static void PrintfLog(const Rssi &signalIntensity)
{
    TELEPHONY_LOGD("gm.rssi:%{public}d, gm.ber:%{public}d\n", signalIntensity.gw.rxlev, signalIntensity.gw.ber);

    TELEPHONY_LOGD("cdma.absoluteRssi:%{public}d, cdma.ecno:%{public}d ", signalIntensity.cdma.absoluteRssi,
        signalIntensity.cdma.ecno);

    TELEPHONY_LOGD("lte.rxlev:%{public}d, "
                   "lte.rsrq:%{public}d, lte.rsrp:%{public}d, lte.snr:%{public}d ",
        signalIntensity.lte.rxlev, signalIntensity.lte.rsrq, signalIntensity.lte.rsrp, signalIntensity.lte.snr);

    TELEPHONY_LOGD("wcdma.rxlev:%{public}d, "
                   "wcdma.ecio:%{public}d "
                   "wcdma.rscp:%{public}d "
                   "wcdma.ber:%{public}d ",
        signalIntensity.wcdma.rxlev, signalIntensity.wcdma.ecio, signalIntensity.wcdma.rscp, signalIntensity.wcdma.ber);

    TELEPHONY_LOGD("tdScdma.rscp:%{public}d\n", signalIntensity.tdScdma.rscp);

    TELEPHONY_LOGD("nr.rsrp:%{public}d, "
                   "nr.rsrq:%{public}d, nr.sinr:%{public}d ",
        signalIntensity.nr.rsrp, signalIntensity.nr.rsrq, signalIntensity.nr.sinr);
}

void SignalInfo::ProcessSignalIntensity(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("rssi start......\n");
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr\n");
        return;
    }

    Rssi *signalIntensity = event->GetSharedObject<Rssi>().get();
    if (signalIntensity == nullptr) {
        TELEPHONY_LOGE("rssi is nullptr\n");
        return;
    }
    bool gsmUpdate = ProcessGsm(signalIntensity->gw);
    bool cdmaUpdate = ProcessCdma(signalIntensity->cdma);
    bool lteUpdate = ProcessLte(signalIntensity->lte);
    bool wcdmaUpdate = ProcessWcdma(signalIntensity->wcdma);
    bool tdScdmaUpdate = ProcessTdScdma(signalIntensity->tdScdma);
    bool nrUpdate = ProcessNr(signalIntensity->nr);
    if (!gsmUpdate || !cdmaUpdate || !lteUpdate || !wcdmaUpdate || !tdScdmaUpdate || !nrUpdate) {
        std::vector<sptr<SignalInformation>> signals;
        GetSignalInfoList(signals);
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifySignalInfoUpdated(slotId, signals);
        int level = 0;
        if (signals.size() != 0) {
            level = signals[0]->GetSignalLevel();
        }
        CoreServiceHiSysEvent::WriteSignalLevelBehaviorEvent(slotId, level);
    }
    PrintfLog(*signalIntensity);
}

void SignalInfo::GetSignalInfoList(std::vector<sptr<SignalInformation>> &signals)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool gsmValid = cur_.gsm.ValidateGsmValue();
    bool cdmaValid = cur_.cdma.ValidateCdmaValue();
    bool lteValid = cur_.lte.ValidateLteValue();
    bool wcdmaValid = cur_.wcdma.ValidateWcdmaValue();
    bool tdScdmaValid = cur_.tdScdma.ValidateTdScdmaValue();
    bool nrValid = cur_.nr.ValidateNrValue();

    if (lteValid) {
        signals.emplace_back(cur_.lte.NewInstance());
    }
    if (nrValid) {
        signals.emplace_back(cur_.nr.NewInstance());
    }
    if (cdmaValid) {
        signals.emplace_back(cur_.cdma.NewInstance());
    }
    if (tdScdmaValid) {
        signals.emplace_back(cur_.tdScdma.NewInstance());
    }
    if (wcdmaValid) {
        signals.emplace_back(cur_.wcdma.NewInstance());
    }
    if (gsmValid) {
        signals.emplace_back(cur_.gsm.NewInstance());
    }
}
} // namespace Telephony
} // namespace OHOS

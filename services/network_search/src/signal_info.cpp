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

#include "network_search_notify.h"
#include "observer_handler.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SignalInfo::SignalInfo()
    : gsmSigInfoCache_(), cdmaSigInfoCache_(), lteSigInfoCache_(), wcdmaSigInfoCache_(), tdScdmaSigInfoCache_(),
    gsmSigInfoCur_(), cdmaSigInfoCur_(), lteSigInfoCur_(), wcdmaSigInfoCur_(), tdScdmaSigInfoCur_()
{}

void SignalInfo::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    gsmSigInfoCache_.SetValue();
    cdmaSigInfoCache_.SetValue();
    lteSigInfoCache_.SetValue();
    wcdmaSigInfoCache_.SetValue();
    tdScdmaSigInfoCache_.SetValue();
    gsmSigInfoCur_.SetValue();
    cdmaSigInfoCur_.SetValue();
    lteSigInfoCur_.SetValue();
    wcdmaSigInfoCur_.SetValue();
    tdScdmaSigInfoCur_.SetValue();
}

void SignalInfo::InitSignalBar(const int32_t bar) const
{
    SignalInformation::InitSignalBar(bar);
}

bool SignalInfo::ProcessGsm(const GsmRssi &gsmSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    gsmSigInfoCur_.SetValue(gsmSignal.rxlev, gsmSignal.ber);
    bool ret = (gsmSigInfoCur_ == gsmSigInfoCache_);
    gsmSigInfoCache_ = gsmSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessCdma(const CdmaRssi &cdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    cdmaSigInfoCur_.SetValue(cdmaSignal.absoluteRssi, cdmaSignal.ecno);
    bool ret = (cdmaSigInfoCur_ == cdmaSigInfoCache_);
    cdmaSigInfoCache_ = cdmaSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessLte(const LteRssi &lteSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    lteSigInfoCur_.SetValue(lteSignal.rxlev, lteSignal.rsrq, lteSignal.rsrp, lteSignal.snr);
    bool ret = (lteSigInfoCur_ == lteSigInfoCache_);
    lteSigInfoCache_ = lteSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessWcdma(const WCdmaRssi &wcdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    wcdmaSigInfoCur_.SetValue(wcdmaSignal.rxlev, wcdmaSignal.ecio, wcdmaSignal.rscp, wcdmaSignal.ber);
    bool ret = (wcdmaSigInfoCur_ == wcdmaSigInfoCache_);
    wcdmaSigInfoCache_ = wcdmaSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessTdScdma(const TdScdmaRssi &tdScdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tdScdmaSigInfoCur_.SetValue(tdScdmaSignal.rscp);
    bool ret = (tdScdmaSigInfoCur_ == tdScdmaSigInfoCache_);
    tdScdmaSigInfoCache_ = tdScdmaSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessNr(const NrRssi &nrSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    nrSigInfoCur_.SetValue(nrSignal.rsrp, nrSignal.rsrq, nrSignal.sinr);
    bool ret = (nrSigInfoCur_ == nrSigInfoCache_);
    nrSigInfoCache_ = nrSigInfoCur_;
    return ret;
}

static void PrintfLog(const Rssi &signalIntensity)
{
    TELEPHONY_LOGI("SignalInfo::ProcessSignalIntensity gm.rssi:%{public}d, gm.ber:%{public}d\n",
        signalIntensity.gw.rxlev, signalIntensity.gw.ber);

    TELEPHONY_LOGI("SignalInfo::ProcessSignalIntensity cdma.absoluteRssi:%{public}d, cdma.ecno:%{public}d ",
        signalIntensity.cdma.absoluteRssi, signalIntensity.cdma.ecno);

    TELEPHONY_LOGI(
        "SignalInfo::ProcessSignalIntensity lte.rxlev:%{public}d, "
        "lte.rsrq:%{public}d, lte.rsrp:%{public}d, lte.snr:%{public}d ",
        signalIntensity.lte.rxlev, signalIntensity.lte.rsrq, signalIntensity.lte.rsrp, signalIntensity.lte.snr);

    TELEPHONY_LOGI(
        "SignalInfo::ProcessSignalIntensity wcdma.rxlev:%{public}d, "
        "SignalInfo::ProcessSignalIntensity wcdma.ecio:%{public}d "
        "SignalInfo::ProcessSignalIntensity wcdma.rscp:%{public}d "
        "SignalInfo::ProcessSignalIntensity wcdma.ber:%{public}d ",
        signalIntensity.wcdma.rxlev, signalIntensity.wcdma.ecio, signalIntensity.wcdma.rscp,
        signalIntensity.wcdma.ber);

    TELEPHONY_LOGI("SignalInfo::ProcessSignalIntensity tdScdma.rscp:%{public}d\n",
        signalIntensity.tdScdma.rscp);

    TELEPHONY_LOGI(
        "SignalInfo::ProcessSignalIntensity nr.rsrp:%{public}d, "
        "nr.rsrq:%{public}d, nr.sinr:%{public}d ",
        signalIntensity.nr.rsrp, signalIntensity.nr.rsrq, signalIntensity.nr.sinr);
}

void SignalInfo::ProcessSignalIntensity(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SignalInfo::ProcessSignalIntensity rssi start......\n");
    if (event == nullptr) {
        TELEPHONY_LOGE("SignalInfo::ProcessSignalIntensity event is nullptr\n");
        return;
    }

    Rssi *signalIntensity = event->GetSharedObject<Rssi>().get();
    if (signalIntensity == nullptr) {
        TELEPHONY_LOGE("SignalInfo::ProcessSignalIntensity rssi is nullptr\n");
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
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifySignalInfoUpdated(signals);
    }
    PrintfLog(*signalIntensity);
}

void SignalInfo::GetSignalInfoList(std::vector<sptr<SignalInformation>> &signals)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool gsmValid = gsmSigInfoCur_.ValidateGsmValue();
    bool cdmaValid = cdmaSigInfoCur_.ValidateCdmaValue();
    bool lteValid = lteSigInfoCur_.ValidateLteValue();
    bool wcdmaValid = wcdmaSigInfoCur_.ValidateWcdmaValue();
    bool tdScdmaValid = tdScdmaSigInfoCur_.ValidateTdScdmaValue();
    bool nrValid = nrSigInfoCur_.ValidateNrValue();

    if (gsmValid) {
        signals.emplace_back(gsmSigInfoCur_.NewInstance());
    }
    if (cdmaValid) {
        signals.emplace_back(cdmaSigInfoCur_.NewInstance());
    }
    if (lteValid) {
        signals.emplace_back(lteSigInfoCur_.NewInstance());
    }
    if (wcdmaValid) {
        signals.emplace_back(wcdmaSigInfoCur_.NewInstance());
    }
    if (tdScdmaValid) {
        signals.emplace_back(tdScdmaSigInfoCur_.NewInstance());
    }
    if (nrValid) {
        signals.emplace_back(nrSigInfoCur_.NewInstance());
    }
}
} // namespace Telephony
} // namespace OHOS

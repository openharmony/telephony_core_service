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
    : gsmSigInfoCache_(), cdmaSigInfoCache_(), lteSigInfoCache_(), wcdmaSigInfoCache_(), gsmSigInfoCur_(),
      cdmaSigInfoCur_(), lteSigInfoCur_(), wcdmaSigInfoCur_()
{}

void SignalInfo::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    gsmSigInfoCache_.SetValue();
    cdmaSigInfoCache_.SetValue();
    lteSigInfoCache_.SetValue();
    wcdmaSigInfoCache_.SetValue();
    gsmSigInfoCur_.SetValue();
    cdmaSigInfoCur_.SetValue();
    lteSigInfoCur_.SetValue();
    wcdmaSigInfoCur_.SetValue();
}

void SignalInfo::InitSignalBar(const int bar) const
{
    SignalInformation::InitSignalBar();
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
    lteSigInfoCur_.SetValue(lteSignal.rxlev, lteSignal.rsrp, lteSignal.rsrq, lteSignal.snr);
    bool ret = (lteSigInfoCur_ == lteSigInfoCache_);
    lteSigInfoCache_ = lteSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessWcdma(const WCdmaRssi &wcdmaSignal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    wcdmaSigInfoCur_.SetValue(wcdmaSignal.rxlev, wcdmaSignal.rscp, wcdmaSignal.ecio, wcdmaSignal.ber);
    bool ret = (wcdmaSigInfoCur_ == wcdmaSigInfoCache_);
    wcdmaSigInfoCache_ = wcdmaSigInfoCur_;
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
        "SignalInfo::ProcessSignalIntensity lte.rsrp:%{public}d "
        "SignalInfo::ProcessSignalIntensity lte.rsrq:%{public}d "
        "SignalInfo::ProcessSignalIntensity lte.snr:%{public}d ",
        signalIntensity.lte.rxlev, signalIntensity.lte.rsrp, signalIntensity.lte.rsrq, signalIntensity.lte.snr);

    TELEPHONY_LOGI(
        "SignalInfo::ProcessSignalIntensity wcdma.rxlev:%{public}d, "
        "SignalInfo::ProcessSignalIntensity wcdma.ecio:%{public}d "
        "SignalInfo::ProcessSignalIntensity wcdma.rscp:%{public}d "
        "SignalInfo::ProcessSignalIntensity wcdma.ber:%{public}d ",
        signalIntensity.wcdma.rxlev, signalIntensity.wcdma.ecio, signalIntensity.wcdma.rscp,
        signalIntensity.wcdma.ber);
}

void SignalInfo::ProcessSignalIntensity(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("SignalInfo::ProcessSignalIntensity rssi start......\n");
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
    if (!gsmUpdate || !cdmaUpdate || !lteUpdate || !wcdmaUpdate) {
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
}
} // namespace Telephony
} // namespace OHOS

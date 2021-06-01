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
#include "hilog_network_search.h"
#include "network_search_notify.h"
#include "hril_types.h"
#include "observer_handler.h"
namespace OHOS {
constexpr int SIGNAL_FIVE_BARS = 5;
constexpr int SIGNAL_FOUR_BARS = 4;
SignalInfo::SignalInfo() : gsmSigInfoCache_(), cdmaSigInfoCache_(), gsmSigInfoCur_(), cdmaSigInfoCur_() {}

void SignalInfo::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    gsmSigInfoCache_.SetValue();
    cdmaSigInfoCache_.SetValue();

    gsmSigInfoCur_.SetValue();
    cdmaSigInfoCur_.SetValue();
}

void SignalInfo::InitSignalBar(const int bar) const
{
    if (bar == SIGNAL_FOUR_BARS) {
        SignalInformation::g_gsmSignalThreshold = SignalInformation::GSM_SIGNAL_THRESHOLD_4BAR;
        SignalInformation::g_cdmaSignalThreshold = SignalInformation::CDMA_SIGNAL_THRESHOLD_4BAR;
        SignalInformation::g_signalBar = SIGNAL_FOUR_BARS;
    } else {
        SignalInformation::g_gsmSignalThreshold = SignalInformation::GSM_SIGNAL_THRESHOLD_5BAR;
        SignalInformation::g_cdmaSignalThreshold = SignalInformation::CDMA_SIGNAL_THRESHOLD_5BAR;
        SignalInformation::g_signalBar = SIGNAL_FIVE_BARS;
    }
}

bool SignalInfo::ProcessGsm(const GsmRssi &gsmSignal)
{
    gsmSigInfoCur_.SetValue(gsmSignal.rssi, gsmSignal.ta);
    bool ret = (gsmSigInfoCur_ == gsmSigInfoCache_);
    gsmSigInfoCache_ = gsmSigInfoCur_;
    return ret;
}

bool SignalInfo::ProcessCdma(const CdmaRssi &cdmaSignal)
{
    cdmaSigInfoCur_.SetValue(cdmaSignal.absoluteRssi, cdmaSignal.ecno);
    bool ret = (cdmaSigInfoCur_ == cdmaSigInfoCache_);
    cdmaSigInfoCache_ = cdmaSigInfoCur_;
    return ret;
}

static void PrintfLog(const Rssi &signalIntensity)
{
    HILOG_INFO(
        "SignalInfo::ProcessSignalIntensity gm.rssi:%{public}d, gm.ber:%{public}d, "
        "gm.ta:%{public}d\n",
        signalIntensity.gw.rssi, signalIntensity.gw.ber, signalIntensity.gw.ta);
    HILOG_INFO("SignalInfo::ProcessSignalIntensity cdma.absoluteRssi:%{public}d, cdma.ecno:%{public}d ",
        signalIntensity.cdma.absoluteRssi, signalIntensity.cdma.ecno);
}

void SignalInfo::ProcessSignalIntensity(const AppExecFwk::InnerEvent::Pointer &event)
{
    HILOG_INFO("SignalInfo::ProcessSignalIntensity rssi start......\n");
    std::lock_guard<std::mutex> lock(mutex_);
    Rssi *signalIntensity = event->GetSharedObject<Rssi>().get();
    if (!signalIntensity) {
        HILOG_INFO("SignalInfo::ProcessSignalIntensity rssi is nullptr\n");
        return;
    }

    bool gsmUpdate = ProcessGsm(signalIntensity->gw);
    bool cdmaUpdate = ProcessCdma(signalIntensity->cdma);
    if (!gsmUpdate || !cdmaUpdate) {
        std::vector<sptr<SignalInformation>> signals;
        GetSignalInfoList(signals, false);
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifySignalInfoUpdated(signals);
    }
    PrintfLog(*signalIntensity);
}

void SignalInfo::GetSignalInfoList(std::vector<sptr<SignalInformation>> &signals, const bool isLock)
{
    if (isLock) {
        std::lock_guard<std::mutex> lock(mutex_);
    }

    bool gsmValid = gsmSigInfoCur_.ValidateGsmValue();
    bool cdmaValid = cdmaSigInfoCur_.ValidateCdmaValue();
    if (gsmValid) {
        signals.emplace_back(gsmSigInfoCur_.NewInstance());
    }
    if (cdmaValid) {
        signals.emplace_back(cdmaSigInfoCur_.NewInstance());
    }
}
} // namespace OHOS

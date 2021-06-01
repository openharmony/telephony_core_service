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
#ifndef TELEPHONY_CORE_SIGNAL_INFO_H
#define TELEPHONY_CORE_SIGNAL_INFO_H
#include "event_handler.h"
#include "signal_information.h"

namespace OHOS {
class NetworkSearchNotify;
class NetworkSearchState;
struct GsmRssi;
struct CdmaRssi;
class SignalInfo {
public:
    explicit SignalInfo();
    virtual ~SignalInfo() = default;
    void Reset();
    void InitSignalBar(const int bar = 5) const;
    void GetSignalInfoList(std::vector<sptr<SignalInformation>> &signals, const bool isLock = true);
    void ProcessSignalIntensity(const AppExecFwk::InnerEvent::Pointer &event);

private:
    bool ProcessGsm(const GsmRssi &gsmSignal);
    bool ProcessCdma(const CdmaRssi &cdmaSignal);

    std::mutex mutex_;
    GsmSignalInformation gsmSigInfoCache_;
    CdmaSignalInformation cdmaSigInfoCache_;
    GsmSignalInformation gsmSigInfoCur_;
    CdmaSignalInformation cdmaSigInfoCur_;
};
} // namespace OHOS

#endif // TELEPHONY_CORE_SIGNAL_INFO_H

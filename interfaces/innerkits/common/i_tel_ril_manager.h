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

#ifndef CORE_SERVICE_IRIL_MANAGER_H
#define CORE_SERVICE_IRIL_MANAGER_H

#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include "cellular_data_profile.h"
#include "event_handler.h"
#include "event_runner.h"
#include "hril_types.h"

namespace OHOS {
enum ModemPowerState { CORE_SERVICE_POWER_OFF, CORE_SERVICE_POWER_NOT_AVAILABLE, CORE_SERVICE_POWER_ON };

class IRilManager {
public:
    // RilBaseCommands
    virtual void OnInit() = 0;
    virtual void InitTelInfo() = 0;

    virtual void RegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) = 0;
    virtual void UnRegisterPhoneNotify(int what) = 0;

    virtual void SetRadioPower(ModemPowerState radioState) = 0;
    virtual void SetModemRadioPower(bool on, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void ShutDown(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual ModemPowerState GetRadioState() = 0;

    virtual void Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Reject(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void Answer(const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetCallList(const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual void ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void DeactivatePdpContext(
        int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendSmsMoreMode(
        std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response) = 0;

    virtual void ReadIccFile(int32_t command, int32_t fileId, std::string path, int32_t p1, int32_t p2, int32_t p3,
        std::string data, std::string pin2, std::string aid, const AppExecFwk::InnerEvent::Pointer &response) = 0;
    virtual void GetImsi(std::string aid, const AppExecFwk::InnerEvent::Pointer &result) = 0;
    virtual void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result) = 0;

    virtual void TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId) = 0;
};
} // namespace OHOS

#endif // CORE_SERVICE_IRIL_MANAGER_H

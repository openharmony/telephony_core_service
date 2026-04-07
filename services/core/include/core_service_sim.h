/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef CORE_SERVICE_SIM_H
#define CORE_SERVICE_SIM_H

#include "i_raw_parcel_callback.h"
#include "i_sim_manager.h"
#include "event_handler.h"

namespace OHOS {
namespace Telephony {

class CoreServiceSim {
public:
    CoreServiceSim() = default;
    virtual ~CoreServiceSim() = default;

    void SetSimManager(const std::shared_ptr<ISimManager> &simManager);
    const std::shared_ptr<ISimManager> &GetSimManager() const;

    int32_t HasSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback);
    int32_t GetSimState(int32_t slotId, const sptr<IRawParcelCallback> &callback);
    int32_t GetDsdsMode(int32_t &dsdsMode);
    int32_t GetCardType(int32_t slotId, CardType &cardType);
    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode);
    int32_t GetSimSpn(int32_t slotId, std::u16string &spn);
    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId);
    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric);
    int32_t GetIMSI(int32_t slotId, std::u16string &imsi);
    int32_t IsCTSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback);
    bool IsSimActive(int32_t slotId, const sptr<IRawParcelCallback> &callback);
    int32_t GetSlotId(int32_t simId);
    int32_t GetSimId(int32_t slotId);
    std::u16string GetLocaleFromDefaultSim();
    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1);
    std::u16string GetSimGid2(int32_t slotId);
    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired);
    int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    int32_t SetDefaultVoiceSlotId(int32_t slotId);
    int32_t GetDefaultVoiceSlotId();
    int32_t GetDefaultVoiceSimId(const sptr<IRawParcelCallback> &callback);
    int32_t SetPrimarySlotId(int32_t slotId);
    int32_t GetPrimarySlotId(int32_t &slotId);
    int32_t SetShowNumber(int32_t slotId, const std::u16string &number, const sptr<IRawParcelCallback> &callback);
    int32_t GetShowNumber(int32_t slotId, const sptr<IRawParcelCallback> &callback);
    int32_t SetShowName(int32_t slotId, const std::u16string &name, const sptr<IRawParcelCallback> &callback);
    int32_t GetShowName(int32_t slotId, const sptr<IRawParcelCallback> &callback);
    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    int32_t UnlockPin(const int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback);
    int32_t UnlockPuk(const int slotId, const std::u16string &newPin, const std::u16string &puk,
        const sptr<IRawParcelCallback> &callback);
    int32_t AlterPin(const int slotId, const std::u16string &newPin, const std::u16string &oldPin,
         const sptr<IRawParcelCallback> &callback);
    int32_t UnlockPin2(const int32_t slotId, const std::u16string &pin2,
        const sptr<IRawParcelCallback> &callback);
    int32_t UnlockPuk2(const int slotId, const std::u16string &newPin2, const std::u16string &puk2,
        const sptr<IRawParcelCallback> &callback);
    
    int32_t AlterPin2(const int slotId, const std::u16string &newPin2,
        const std::u16string &oldPin2, const sptr<IRawParcelCallback> &callback);
    
    int32_t SetLockState(int32_t slotId, const LockInfo &options, const sptr<IRawParcelCallback> &callback);
    
    int32_t GetLockState(int32_t slotId, LockType lockType, const sptr<IRawParcelCallback> &callback);

    int32_t RefreshSimState(int32_t slotId);

    int32_t SetActiveSim(int32_t slotId, int32_t enable);

    int32_t SetActiveSimSatellite(int32_t slotId, int32_t enable);

    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber);

    std::u16string GetSimTeleNumberIdentifier(const int32_t slotId);

    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier);

    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber);

    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount);

    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount);

    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number);

    int32_t QueryIccDiallingNumbers(int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &reslut);

    int32_t AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);

    int32_t DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);

    int32_t UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);

    int32_t SetVoiceMailInfo(const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    int32_t GetOpKey(int32_t slotId, std::u16string &opkey);

    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt);

    int32_t GetOpName(int32_t slotId, std::u16string &opname);

    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd);

    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd);

    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept);

    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);

    int32_t HasOperatorPrivileges(const int32_t slotId, const sptr<IRawParcelCallback> &callback);

    int32_t SimAuthentication(int32_t slotId, AuthType authType, const std::string &authData,
        SimAuthenticationResponse &response);

    int32_t GetSimIO(int32_t slotId, int32_t command, int32_t fileId, const std::string &data,
        const std::string &path, SimAuthenticationResponse &response);

    int32_t GetAllSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    int32_t GetSimLabel(int32_t slotId, SimLabel &simLabel, const sptr<IRawParcelCallback> &callback);
    int32_t GetRealSimCount();
    int32_t SetSimLabelIndex(int32_t simId, int32_t simLabelIndex, const sptr<IRawParcelCallback> &callback);

private:
    virtual void AsyncSimGeneralExecute(const std::function<void()> task);
    virtual void AsyncSimPinExecute(const std::function<void()> task);
private:
    std::shared_ptr<ISimManager> simManager_;
    std::shared_ptr<AppExecFwk::EventHandler> simGeneralHandler_;
    std::shared_ptr<AppExecFwk::EventHandler> simPinHandler_;
    std::mutex handlerInitMutex_;
};

} // namespace Telephony
} // namespace OHOS

#endif // CORE_SERVICE_SIM_H

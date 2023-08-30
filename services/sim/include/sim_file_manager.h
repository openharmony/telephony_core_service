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

#ifndef OHOS_SIM_FILE_MANAGER_H
#define OHOS_SIM_FILE_MANAGER_H

#include "event_handler.h"
#include "event_runner.h"
#include "hril_modem_parcel.h"
#include "sim_file_controller.h"
#include "usim_file_controller.h"
#include "i_tel_ril_manager.h"
#include "ruim_file.h"
#include "ruim_file_controller.h"
#include "sim_file.h"
#include "isim_file.h"
#include "isim_file_controller.h"
#include "csim_file_controller.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class SimFileManager : public AppExecFwk::EventHandler {
public:
    using HANDLE = std::shared_ptr<AppExecFwk::EventHandler>;
    SimFileManager(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        std::weak_ptr<Telephony::ITelRilManager> telRilManager, std::weak_ptr<Telephony::SimStateManager> state);
    virtual ~SimFileManager();
    void Init(int slotId);
    void ClearData();
    std::u16string GetSimOperatorNumeric();
    std::u16string GetISOCountryCodeForSim();
    std::u16string GetSimSpn();
    std::u16string GetSimEons(const std::string &plmn, int32_t lac, bool longNameRequired);
    std::u16string GetSimIccId();
    std::u16string GetIMSI();
    std::u16string GetLocaleFromDefaultSim();
    std::u16string GetSimGid1();
    std::u16string GetSimGid2();
    std::u16string GetSimTelephoneNumber();
    std::u16string GetSimTeleNumberIdentifier();
    std::u16string GetSimIst();
    std::u16string GetVoiceMailIdentifier();
    std::u16string GetVoiceMailNumber();
    int32_t GetVoiceMailCount();
    bool SetVoiceMailCount(int32_t voiceMailCount);
    bool SetVoiceCallForwarding(bool enable, const std::string &number);
    std::u16string GetOpName();
    std::u16string GetOpKey();
    std::u16string GetOpKeyExt();
    void SetOpName(const std::string &opName);
    void SetOpKey(const std::string &opKey);
    void SetOpKeyExt(const std::string &opKeyExt);
    int ObtainSpnCondition(bool roaming, const std::string &operatorNum);
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);
    void SetImsi(std::string imsi);
    std::shared_ptr<IccFile> GetIccFile();
    std::shared_ptr<IccFileController> GetIccFileController();
    std::shared_ptr<IccDiallingNumbersHandler> ObtainDiallingNumberHandler();
    bool SetVoiceMailInfo(const std::u16string &mailName, const std::u16string &mailNumber);
    bool HasSimCard();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    static std::shared_ptr<SimFileManager> CreateInstance(
        std::weak_ptr<Telephony::ITelRilManager> ril, std::weak_ptr<SimStateManager> simState);
    enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };
    enum class IccType { ICC_TYPE_CDMA, ICC_TYPE_GSM, ICC_TYPE_IMS, ICC_TYPE_USIM };

protected:
    std::weak_ptr<Telephony::ITelRilManager> telRilManager_;
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    std::shared_ptr<IccFile> simFile_ = nullptr;
    std::shared_ptr<IccDiallingNumbersHandler> diallingNumberHandler_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopFileController_ = nullptr;
    HandleRunningState stateRecord_ = HandleRunningState::STATE_NOT_START;
    HandleRunningState stateHandler_ = HandleRunningState::STATE_NOT_START;
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    int slotId_ = 0;
    IccType iccType_ = IccType::ICC_TYPE_USIM;
    std::map<IccType, std::shared_ptr<IccFile>> iccFileCache_;
    std::map<IccType, std::shared_ptr<IccFileController>> iccFileControllerCache_;

private:
    bool InitDiallingNumberHandler();
    IccType GetIccTypeByCardType(CardType type);
    IccType GetIccTypeByTech(const std::shared_ptr<VoiceRadioTechnology> &tech);
    bool InitSimFile(IccType type);
    bool InitIccFileController(IccType type);
    void ChangeSimFileByCardType(IccType type);
    bool IsValidType(IccType type);
    std::string opName_;
    std::string opKey_;
    std::string opKeyExt_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_FILE_MANAGER_H
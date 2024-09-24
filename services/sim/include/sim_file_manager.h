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

#include "common_event_subscriber.h"
#include "event_handler.h"
#include "event_runner.h"
#include "tel_ril_modem_parcel.h"
#include "i_tel_ril_manager.h"
#include "isim_file.h"
#include "isim_file_controller.h"
#include "ruim_file.h"
#include "ruim_file_controller.h"
#include "sim_file.h"
#include "sim_file_controller.h"
#include "system_ability_status_change_stub.h"
#include "isim_file.h"
#include "isim_file_controller.h"
#include "csim_file_controller.h"
#include "telephony_log_wrapper.h"
#include "usim_file_controller.h"

namespace OHOS {
namespace Telephony {
class SimFileManager : public TelEventHandler, public EventFwk::CommonEventSubscriber {
public:
    using HANDLE = std::shared_ptr<AppExecFwk::EventHandler>;
    SimFileManager(
        const EventFwk::CommonEventSubscribeInfo &sp, std::weak_ptr<Telephony::ITelRilManager> telRilManager,
        std::weak_ptr<Telephony::SimStateManager> state);
    virtual ~SimFileManager();
    void Init(int slotId);
    void ClearData();
    std::u16string GetSimOperatorNumeric();
    std::u16string GetISOCountryCodeForSim();
    std::u16string GetSimSpn();
    std::u16string GetSimEons(const std::string &plmn, int32_t lac, bool longNameRequired);
    std::u16string GetSimIccId();
    std::u16string GetSimDecIccId();
    std::u16string GetIMSI();
    std::u16string GetMCC();
    std::u16string GetMNC();
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
    bool SetSimTelephoneNumber(const std::u16string &alphaTag, const std::u16string &phoneNumber);
    bool HasSimCard();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
    void DeleteOperatorCache();
    void UpdateOpkeyConfig();
    bool IsCTSimCard();
    static std::shared_ptr<SimFileManager> CreateInstance(
        std::weak_ptr<Telephony::ITelRilManager> ril, std::weak_ptr<SimStateManager> simState);
    enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };
    enum class IccType { ICC_TYPE_CDMA, ICC_TYPE_GSM, ICC_TYPE_IMS, ICC_TYPE_USIM };
    ResponseEsimResult PrepareDownload(
        int32_t portIndex,
        const std::u16string &hashCc,
        const std::u16string &smdpSigned2,
        const std::u16string &smdpSignature2,
        const std::u16string &smdpCertificate);
    ResponseEsimBppResult LoadBoundProfilePackage(int32_t portIndex, const std::u16string &boundProfilePackage);
    EuiccNotificationList ListNotifications(int32_t portIndex, Event events);

protected:
    std::weak_ptr<Telephony::ITelRilManager> telRilManager_;
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    std::shared_ptr<IccFile> simFile_ = nullptr;
    std::shared_ptr<IccDiallingNumbersHandler> diallingNumberHandler_ = nullptr;
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
    bool IsCTCardType(CardType type);
    bool IsCTIccId(std::string iccId);
    std::string opName_;
    std::string opKey_;
    std::string opKeyExt_;

    const std::string VM_NUMBER_KEY = "persist.telephony.voicemail.gsm";
    const std::string VM_NUMBER_CDMA_KEY = "persist.telephony.voicemail.cdma";
    void SetVoiceMailParamGsm(const std::u16string mailNumber, bool isSavedIccRecords);
    void SetVoiceMailParamCdma(const std::u16string mailNumber);
    std::string GetVoiceMailNumberKey();
    std::string GetVoiceMailNumberCdmaKey();
    std::string GetVoiceMailNumberFromParam();
    void SetVoiceMailSimImsiParam(std::string imsi);
    void StoreVoiceMailNumber(const std::u16string mailNumber, bool isSavedIccRecoeds);
    std::string GetVoiceMailSimImsiFromParam();
    void HandleSimRecordsLoaded();
    void HandleSimIccidLoaded(std::string iccid);
    bool IsPhoneTypeGsm(int32_t slotId);
    std::string EncryptImsi(const std::string imsi);
    bool IsEncryptImsiEmpty(const std::string encryptImsi);
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_FILE_MANAGER_H

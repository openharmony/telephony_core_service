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

#ifndef OHOS_ICC_FILE_H
#define OHOS_ICC_FILE_H

#include "event_handler.h"
#include "event_runner.h"
#include "i_tel_ril_manager.h"
#include "mcc_pool.h"
#include "observer_handler.h"
#include "plmn_file.h"
#include "sim_constant.h"
#include "icc_file_controller.h"
#include "sim_state_manager.h"
#include "telephony_log_wrapper.h"
#include "usim_function_handle.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "want.h"
#include "icc_dialling_numbers_handler.h"

namespace OHOS {
namespace Telephony {
class IccFile : public AppExecFwk::EventHandler {
public:
    IccFile(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimStateManager> simStateManager);
    virtual void Init();
    virtual void StartLoad();
    std::string ObtainIMSI();
    void UpdateImsi(std::string imsi);
    std::string ObtainIccId();
    std::string ObtainGid1();
    std::string ObtainGid2();
    std::string ObtainMsisdnNumber();
    virtual std::string ObtainSimOperator();
    virtual std::string ObtainIsoCountryCode();
    virtual int ObtainCallForwardStatus();
    virtual int ObtainSpnCondition(bool roaming, const std::string &operatorNum) = 0;
    bool LoadedOrNot();
    void UpdateLoaded(bool loaded);
    virtual void UpdateMsisdnNumber(
        const std::string &alphaTag, const std::string &number, const AppExecFwk::InnerEvent::Pointer &onComplete);
    virtual void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    virtual ~IccFile();
    virtual bool ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event) = 0;
    std::string ObtainDiallingNumberInfo();
    std::string ObtainNAI();
    std::string ObtainHomeNameOfPnn();
    std::string ObtainMsisdnAlphaStatus();
    std::string ObtainVoiceMailNumber();
    std::string ObtainSPN();
    std::string ObtainVoiceMailInfo();
    bool ObtainFilesFetched();
    std::string ObtainIccLanguage();
    virtual std::shared_ptr<UsimFunctionHandle> ObtainUsimFunctionHandle();
    std::string ObtainSpNameFromEfSpn();
    int ObtainLengthOfMnc();
    virtual void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    virtual void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);
    void SetRilAndFileController(const std::shared_ptr<Telephony::ITelRilManager> &ril,
         const std::shared_ptr<IccFileController> &file, const std::shared_ptr<IccDiallingNumbersHandler> &handler);
    struct IccFileLoaded {
        virtual std::string ObtainElementaryFileName() = 0;
        virtual void ProcessParseFile(const AppExecFwk::InnerEvent::Pointer &event) = 0;
    };
    virtual bool UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber) = 0;
    bool HasSimCard();
    virtual void UnInit();
    void SetId(int id)
    {
        slotId_ = id;
    }

protected:
    virtual void ProcessIccRefresh(int msgId) = 0;
    virtual void ProcessFileLoaded(bool response) = 0;
    virtual void OnAllFilesFetched() = 0;
    bool LockQueriedOrNot();
    void UpdateSPN(const std::string spn);
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    std::shared_ptr<SimStateManager> stateManager_ = nullptr;
    std::string imsi_ = "";
    std::string iccId_ = ""; // decimals
    std::string spn_ = "";
    std::string gid1_ = "";
    std::string gid2_ = "";
    std::string msisdn_ = "";
    std::string msisdnTag_ = "";
    std::string lastMsisdn_ = "";
    std::string lastMsisdnTag_ = "";
    std::string voiceMailNum_ = "";
    std::string voiceMailTag_ = "";
    std::string lastVoiceMailNum_ = "";
    std::string lastVoiceMailTag_ = "";
    std::string operatorNumeric_ = "";
    bool voiceMailFixedOrNot_ = false;
    std::string pnnHomeName_ = "";
    std::string iccLanguage_ = "";
    PlmnFile *hplmnRAT_ = nullptr;
    PlmnFile *oplmnRAT_ = nullptr;
    PlmnFile *plmnRAT_ = nullptr;
    std::string ehplmns_ = "";
    std::string fplmns_ = "";
    int lengthOfMnc_ = DEFAULT_MNC;
    int indexOfMailbox_ = 1;
    int fileToGet_ = 0;
    bool loaded_ = false;
    bool fileQueried_ = false;
    bool lockQueried_ = false;
    bool waitResult_ = false;
    static std::mutex mtx_;
    std::condition_variable processWait_;
    const uint8_t BYTE_NUM = 0xff;
    const int DATA_STEP = 2;
    const std::string SIM_STATE_ACTION = "com.hos.action.SIM_STATE_CHANGED";
    static std::unique_ptr<ObserverHandler> filesFetchedObser_;
    std::unique_ptr<ObserverHandler> lockedFilesFetchedObser_ = nullptr;
    std::unique_ptr<ObserverHandler> networkLockedFilesFetchedObser_ = nullptr;
    std::unique_ptr<ObserverHandler> imsiReadyObser_ = nullptr;
    std::unique_ptr<ObserverHandler> recordsEventsObser_ = nullptr;
    std::unique_ptr<ObserverHandler> networkSelectionModeAutomaticObser_ = nullptr;
    std::unique_ptr<ObserverHandler> spnUpdatedObser_ = nullptr;
    std::unique_ptr<ObserverHandler> recordsOverrideObser_ = nullptr;
    virtual AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId);
    virtual AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId, int arg1, int arg2);
    virtual AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId, std::shared_ptr<void> loader);
    bool PublishSimFileEvent(const std::string &event, int eventCode, const std::string &eventData);
    void UpdateIccLanguage(const std::string &langLi, const std::string &langPl);
    std::string ObtainValidLanguage(const std::string &langData);
    std::shared_ptr<IccDiallingNumbersHandler> diallingNumberHandler_ = nullptr;
    AppExecFwk::InnerEvent::Pointer CreateDiallingNumberPointer(
        int eventid, int efId, int index, std::shared_ptr<void> pobj);
    void NotifyRegistrySimState(CardType type, SimState state, LockReason reason);
    int slotId_ = 0;

private:
    bool ProcessIccFileObtained(const AppExecFwk::InnerEvent::Pointer &event);
    void RegisterImsiLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler);
    void UnregisterImsiLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void RegisterAllFilesLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler);
    void UnregisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ICC_FILE_H

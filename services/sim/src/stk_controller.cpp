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

#include "stk_controller.h"

#include "ability_manager_client.h"
#include "bundle_mgr_proxy.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_publish_info.h"
#include "common_event_support.h"
#include "extension_ability_info.h"
#ifdef CORE_SERVICE_SUPPORT_ESIM
#include "esim_controller.h"
#endif
#include "tel_ril_types.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "radio_event.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const int32_t ICC_CARD_STATE_ABSENT = 0;
const int32_t ICC_CARD_STATE_PRESENT = 1;
const int32_t WAIT_TIME_SECOND = 2; // Set the timeout for sending the stk command
const int32_t PARAMETER_LENGTH = 128;
const int64_t DELAY_TIME = 3000;
const int32_t MAX_RETRY_COUNT = 10;
const int32_t REFRESH_RESULT_FILE_UPDATE = 0;
const std::string PARAM_SLOTID = "slotId";
const std::string PARAM_MSG_CMD = "msgCmd";
const std::string PARAM_CARD_STATUS = "cardStatus";
const std::string PARAM_ALPHA_STRING = "alphaString";
const std::string PARAM_REFRESH_RESULT = "refreshResult";
const std::string STK_BUNDLE = "const.telephony.stk_bundle_name";
const std::string ABILITY_NAME = "ServiceExtAbility";
const std::string DEFAULT_BUNDLE = "";
} // namespace

StkController::StkController(const std::weak_ptr<Telephony::ITelRilManager> &telRilManager,
    const std::weak_ptr<Telephony::SimStateManager> &simStateManager, int32_t slotId)
    : TelEventHandler("StkController"), telRilManager_(telRilManager), simStateManager_(simStateManager),
      slotId_(slotId)
{}

StkController::~StkController()
{
    UnSubscribeListeners();
}

void StkController::Init()
{
    stkBundleName_ = initStkBudleName();
    RegisterEvents();
    if (TELEPHONY_EXT_WRAPPER.initBip_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.initBip_(slotId_);
    }
    InitListener();
}

void StkController::UnSubscribeListeners()
{
    if (bundleScanFinishedSubscriber_ != nullptr &&
        CommonEventManager::UnSubscribeCommonEvent(bundleScanFinishedSubscriber_)) {
        bundleScanFinishedSubscriber_ = nullptr;
        TELEPHONY_LOGI("Unsubscribe Bundle Scan Finished success");
    }
    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy != nullptr) {
            samgrProxy->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, statusChangeListener_);
            statusChangeListener_ = nullptr;
            TELEPHONY_LOGI("Unsubscribe COMMON_EVENT_SERVICE_ID success");
        }
    }
}

void StkController::InitListener()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(*this);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    auto ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility COMMON_EVENT_SERVICE_ID result is %{public}d", ret);
}

void StkController::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    switch (systemAbilityId) {
        case COMMON_EVENT_SERVICE_ID: {
            TELEPHONY_LOGI("COMMON_EVENT_SERVICE_ID is running");
            handler_.SubscribeBundleScanFinished();
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void StkController::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    switch (systemAbilityId) {
        case COMMON_EVENT_SERVICE_ID: {
            handler_.UnSubscribeListeners();
            TELEPHONY_LOGI("COMMON_EVENT_SERVICE_ID stopped");
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void StkController::SubscribeBundleScanFinished()
{
    if (bundleScanFinishedSubscriber_ != nullptr) {
        TELEPHONY_LOGW("Bundle Scan Finished has Subscribed");
        return;
    }
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(BUNDLE_SCAN_FINISHED_EVENT);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(CommonEventSubscribeInfo::COMMON);
    bundleScanFinishedSubscriber_ = std::make_shared<BundleScanFinishedEventSubscriber>(subscriberInfo, *this);
    if (CommonEventManager::SubscribeCommonEvent(bundleScanFinishedSubscriber_)) {
        TELEPHONY_LOGI("Subscribe Bundle Scan Finished success");
    } else {
        bundleScanFinishedSubscriber_ = nullptr;
        TELEPHONY_LOGE("Subscribe Bundle Scan Finished fail");
    }
}

void StkController::BundleScanFinishedEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = want.GetAction();
    TELEPHONY_LOGI("action = %{public}s", action.c_str());
    if (action == BUNDLE_SCAN_FINISHED_EVENT) {
        handler_.OnReceiveBms();
    }
}

void StkController::OnReceiveBms()
{
    if (!retryWant_.GetStringParam(PARAM_MSG_CMD).empty() && !isProactiveCommandSucc) {
        if (remainTryCount_ == 0) {
            remainTryCount_ = MAX_RETRY_COUNT;
            TELEPHONY_LOGI("OnReceiveBms retry send stkdata");
            SendEvent(StkController::RETRY_SEND_RIL_PROACTIVE_COMMAND, 0, DELAY_TIME);
        } else {
            remainTryCount_ = MAX_RETRY_COUNT;
        }
    }
}

std::string StkController::initStkBudleName()
{
    char bundleName[PARAMETER_LENGTH] = { 0 };
    GetParameter(STK_BUNDLE.c_str(), DEFAULT_BUNDLE.c_str(), bundleName, PARAMETER_LENGTH);
    return bundleName;
}

sptr<OHOS::IRemoteObject> StkController::GetBundleMgr()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TELEPHONY_LOGE("Failed to get ability mgr.");
        return nullptr;
    }
    return systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

void StkController::RegisterEvents()
{
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::RegisterEvents() telRilManager is nullptr", slotId_);
        return;
    }
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::RegisterEvents() simStateManager is nullptr", slotId_);
        return;
    }
    simStateManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_SESSION_END, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_PROACTIVE_COMMAND, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_ALPHA_NOTIFY, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_EVENT_NOTIFY, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_CALL_SETUP, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_ICC_REFRESH, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED, nullptr);
}

void StkController::UnRegisterEvents()
{
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::UnRegisterEvents() telRilManager is nullptr", slotId_);
        return;
    }
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::UnRegisterEvents() simStateManager is nullptr", slotId_);
        return;
    }
    simStateManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_SESSION_END);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_PROACTIVE_COMMAND);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_ALPHA_NOTIFY);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_EVENT_NOTIFY);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_CALL_SETUP);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_ICC_REFRESH);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED);
}

void StkController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::ProcessEvent() event is nullptr", slotId_);
        return;
    }
    uint32_t id = event->GetInnerEventId();
    switch (id) {
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            OnIccStateChanged(event);
            break;
        case RadioEvent::RADIO_STK_SESSION_END:
            OnSendRilSessionEnd(event);
            break;
        case RadioEvent::RADIO_STK_PROACTIVE_COMMAND:
            OnSendRilProactiveCommand(event);
            break;
        case RadioEvent::RADIO_STK_ALPHA_NOTIFY:
            OnSendRilAlphaNotify(event);
            break;
        case RadioEvent::RADIO_STK_EVENT_NOTIFY:
            OnSendRilEventNotify(event);
            break;
        case RadioEvent::RADIO_STK_CALL_SETUP:
            TELEPHONY_LOGI("StkController[%{public}d]::ProcessEvent(),"
                " event notify command supplied all the information needed for set up call processing", slotId_);
            break;
        case RadioEvent::RADIO_ICC_REFRESH:
            OnIccRefresh(event);
            break;
        case RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE:
            OnSendTerminalResponseResult(event);
            break;
        case RadioEvent::RADIO_STK_SEND_ENVELOPE:
            OnSendEnvelopeCmdResult(event);
            break;
        case RadioEvent::RADIO_STK_IS_READY:
            TELEPHONY_LOGI("StkController[%{public}d]::ProcessEvent() SimStkIsReady done", slotId_);
            break;
        case RadioEvent::RADIO_STK_SEND_CALL_SETUP_REQUEST_RESULT:
            OnSendCallSetupRequestResult(event);
            break;
        case StkController::RETRY_SEND_RIL_PROACTIVE_COMMAND:
            RetrySendRilProactiveCommand();
            break;
        default:
            ProcessEventExt(id, event);
            break;
    }
}

void StkController::ProcessEventExt(uint32_t id, const AppExecFwk::InnerEvent::Pointer &event)
{
    switch (id) {
        case RadioEvent::RADIO_STATE_CHANGED:
            OnRadioStateChanged(event);
            break;
        default:
            TELEPHONY_LOGE("StkController[%{public}d]::ProcessEvent() unknown event", slotId_);
            break;
    }
}

void StkController::OnIccStateChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnIccStateChanged() simStateManager is nullptr", slotId_);
        return;
    }
    int32_t newState = simStateManager->HasSimCard() ? ICC_CARD_STATE_PRESENT : ICC_CARD_STATE_ABSENT;
    int32_t oldState = iccCardState_;
    iccCardState_ = newState;
    TELEPHONY_LOGI("StkController[%{public}d]::OnIccStateChanged(), oldState: %{public}d newState: %{public}d",
        slotId_, oldState, newState);
    if (oldState == ICC_CARD_STATE_PRESENT && newState == ICC_CARD_STATE_ABSENT) {
        AAFwk::Want want;
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_CARD_STATE_CHANGED);
        want.SetParam(PARAM_SLOTID, slotId_);
        want.SetParam(PARAM_CARD_STATUS, iccCardState_);
        bool publishResult = PublishStkEvent(want);
        TELEPHONY_LOGI("StkController[%{public}d]::OnIccStateChanged() publishResult = %{public}d",
            slotId_, publishResult);
    } else if (oldState == ICC_CARD_STATE_ABSENT && newState == ICC_CARD_STATE_PRESENT) {
        TELEPHONY_LOGI("StkController[%{public}d]::OnIccStateChanged(), call SimStkIsReady()", slotId_);
        auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_IS_READY);
        if (event == nullptr) {
            TELEPHONY_LOGE("StkController[%{public}d]::OnIccStateChanged() event is nullptr", slotId_);
            return;
        }
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager == nullptr) {
            TELEPHONY_LOGE("StkController[%{public}d]::OnIccStateChanged() telRilManager is nullptr", slotId_);
            return;
        }
        telRilManager->SimStkIsReady(slotId_, event);
    }
}

void StkController::OnSendRilSessionEnd(const AppExecFwk::InnerEvent::Pointer &event)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_SESSION_END);
    want.SetParam(PARAM_SLOTID, slotId_);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilSessionEnd() publishResult = %{public}d",
        slotId_, publishResult);
}

std::string SafeSubstr(const std::string& str, size_t pos, size_t len)
{
    if (pos >= str.length()) {
        TELEPHONY_LOGE("string pos abnormal. str: %{public}s  pos: %{public}zu, len: %{public}zu",
            str.c_str(), pos, len);
        return "";
    }

    if (pos + len > str.length()) {
        TELEPHONY_LOGI("string len abnormal: str: %{public}s  pos: %{public}zu, len: %{public}zu",
            str.c_str(), pos, len);
        len = str.length() - pos;
    }

    return str.substr(pos, len);
}

void StkController::HandleStkBipCmd(const std::string &cmdData)
{
    std::string commandLen = SafeSubstr(cmdData, STK_CMD_CMD_LEN_INDEX, STK_CMD_TYPE_LEN);
    uint32_t typeOffset;
    if (commandLen == "") {
        return;
    } else if (commandLen == STK_CMD_CMD_LEN_81) {
        typeOffset = STK_CMD_TYPE_81_INDEX;
    } else if (commandLen == STK_CMD_CMD_LEN_82) {
        typeOffset = STK_CMD_TYPE_82_INDEX;
    } else if (commandLen == STK_CMD_CMD_LEN_83) {
        typeOffset = STK_CMD_TYPE_83_INDEX;
    } else {
        typeOffset = STK_CMD_TYPE_80_INDEX;
    }

    std::string commandType = SafeSubstr(cmdData, typeOffset, STK_CMD_TYPE_LEN);
    if (commandType == STK_BIP_CMD_OPEN_CHANNEL || commandType == STK_BIP_CMD_SEND_DATA ||
        commandType == STK_BIP_CMD_RECEVIE_DATA || commandType == STK_BIP_CMD_GET_CHANNEL_STATUS ||
        commandType == STK_BIP_CMD_CLOSE_CHANNEL || commandType == STK_BIP_CMD_SET_UP_EVENT_LIST) {
        if (TELEPHONY_EXT_WRAPPER.sendEvent_ &&
            TELEPHONY_EXT_WRAPPER.sendEvent_(std::make_shared<std::string>(cmdData), slotId_)) {
                TELEPHONY_LOGI("sendEvent_. slotId_ [%{public}d]", slotId_);
        }
    }
}

void StkController::OnSendRilProactiveCommand(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto stkData = event->GetSharedObject<std::string>();
    if (stkData == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendRilProactiveCommand() stkData is nullptr", slotId_);
        return;
    }

    std::string cmdData = (std::string)*stkData;
    HandleStkBipCmd(cmdData);

#ifdef CORE_SERVICE_SUPPORT_ESIM
    if (EsimController::GetInstance().ChecIsVerifyBindCommand(cmdData)) {
        EsimController::GetInstance().ProcessCommandMessage(slotId_, cmdData);
        return;
    }
#endif

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_COMMAND);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_MSG_CMD, cmdData);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilProactiveCommand() stkData = %{public}s "
        "publishResult = %{public}d", slotId_, cmdData.c_str(), publishResult);
    if (!publishResult) {
        retryWant_ = want;
        remainTryCount_ = MAX_RETRY_COUNT;
        SendEvent(StkController::RETRY_SEND_RIL_PROACTIVE_COMMAND, 0, DELAY_TIME);
        return;
    }
    isProactiveCommandSucc = true;
    remainTryCount_ = 0;
}

void StkController::RetrySendRilProactiveCommand()
{
    remainTryCount_--;
    TELEPHONY_LOGI("StkController[%{public}d], remainTryCount_ is %{public}d", slotId_, remainTryCount_);
    if (remainTryCount_ > 0) {
        if (!PublishStkEvent(retryWant_)) {
            SendEvent(StkController::RETRY_SEND_RIL_PROACTIVE_COMMAND, 0, DELAY_TIME);
            return;
        }
        TELEPHONY_LOGI("StkController[%{public}d] retry sucess", slotId_);
        isProactiveCommandSucc = true;
        remainTryCount_ = 0;
        return;
    }
    TELEPHONY_LOGI("StkController[%{public}d] stop retry", slotId_);
}

void StkController::OnSendRilAlphaNotify(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto alphaData = event->GetSharedObject<std::string>();
    if (alphaData == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendRilAlphaNotify() alphaData is nullptr", slotId_);
        return;
    }
    std::string cmdData = (std::string)*alphaData;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_ALPHA_IDENTIFIER);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_ALPHA_STRING, cmdData);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilAlphaNotify() alphaData = %{public}s "
        "publishResult = %{public}d", slotId_, cmdData.c_str(), publishResult);
}

void StkController::OnSendRilEventNotify(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto eventData = event->GetSharedObject<std::string>();
    if (eventData == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendRilEventNotify() eventData is nullptr", slotId_);
        return;
    }
    std::string cmdData = (std::string)*eventData;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_COMMAND);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_MSG_CMD, cmdData);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilEventNotify() eventData = %{public}s "
        "publishResult = %{public}d", slotId_, cmdData.c_str(), publishResult);
}

void StkController::OnIccRefresh(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto refreshResult = event->GetSharedObject<int32_t>();
    int32_t result = REFRESH_RESULT_FILE_UPDATE;
    if (refreshResult == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnIccRefresh() refreshResult is nullptr", slotId_);
    } else {
        result = (int32_t)*refreshResult;
    }
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_CARD_STATE_CHANGED);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_CARD_STATUS, ICC_CARD_STATE_PRESENT);
    want.SetParam(PARAM_REFRESH_RESULT, result);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnIccRefresh() refresh result = %{public}d publishResult = %{public}d",
        slotId_, result, publishResult);
}

bool StkController::PublishStkEvent(AAFwk::Want &want)
{
    if (stkBundleName_.empty()) {
        TELEPHONY_LOGE("stkBundleName_ is empty");
        return false;
    }
    if (!CheckIsSystemApp(stkBundleName_)) {
        TELEPHONY_LOGE("is not system app");
        return false;
    }
    AppExecFwk::ElementName element("", stkBundleName_, ABILITY_NAME);
    want.SetElement(element);
    int32_t accountId = -1;
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
        want, nullptr, accountId, AppExecFwk::ExtensionAbilityType::SERVICE);
    return ret == 0;
}

bool StkController::CheckIsSystemApp(const std::string &bundleName)
{
    sptr<OHOS::IRemoteObject> remoteObject = GetBundleMgr();
    if (remoteObject == nullptr) {
        TELEPHONY_LOGE("error to get bundleMgr");
        return false;
    }
    sptr<AppExecFwk::IBundleMgr> iBundleMgr = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        TELEPHONY_LOGE("iBundleMgr is null");
        return false;
    }
    OHOS::AppExecFwk::BundleInfo info;
    info.applicationInfo.isSystemApp = false;
    if (!iBundleMgr->GetBundleInfo(
        bundleName, OHOS::AppExecFwk::GET_BUNDLE_DEFAULT, info, AppExecFwk::Constants::ALL_USERID)) {
        TELEPHONY_LOGE("Failed to get bundleInfo from bundleMgr");
    } else {
        TELEPHONY_LOGI("isSystemApp =%{public}d", info.applicationInfo.isSystemApp);
    }
    return info.applicationInfo.isSystemApp;
}

int32_t StkController::SendTerminalResponseCmd(const std::string &strCmd)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE);
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendTerminalResponseCmd() event is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    event->SetOwner(shared_from_this());
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendTerminalResponseCmd() telRilManager is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::unique_lock<std::mutex> terminalResponselock(stkMutex_);
    terminalResponseResult_ = 0;
    responseFinished_ = false;
    telRilManager->SendTerminalResponseCmd(slotId_, strCmd, event);
    while (!responseFinished_) {
        TELEPHONY_LOGI("StkController[%{public}d]::SendTerminalResponseCmd() wait for the response to finish", slotId_);
        if (stkCv_.wait_for(terminalResponselock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            TELEPHONY_LOGE("StkController[%{public}d]::SendTerminalResponseCmd() wait timeout", slotId_);
            break;
        }
    }
    if (!responseFinished_) {
        TELEPHONY_LOGE("ril cmd fail");
        return TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t StkController::SendEnvelopeCmd(const std::string &strCmd)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_ENVELOPE);
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendEnvelopeCmd() event is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    event->SetOwner(shared_from_this());
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendEnvelopeCmd() telRilManager is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::unique_lock<std::mutex> envelopelock(stkMutex_);
    envelopeResponseResult_ = 0;
    responseFinished_ = false;
    telRilManager->SendEnvelopeCmd(slotId_, strCmd, event);
    while (!responseFinished_) {
        TELEPHONY_LOGI("StkController[%{public}d]::SendEnvelopeCmd() wait for the response to finish", slotId_);
        if (stkCv_.wait_for(envelopelock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            TELEPHONY_LOGE("StkController[%{public}d]::SendEnvelopeCmd() wait timeout", slotId_);
            break;
        }
    }
    if (!responseFinished_) {
        TELEPHONY_LOGE("ril cmd fail");
        return TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t StkController::SendCallSetupRequestResult(bool accept)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_CALL_SETUP_REQUEST_RESULT);
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendCallSetupRequestResult() event is nullptr", slotId_);
        return TELEPHONY_ERR_FAIL;
    }
    event->SetOwner(shared_from_this());
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendCallSetupRequestResult() telRilManager is nullptr", slotId_);
        return TELEPHONY_ERR_FAIL;
    }

    std::unique_lock<std::mutex> callSetupRequestlock(stkMutex_);
    callSetupResponseResult_ = TELEPHONY_ERR_FAIL;
    responseFinished_ = false;
    telRilManager->SendCallSetupRequestResult(slotId_, accept, event);
    while (!responseFinished_) {
        TELEPHONY_LOGI(
            "StkController[%{public}d]::SendCallSetupRequestResult() wait for the response to finish", slotId_);
        if (stkCv_.wait_for(callSetupRequestlock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            TELEPHONY_LOGE("StkController[%{public}d]::SendCallSetupRequestResult() wait timeout", slotId_);
            responseFinished_ = true;
        }
    }
    return callSetupResponseResult_;
}

void StkController::OnSendTerminalResponseResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendTerminalResponseResult() event is nullptr", slotId_);
        return;
    }
    std::shared_ptr<RadioResponseInfo> response = event->GetSharedObject<RadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendTerminalResponseResult() response is nullptr", slotId_);
        return;
    }
    terminalResponseResult_ = response->error == ErrType::NONE;
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendTerminalResponseResult(), result = %{public}d",
        slotId_, terminalResponseResult_);
    responseFinished_ = true;
    stkCv_.notify_one();
}

void StkController::OnSendEnvelopeCmdResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendEnvelopeCmdResult() event is nullptr", slotId_);
        return;
    }
    std::shared_ptr<RadioResponseInfo> response = event->GetSharedObject<RadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendEnvelopeCmdResult() response is nullptr", slotId_);
        return;
    }
    envelopeResponseResult_ = response->error == ErrType::NONE;
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendEnvelopeCmdResult(), result = %{public}d",
        slotId_, envelopeResponseResult_);
    responseFinished_ = true;
    stkCv_.notify_one();
}

void StkController::OnSendCallSetupRequestResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendCallSetupRequestResult() event is nullptr", slotId_);
        return;
    }
    std::shared_ptr<RadioResponseInfo> response = event->GetSharedObject<RadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendCallSetupRequestResult() response is nullptr", slotId_);
        return;
    }
    callSetupResponseResult_ = response->error == ErrType::NONE ? TELEPHONY_ERR_SUCCESS : TELEPHONY_ERR_FAIL;
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendCallSetupRequestResult(), result = %{public}d",
        slotId_, callSetupResponseResult_);
    responseFinished_ = true;
    stkCv_.notify_one();
}

void StkController::OnRadioStateChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<Int32Parcel> object = event->GetSharedObject<Int32Parcel>();
    if (object == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnRadioStateChanged object is nullptr", slotId_);
        return;
    }

    int32_t radioState = object->data;
    if (radioState == CORE_SERVICE_POWER_NOT_AVAILABLE) {
        TELEPHONY_LOGI("StkController[%{public}d]::OnRadioStateChanged radioState: -1, iccCardState: %{public}d "
            "set to absent", slotId_, iccCardState_);
        iccCardState_ = ICC_CARD_STATE_ABSENT;
    }
}

} // namespace Telephony
} // namespace OHOS

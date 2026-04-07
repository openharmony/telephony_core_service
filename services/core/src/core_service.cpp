/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "core_service.h"

#include "core_manager_inner.h"
#include "core_service_dump_helper.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_publish_info.h"
#include "ffrt_inner.h"
#include "ims_core_service_client.h"
#include "network_search_manager.h"
#include "network_search_types.h"
#include "tel_ril_manager.h"
#include "sim_constant.h"
#include "parameter.h"
#include "sim_manager.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "telephony_common_utils.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"
#ifdef CORE_SERVICE_SUPPORT_ESIM
#include "esim_manager.h"
#endif
#include "core_service_common_event_hub.h"

namespace OHOS {
namespace Telephony {
namespace {
const int32_t MAX_FFRT_THREAD_NUM = 32;
}
const bool G_REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<CoreService>::GetInstance().get());

CoreService::CoreService() : SystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, true)
{
    coreServiceSim_ = std::make_shared<CoreServiceSim>();
}

CoreService::~CoreService() {}

void CoreService::OnStart()
{
    bindTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("CoreService has already started.");
        return;
    }

    if (!registerToService_) {
        bool ret = Publish(DelayedSingleton<CoreService>::GetInstance().get());
        if (!ret) {
            TELEPHONY_LOGE("CoreService::Init Publish failed!");
            return;
        }
        registerToService_ = true;
    }
    int ffrtRet = ffrt_set_cpu_worker_max_num(ffrt::qos_default, MAX_FFRT_THREAD_NUM);
    if (ffrtRet == -1) {
        TELEPHONY_LOGE("ffrt_set_cpu_worker_max_num fail");
    }
    if (!Init()) {
        TELEPHONY_LOGE("failed to init CoreService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    endTime_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    bool res = NotifyCoreServiceReady();
    TELEPHONY_LOGI("CoreService start success, notify [%{public}d]", res);
}

bool CoreService::Init()
{
    TELEPHONY_LOGI("CoreService::Init");
    auto coreServiceCommonEventHub = std::make_shared<CoreServiceCommonEventHub>();
    coreServiceCommonEventHub->Init();
    CoreManagerInner::GetInstance().SetCommonEventHubObj(coreServiceCommonEventHub);
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_EXT
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
#endif
    telRilManager_ = std::make_shared<TelRilManager>();
    if (!telRilManager_->OnInit()) {
        TELEPHONY_LOGE("TelRilManager init is failed!");
        return false;
    }
    CoreManagerInner::GetInstance().SetTelRilMangerObj(telRilManager_);
    int32_t slotCount = GetMaxSimCount();
#ifdef CORE_SERVICE_SUPPORT_ESIM
    esimManager_ = std::make_shared<EsimManager>(telRilManager_);
    esimManager_->OnInit(slotCount);
    CoreManagerInner::GetInstance().SetEsimManagerObj(esimManager_);
#endif
    simManager_ = std::make_shared<SimManager>(telRilManager_);
    simManager_->OnInit(slotCount);
    coreServiceSim_->SetSimManager(simManager_);
    // connect ims_service
    DelayedSingleton<ImsCoreServiceClient>::GetInstance()->Init();
    networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager_, simManager_);
    if (!networkSearchManager_->OnInit()) {
        TELEPHONY_LOGE("NetworkSearchManager init is failed!");
        return false;
    }
    CoreManagerInner::GetInstance().OnInit(networkSearchManager_, simManager_, telRilManager_);
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        networkSearchManager_->InitAirplaneMode(slotId);
    }
    TELEPHONY_LOGI("CoreService::Init success");
    return true;
}

bool CoreService::NotifyCoreServiceReady()
{
    AAFwk::Want want;
    want.SetAction("telephony.event.CORE_SERVICE_READY");
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> callPermissions;
    callPermissions.emplace_back(Permission::GET_TELEPHONY_STATE);
    publishInfo.SetSubscriberPermissions(callPermissions);
    return EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo, nullptr);
}

void CoreService::OnStop()
{
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
    DelayedSingleton<ImsCoreServiceClient>::GetInstance()->UnInit();
    networkSearchManager_->DeInit();
    telRilManager_->DeInit();
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_EXT
    TELEPHONY_EXT_WRAPPER.DeInitTelephonyExtWrapper();
#endif
    TELEPHONY_LOGI("CoreService Stop success");
}

int32_t CoreService::GetServiceRunningState()
{
    return static_cast<int32_t>(state_);
}

void CoreService::AsyncNetSearchExecute(const std::function<void()> task)
{
    if (networkSearchManagerHandler_ == nullptr) {
        std::lock_guard<std::mutex> lock(handlerInitMutex_);
        if (networkSearchManagerHandler_ == nullptr) {
            auto networkSearchRunner = AppExecFwk::EventRunner::Create("networkSearchHandler",
                AppExecFwk::ThreadMode::FFRT);
            networkSearchManagerHandler_ = std::make_shared<AppExecFwk::EventHandler>(networkSearchRunner);
        }
    }
    networkSearchManagerHandler_->PostTask(task);
}

void CoreService::AsyncSimGeneralExecute(const std::function<void()> task)
{
    if (simGeneralHandler_ == nullptr) {
        std::lock_guard<std::mutex> lock(handlerInitMutex_);
        if (simGeneralHandler_ == nullptr) {
            auto simManagerRunner = AppExecFwk::EventRunner::Create("simManagerHandler",
                AppExecFwk::ThreadMode::FFRT);
            simGeneralHandler_ = std::make_shared<AppExecFwk::EventHandler>(simManagerRunner);
        }
    }
    simGeneralHandler_->PostTask(task);
}

void CoreService::AsyncSimPinExecute(const std::function<void()> task)
{
    if (simPinHandler_ == nullptr) {
        std::lock_guard<std::mutex> lock(handlerInitMutex_);
        if (simPinHandler_ == nullptr) {
            auto simManagerRunner = AppExecFwk::EventRunner::Create("simPinManagerHandler",
                AppExecFwk::ThreadMode::FFRT);
            simPinHandler_ = std::make_shared<AppExecFwk::EventHandler>(simManagerRunner);
        }
    }
    simPinHandler_->PostTask(task);
}

int32_t CoreService::GetPsRadioTech(int32_t slotId, int32_t &psRadioTech)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_NETWORK_INFO)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetPsRadioTech(slotId, psRadioTech);
}

int32_t CoreService::GetCsRadioTech(int32_t slotId, int32_t &csRadioTech)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_NETWORK_INFO)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetCsRadioTech(slotId, csRadioTech);
}

int32_t CoreService::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("CoreService::SetNetworkSelectionMode selectMode:%{public}d", selectMode);
    return networkSearchManager_->SetNetworkSelectionMode(
        slotId, selectMode, networkInformation, resumeSelection, callback);
}

int32_t CoreService::GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetSignalInfoList(slotId, signals);
}

std::u16string CoreService::GetOperatorNumeric(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorNumeric(slotId);
}

std::string CoreService::GetResidentNetworkNumeric(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return "";
    }
    return networkSearchManager_->GetResidentNetworkNumeric(slotId);
}

int32_t CoreService::GetOperatorName(int32_t slotId, std::u16string &operatorName)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetOperatorName(slotId, operatorName);
}

int32_t CoreService::GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_NETWORK_INFO)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkStatus(slotId, networkState);
}

int32_t CoreService::SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("CoreService::SetRadioState --> slotId:%{public}d, isOn:%{public}d", slotId, isOn);
    return networkSearchManager_->SetRadioState(slotId, isOn, 0, callback);
}

int32_t CoreService::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_NETWORK_INFO)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetRadioState(slotId, callback);
}

int32_t CoreService::GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetIsoCountryCodeForNetwork(slotId, countryCode);
}

int32_t CoreService::GetImei(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null or GetImei no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncNetSearchExecute([wp = std::weak_ptr<INetworkSearch>(networkSearchManager_), slotId, callback]() {
        std::u16string imei = u"";
        MessageParcel dataTmp;
        auto networkSearchManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (networkSearchManager) {
            ret = networkSearchManager->GetImei(slotId, imei);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteString16(imei);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetImeiSv(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null or GetImeiSv no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncNetSearchExecute([wp = std::weak_ptr<INetworkSearch>(networkSearchManager_), slotId, callback]() {
        std::u16string imeiSv = u"";
        MessageParcel dataTmp;
        auto networkSearchManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (networkSearchManager) {
            ret = networkSearchManager->GetImeiSv(slotId, imeiSv);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteString16(imeiSv);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetMeid(int32_t slotId, std::u16string &meid)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetMeid(slotId, meid);
}

int32_t CoreService::GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetUniqueDeviceId(slotId, deviceId);
}

bool CoreService::IsNrSupported(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return false;
    }
    return networkSearchManager_->IsNrSupported(slotId);
}

int32_t CoreService::SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->SetNrOptionMode(slotId, mode, callback);
}

int32_t CoreService::GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNrOptionMode(slotId, callback);
}

int32_t CoreService::HasSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->HasSimCard(slotId, callback);
}

int32_t CoreService::GetSimState(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->GetSimState(slotId, callback);
}

int32_t CoreService::GetDsdsMode(int32_t &dsdsMode)
{
    return coreServiceSim_->GetDsdsMode(dsdsMode);
}

int32_t CoreService::GetCardType(int32_t slotId, CardType &cardType)
{
    return coreServiceSim_->GetCardType(slotId, cardType);
}

int32_t CoreService::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    return coreServiceSim_->GetISOCountryCodeForSim(slotId, countryCode);
}

int32_t CoreService::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    return coreServiceSim_->GetSimSpn(slotId, spn);
}

int32_t CoreService::GetSimIccId(int32_t slotId, std::u16string &iccId)
{
    return coreServiceSim_->GetSimIccId(slotId, iccId);
}

int32_t CoreService::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    return coreServiceSim_->GetSimOperatorNumeric(slotId, operatorNumeric);
}

int32_t CoreService::GetIMSI(int32_t slotId, std::u16string &imsi)
{
    return coreServiceSim_->GetIMSI(slotId, imsi);
}

int32_t CoreService::IsCTSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->IsCTSimCard(slotId, callback);
}

bool CoreService::IsSimActive(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->IsSimActive(slotId, callback);
}

int32_t CoreService::GetSlotId(int32_t simId)
{
    return coreServiceSim_->GetSlotId(simId);
}

int32_t CoreService::GetSimId(int32_t slotId)
{
    return coreServiceSim_->GetSimId(slotId);
}

int32_t CoreService::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkSearchInformation(slotId, callback);
}

int32_t CoreService::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkSelectionMode(slotId, callback);
}

std::u16string CoreService::GetLocaleFromDefaultSim()
{
    return coreServiceSim_->GetLocaleFromDefaultSim();
}

int32_t CoreService::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    return coreServiceSim_->GetSimGid1(slotId, gid1);
}

std::u16string CoreService::GetSimGid2(int32_t slotId)
{
    return coreServiceSim_->GetSimGid2(slotId);
}

std::u16string CoreService::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired)
{
    return coreServiceSim_->GetSimEons(slotId, plmn, lac, longNameRequired);
}

int32_t CoreService::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    return coreServiceSim_->GetSimAccountInfo(slotId, info);
}

int32_t CoreService::SetDefaultVoiceSlotId(int32_t slotId)
{
    return coreServiceSim_->SetDefaultVoiceSlotId(slotId);
}

int32_t CoreService::GetDefaultVoiceSlotId()
{
    return coreServiceSim_->GetDefaultVoiceSlotId();
}

int32_t CoreService::GetDefaultVoiceSimId(const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->GetDefaultVoiceSimId(callback);
}

int32_t CoreService::SetPrimarySlotId(int32_t slotId)
{
    return coreServiceSim_->SetPrimarySlotId(slotId);
}

int32_t CoreService::GetPrimarySlotId(int32_t &slotId)
{
    return coreServiceSim_->GetPrimarySlotId(slotId);
}

int32_t CoreService::SetShowNumber(int32_t slotId, const std::u16string &number,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->SetShowNumber(slotId, number, callback);
}

int32_t CoreService::GetShowNumber(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->GetShowNumber(slotId, callback);
}

int32_t CoreService::SetShowName(int32_t slotId, const std::u16string &name,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->SetShowName(slotId, name, callback);
}

int32_t CoreService::GetShowName(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->GetShowName(slotId, callback);
}

int32_t CoreService::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    return coreServiceSim_->GetActiveSimAccountInfoList(iccAccountInfoList);
}

int32_t CoreService::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    return coreServiceSim_->GetOperatorConfigs(slotId, poc);
}

int32_t CoreService::UnlockPin(const int32_t slotId, const std::u16string &pin,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->UnlockPin(slotId, pin, callback);
}

int32_t CoreService::UnlockPuk(const int slotId, const std::u16string &newPin, const std::u16string &puk,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->UnlockPuk(slotId, newPin, puk, callback);
}

int32_t CoreService::AlterPin(const int slotId, const std::u16string &newPin, const std::u16string &oldPin,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->AlterPin(slotId, newPin, oldPin, callback);
}

int32_t CoreService::UnlockPin2(const int32_t slotId, const std::u16string &pin2,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->UnlockPin2(slotId, pin2, callback);
}

int32_t CoreService::UnlockPuk2(const int slotId, const std::u16string &newPin2, const std::u16string &puk2,
    const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->UnlockPuk2(slotId, newPin2, puk2, callback);
}

int32_t CoreService::AlterPin2(const int slotId, const std::u16string &newPin2,
    const std::u16string &oldPin2, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->AlterPin2(slotId, newPin2, oldPin2, callback);
}

int32_t CoreService::SetLockState(int32_t slotId, const LockInfo &options, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->SetLockState(slotId, options, callback);
}

int32_t CoreService::GetLockState(int32_t slotId, LockType lockType, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->GetLockState(slotId, lockType, callback);
}

int32_t CoreService::RefreshSimState(int32_t slotId)
{
    return coreServiceSim_->RefreshSimState(slotId);
}

int32_t CoreService::SetActiveSim(int32_t slotId, int32_t enable)
{
    return coreServiceSim_->SetActiveSim(slotId, enable);
}

int32_t CoreService::SetActiveSimSatellite(int32_t slotId, int32_t enable)
{
    return coreServiceSim_->SetActiveSimSatellite(slotId, enable);
}

int32_t CoreService::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetPreferredNetwork(slotId, callback);
}

int32_t CoreService::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->SetPreferredNetwork(slotId, networkMode, callback);
}

int32_t CoreService::GetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkCapability(slotId, networkCapabilityType, networkCapabilityState);
}

int32_t CoreService::SetNetworkCapability(int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->SetNetworkCapability(slotId, networkCapabilityType, networkCapabilityState);
}

int32_t CoreService::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
{
    return coreServiceSim_->GetSimTelephoneNumber(slotId, telephoneNumber);
}

std::u16string CoreService::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    return coreServiceSim_->GetSimTeleNumberIdentifier(slotId);
}

int32_t CoreService::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
{
    return coreServiceSim_->GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
}

int32_t CoreService::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
{
    return coreServiceSim_->GetVoiceMailNumber(slotId, voiceMailNumber);
}

int32_t CoreService::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    return coreServiceSim_->GetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreService::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    return coreServiceSim_->SetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreService::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    return coreServiceSim_->SetVoiceCallForwarding(slotId, enable, number);
}

int32_t CoreService::QueryIccDiallingNumbers(
    int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &reslut)
{
    return coreServiceSim_->QueryIccDiallingNumbers(slotId, type, reslut);
}

int32_t CoreService::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    return coreServiceSim_->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreService::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    return coreServiceSim_->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreService::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    return coreServiceSim_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreService::SetVoiceMailInfo(
    const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    return coreServiceSim_->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t CoreService::GetMaxSimCount()
{
    return SIM_SLOT_COUNT;
}

int32_t CoreService::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    return coreServiceSim_->GetOpKey(slotId, opkey);
}

int32_t CoreService::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    return coreServiceSim_->GetOpKeyExt(slotId, opkeyExt);
}

int32_t CoreService::GetOpName(int32_t slotId, std::u16string &opname)
{
    return coreServiceSim_->GetOpName(slotId, opname);
}

int32_t CoreService::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    return coreServiceSim_->SendEnvelopeCmd(slotId, cmd);
}

int32_t CoreService::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    return coreServiceSim_->SendTerminalResponseCmd(slotId, cmd);
}

int32_t CoreService::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    return coreServiceSim_->SendCallSetupRequestResult(slotId, accept);
}

int32_t CoreService::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    return coreServiceSim_->UnlockSimLock(slotId, lockInfo, response);
}

int32_t CoreService::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info)
{
    TELEPHONY_LOGI("CoreService::GetImsRegStatus --> slotId:%{public}d, imsSrvType:%{public}d", slotId, imsSrvType);
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:GET_TELEPHONY_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("failed! network search manager is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetImsRegStatus(slotId, imsSrvType, info);
}

int32_t CoreService::GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::CELL_LOCATION)) {
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetCellInfoList(slotId, cellInfo);
}

int32_t CoreService::GetNeighboringCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::CELL_LOCATION)) {
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNeighboringCellInfoList(slotId, cellInfo);
}

int32_t CoreService::SendUpdateCellLocationRequest(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::CELL_LOCATION)) {
        TELEPHONY_LOGE("CoreService::SendUpdateCellLocationRequest, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->SendUpdateCellLocationRequest(slotId);
}

int32_t CoreService::HasOperatorPrivileges(const int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->HasOperatorPrivileges(slotId, callback);
}

int32_t CoreService::SimAuthentication(
    int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response)
{
    return coreServiceSim_->SimAuthentication(slotId, authType, authData, response);
}

int32_t CoreService::RegisterImsRegInfoCallback(
    int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:GET_TELEPHONY_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("failed! network search manager is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->RegisterImsRegInfoCallback(slotId, imsSrvType, GetTokenID(), callback);
}

int32_t CoreService::UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:GET_TELEPHONY_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("failed! network search manager is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->UnregisterImsRegInfoCallback(slotId, imsSrvType, GetTokenID());
}

int32_t CoreService::GetBasebandVersion(int32_t slotId, std::string &version)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:GET_TELEPHONY_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetBasebandVersion(slotId, version);
}

int32_t CoreService::FactoryReset(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->FactoryReset(slotId);
}

int32_t CoreService::Dump(std::int32_t fd, const std::vector<std::u16string> &args)
{
    if (fd < 0) {
        TELEPHONY_LOGE("dump fd invalid");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::vector<std::string> argsInStr;
    for (const auto &arg : args) {
        TELEPHONY_LOGI("Dump args: %s", Str16ToStr8(arg).c_str());
        argsInStr.emplace_back(Str16ToStr8(arg));
    }
    std::string result;
    CoreServiceDumpHelper dumpHelper;
    if (dumpHelper.Dump(argsInStr, result)) {
        TELEPHONY_LOGI("%s", result.c_str());
        std::int32_t ret = dprintf(fd, "%s", result.c_str());
        if (ret < 0) {
            TELEPHONY_LOGE("dprintf to dump fd failed");
            return TELEPHONY_ERROR;
        }
        return 0;
    }
    TELEPHONY_LOGW("dumpHelper failed");
    return TELEPHONY_ERROR;
}

int64_t CoreService::GetBindTime()
{
    return bindTime_;
}

int64_t CoreService::GetEndTime()
{
    return endTime_;
}

int64_t CoreService::GetSpendTime()
{
    return endTime_ - bindTime_;
}

int32_t CoreService::GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::CELL_LOCATION)) {
        TELEPHONY_LOGE("Do not support Permission::CELL_LOCATION");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNrSsbId(slotId, nrSsbInformation);
}

bool CoreService::IsAllowedInsertApn(std::string &value)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return true;
    }
    if (TELEPHONY_EXT_WRAPPER.isAllowedInsertApn_ != nullptr) {
        return TELEPHONY_EXT_WRAPPER.isAllowedInsertApn_(value);
    }
    return true;
}

int32_t CoreService::GetTargetOpkey(int32_t slotId, std::u16string &opkey)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (TELEPHONY_EXT_WRAPPER.getTargetOpkey_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.getTargetOpkey_(slotId, opkey);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetOpkeyVersion(std::string &versionInfo)
{
    if (TELEPHONY_EXT_WRAPPER.getOpkeyVersion_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.getOpkeyVersion_(versionInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t CoreService::GetOpnameVersion(std::string &versionInfo)
{
    if (TELEPHONY_EXT_WRAPPER.getOpnameVersion_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.getOpnameVersion_(versionInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t CoreService::GetSimIO(int32_t slotId, int32_t command,
    int32_t fileId, const std::string &data, const std::string &path, SimAuthenticationResponse &response)
{
    return coreServiceSim_->GetSimIO(slotId, command, fileId, data, path, response);
}

int32_t CoreService::GetAllSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    return coreServiceSim_->GetAllSimAccountInfoList(iccAccountInfoList);
}

int32_t CoreService::GetSimLabel(int32_t slotId, SimLabel &simLabel, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->GetSimLabel(slotId, simLabel, callback);
}

int32_t CoreService::SendApduData(
    int32_t slotId, const std::u16string &aid, const EsimApduData &apduData, ResponseEsimResult &responseResult)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_ESIM_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:SET_TELEPHONY_ESIM_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (esimManager_ == nullptr) {
        TELEPHONY_LOGE("esimManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    OHOS::Telephony::ResponseEsimInnerResult result;
    int32_t res = esimManager_->SendApduData(slotId, aid, apduData, result);
    responseResult.resultCode_ = static_cast<EsimResultCode>(result.resultCode_);
    responseResult.response_ = result.response_;
    responseResult.sw1_ = result.sw1_;
    responseResult.sw2_ = result.sw2_;

    return res;
}

int32_t CoreService::GetRealSimCount()
{
    return coreServiceSim_->GetRealSimCount();
}

int32_t CoreService::GetManualNetworkScanState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetManualNetworkScanState(slotId, callback);
}

int32_t CoreService::StopManualNetworkScanCallback(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->StopManualNetworkScanCallback(slotId);
}

int32_t CoreService::StartManualNetworkScanCallback(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->StartManualNetworkScanCallback(slotId, callback);
}

int32_t CoreService::SetSimLabelIndex(int32_t simId, int32_t simLabelIndex, const sptr<IRawParcelCallback> &callback)
{
    return coreServiceSim_->SetSimLabelIndex(simId, simLabelIndex, callback);
}
} // namespace Telephony
} // namespace OHOS

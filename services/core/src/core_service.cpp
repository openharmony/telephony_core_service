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

namespace OHOS {
namespace Telephony {
namespace {
const int32_t MAX_IPC_THREAD_NUM = 6;
const int32_t MAX_FFRT_THREAD_NUM = 32;
}
const bool G_REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<CoreService>::GetInstance().get());

CoreService::CoreService() : SystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, true) {}

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
    simManager_ = std::make_shared<SimManager>(telRilManager_);
    simManager_->OnInit(slotCount);
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
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("GetImei no callback");
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
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("GetImeiSv no callback");
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
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("HasSimCard no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        bool hasSimCard = false;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->HasSimCard(slotId, hasSimCard);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteBool(hasSimCard);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetSimState(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("GetSimState no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        SimState simState = SimState::SIM_STATE_UNKNOWN;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->GetSimState(slotId, simState);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(static_cast<int32_t>(simState));
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetDsdsMode(int32_t &dsdsMode)
{
    TELEPHONY_LOGI("CoreService::GetDsdsMode()");
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return simManager_->GetDsdsMode(dsdsMode);
}

int32_t CoreService::GetCardType(int32_t slotId, CardType &cardType)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return simManager_->GetCardType(slotId, cardType);
}

int32_t CoreService::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return simManager_->GetISOCountryCodeForSim(slotId, countryCode);
}

int32_t CoreService::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimSpn(slotId, spn);
}

int32_t CoreService::GetSimIccId(int32_t slotId, std::u16string &iccId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimIccId(slotId, iccId);
}

int32_t CoreService::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimOperatorNumeric(slotId, operatorNumeric);
}

int32_t CoreService::GetIMSI(int32_t slotId, std::u16string &imsi)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetIMSI(slotId, imsi);
}

int32_t CoreService::IsCTSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("IsCTSimCard no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        bool isCTSimCard = false;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->IsCTSimCard(slotId, isCTSimCard);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteBool(isCTSimCard);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

bool CoreService::IsSimActive(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return false;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("IsSimActive no callback");
        return false;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        bool isSimActive = false;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        if (simManager) {
            isSimActive = simManager->IsSimActive(slotId);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteBool(isSimActive);
            }, dataTmp);
    });
    return true;
}

int32_t CoreService::GetSlotId(int32_t simId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreService::GetSlotId(), simManager_ is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSlotId(simId);
}

int32_t CoreService::GetSimId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreService::GetSimId(), simManager_ is nullptr!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetSimId(slotId);
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
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::GetLocaleFromDefaultSim, Permission denied!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return std::u16string();
    }
    int32_t slotId = INVALID_VALUE;
    simManager_->GetPrimarySlotId(slotId);
    if (slotId < DEFAULT_SIM_SLOT_ID) {
        slotId = DEFAULT_SIM_SLOT_ID;
    }
    return simManager_->GetLocaleFromDefaultSim(slotId);
}

int32_t CoreService::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::GetSimGid1, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimGid1(slotId, gid1);
}

std::u16string CoreService::GetSimGid2(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return std::u16string();
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::GetSimGid2, Permission denied!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return std::u16string();
    }
    return simManager_->GetSimGid2(slotId);
}

std::u16string CoreService::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreService::GetSimEons, Permission denied!");
        return std::u16string();
    }
    return simManager_->GetSimEons(slotId, plmn, lac, longNameRequired);
}

int32_t CoreService::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    bool denied = false;
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        denied = true;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimAccountInfo(slotId, denied, info);
}

int32_t CoreService::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetDefaultVoiceSlotId(slotId);
}

int32_t CoreService::GetDefaultVoiceSlotId()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetDefaultVoiceSlotId();
}

int32_t CoreService::GetDefaultVoiceSimId(const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (callback == nullptr) {
        TELEPHONY_LOGE("GetDefaultVoiceSimId no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), callback]() {
        int32_t simId = 0;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->GetDefaultVoiceSimId(simId);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(simId);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::SetPrimarySlotId(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    bool hasSim = false;
    simManager_->HasSimCard(slotId, hasSim);
    if (!hasSim) {
        TELEPHONY_LOGE("has no sim");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (!simManager_->IsSimActive(slotId)) {
        TELEPHONY_LOGE("sim is not active");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    return simManager_->SetPrimarySlotId(slotId);
}

int32_t CoreService::GetPrimarySlotId(int32_t &slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetPrimarySlotId(slotId);
}

int32_t CoreService::SetShowNumber(int32_t slotId, const std::u16string &number,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("SetShowNumber no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, number, callback]() {
        int32_t state = TELEPHONY_ERR_FAIL;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->SetShowNumber(slotId, number);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetShowNumber(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("GetShowNumber no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        std::u16string showNumber = u"";
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->GetShowNumber(slotId, showNumber);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteString16(showNumber);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::SetShowName(int32_t slotId, const std::u16string &name,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("SetShowName no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, name, callback]() {
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->SetShowName(slotId, name);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetShowName(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("GetShowName no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        std::u16string showName = u"";
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->GetShowName(slotId, showName);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteString16(showName);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    bool denied = false;
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        denied = true;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetActiveSimAccountInfoList(denied, iccAccountInfoList);
}

int32_t CoreService::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOperatorConfigs(slotId, poc);
}

int32_t CoreService::UnlockPin(const int32_t slotId, const std::u16string &pin,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnlockPin no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimPinExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, pin, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->UnlockPin(slotId, Str16ToStr8(pin), response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::UnlockPuk(const int slotId, const std::u16string &newPin, const std::u16string &puk,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::UnlockPuk(), newPinLen = %{public}lu, pukLen = %{public}lu, slotId = %{public}d",
        static_cast<unsigned long>(newPin.length()), static_cast<unsigned long>(puk.length()), slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnlockPuk no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimPinExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, newPin, puk, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->UnlockPuk(slotId, Str16ToStr8(newPin), Str16ToStr8(puk), response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::AlterPin(const int slotId, const std::u16string &newPin, const std::u16string &oldPin,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::AlterPin(), newPinLen = %{public}lu, oldPinLen = %{public}lu, slotId = %{public}d",
        static_cast<unsigned long>(newPin.length()), static_cast<unsigned long>(oldPin.length()), slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("AlterPin no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimPinExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, newPin, oldPin, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->AlterPin(slotId, Str16ToStr8(newPin), Str16ToStr8(oldPin), response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::UnlockPin2(const int32_t slotId, const std::u16string &pin2,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::UnlockPin2(), pin2Len = %{public}lu, slotId = %{public}d",
        static_cast<unsigned long>(pin2.length()), slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnlockPin2 no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimPinExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, pin2, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->UnlockPin2(slotId, Str16ToStr8(pin2), response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::UnlockPuk2(const int slotId, const std::u16string &newPin2, const std::u16string &puk2,
    const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::UnlockPuk2(), newPin2Len = %{public}lu, puk2Len = %{public}lu, slotId = %{public}d",
        static_cast<unsigned long>(newPin2.length()), static_cast<unsigned long>(puk2.length()), slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnlockPuk2 no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimPinExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, newPin2, puk2, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->UnlockPuk2(slotId, Str16ToStr8(newPin2), Str16ToStr8(puk2), response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::AlterPin2(const int slotId, const std::u16string &newPin2,
    const std::u16string &oldPin2, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::AlterPin2(), newPin2Len = %{public}lu, oldPin2Len = %{public}lu, slotId = %{public}d",
        static_cast<unsigned long>(newPin2.length()), static_cast<unsigned long>(oldPin2.length()), slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("AlterPin2 no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimPinExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, newPin2, oldPin2, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->AlterPin2(slotId, Str16ToStr8(newPin2), Str16ToStr8(oldPin2), response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::SetLockState(int32_t slotId, const LockInfo &options, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    std::u16string strPin = options.password;
    TELEPHONY_LOGI(
        "CoreService::SetLockState(),lockType = %{public}d, pinLen = %{public}lu, lockState = %{public}d, slotId "
        "= "
        "%{public}d",
        options.lockType, static_cast<unsigned long>(strPin.length()), options.lockState, slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("SetLockState no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, options, callback]() {
        LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->SetLockState(slotId, options, response);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(response.result);
                data.WriteInt32(response.remain);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::GetLockState(int32_t slotId, LockType lockType, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::GetLockState, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::GetLockState(), lockType = %{public}d, slotId = %{public}d", lockType, slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("GetLockState no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, lockType, callback]() {
        LockState lockState = LockState::LOCK_ERROR;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->GetLockState(slotId, lockType, lockState);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(static_cast<int32_t>(lockState));
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::RefreshSimState(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERROR;
    }
    return simManager_->RefreshSimState(slotId);
}

int32_t CoreService::SetActiveSim(int32_t slotId, int32_t enable)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetActiveSim(slotId, enable);
}

int32_t CoreService::SetActiveSimSatellite(int32_t slotId, int32_t enable)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetActiveSimSatellite(slotId, enable);
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
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if ((!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) &&
        (!TelephonyPermission::CheckPermission(Permission::GET_PHONE_NUMBERS))) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimTelephoneNumber(slotId, telephoneNumber);
}

std::u16string CoreService::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::GetSimTeleNumberIdentifier, Permission denied!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return std::u16string();
    }
    return simManager_->GetSimTeleNumberIdentifier(slotId);
}

int32_t CoreService::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
}

int32_t CoreService::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailNumber(slotId, voiceMailNumber);
}

int32_t CoreService::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::GetVoiceMailCount(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreService::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::SetVoiceMailCount(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreService::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreService::SetVoiceCallForwarding(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceCallForwarding(slotId, enable, number);
}

int32_t CoreService::QueryIccDiallingNumbers(
    int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &reslut)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::READ_CONTACTS)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->QueryIccDiallingNumbers(slotId, type, reslut);
}

int32_t CoreService::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::WRITE_CONTACTS)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreService::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::WRITE_CONTACTS)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreService::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::WRITE_CONTACTS)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreService::SetVoiceMailInfo(
    const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t CoreService::GetMaxSimCount()
{
    return SIM_SLOT_COUNT;
}

int32_t CoreService::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpKey(slotId, opkey);
}

int32_t CoreService::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpKeyExt(slotId, opkeyExt);
}

int32_t CoreService::GetOpName(int32_t slotId, std::u16string &opname)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpName(slotId, opname);
}

int32_t CoreService::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreService::SendEnvelopeCmd simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::SendEnvelopeCmd, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    return simManager_->SendEnvelopeCmd(slotId, cmd);
}

int32_t CoreService::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreService::SendEnvelopeCmd simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::SendTerminalResponseCmd, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    return simManager_->SendTerminalResponseCmd(slotId, cmd);
}

int32_t CoreService::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreService::SendEnvelopeCmd simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreService::SendCallSetupRequestResult, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    return simManager_->SendCallSetupRequestResult(slotId, accept);
}

int32_t CoreService::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI(
        "CoreService::UnlockSimLock(), lockType = %{public}d, slotId = %{public}d", lockInfo.lockType, slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockSimLock(slotId, lockInfo, response);
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
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("HasOperatorPrivileges no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        bool hasOperatorPrivileges = false;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->HasOperatorPrivileges(slotId, hasOperatorPrivileges);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteBool(hasOperatorPrivileges);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreService::SimAuthentication(
    int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:GET_TELEPHONY_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SimAuthentication(slotId, authType, authData, response);
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
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Failed because no permission:GET_TELEPHONY_STATE");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimIO(slotId, command, fileId, data, path, response);
}

#ifdef CORE_SERVICE_SUPPORT_ESIM
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
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    OHOS::Telephony::ResponseEsimInnerResult result;
    int32_t res = simManager_->SendApduData(slotId, aid, apduData, result);
    responseResult.resultCode_ = static_cast<ResultCode>(result.resultCode_);
    responseResult.response_ = result.response_;
    responseResult.sw1_ = result.sw1_;
    responseResult.sw2_ = result.sw2_;

    return res;
}
#endif
} // namespace Telephony
} // namespace OHOS

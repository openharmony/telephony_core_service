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

#include "core_manager_inner.h"

#include "network_search_types.h"
#include "parameter.h"
#include "radio_event.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

using namespace OHOS::Telephony;
namespace OHOS {
namespace Telephony {
constexpr int NETWORK_IS_NULL = -1;
constexpr int32_t INVALID_VALUE = -1;

CoreManagerInner::CoreManagerInner() {}

CoreManagerInner &CoreManagerInner::GetInstance()
{
    static CoreManagerInner instance;
    return instance;
}

void CoreManagerInner::OnInit(std::shared_ptr<INetworkSearch> networkSearchManager,
    std::shared_ptr<ISimManager> simManager, std::shared_ptr<ITelRilManager> telRilManager)
{
    networkSearchManager_ = networkSearchManager;
    simManager_ = simManager;
    telRilManager_ = telRilManager;
    isInitAllObj_ = true;
}

bool CoreManagerInner::IsInitFinished(void)
{
    return isInitAllObj_;
}

void CoreManagerInner::SetTelRilMangerObj(std::shared_ptr<ITelRilManager> telRilManager)
{
    telRilManager_ = telRilManager;
}

bool CoreManagerInner::IsInitFinishedForTelRil(void)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telrilmanager is null");
    }
    return telRilManager_ != nullptr;
}

int32_t CoreManagerInner::InitExtraModule(int32_t slotId)
{
    TELEPHONY_LOGI("InitExtraModule, slotId: %{public}d", slotId);
    if (isInitExtraObj_) {
        TELEPHONY_LOGE("InitExtraModule, has been inited, return!");
        return TELEPHONY_SUCCESS;
    }
    if (SIM_SLOT_COUNT != DUAL_SLOT_COUNT) {
        TELEPHONY_LOGE("InitExtraModule, can not been inited because of slot number, return!");
        return TELEPHONY_ERROR;
    }
    if (telRilManager_ == nullptr || simManager_ == nullptr || networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("InitExtraModule, can not been inited because of nullptr, return!");
        return TELEPHONY_ERROR;
    }
    int resultCode = TELEPHONY_SUCCESS;
    // Step1. Init ril object.
    if (telRilManager_ != nullptr) {
        resultCode = telRilManager_->InitTelExtraModule(slotId);
    }
    TELEPHONY_LOGI("InitExtraModule, resultCode of ril: %{public}d", resultCode);
    if (resultCode != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERROR;
    }
    // Step2. Init sim object.
    if (simManager_ != nullptr) {
        resultCode = simManager_->InitTelExtraModule(slotId);
    }
    TELEPHONY_LOGI("InitExtraModule, resultCode of sim: %{public}d", resultCode);
    if (resultCode != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERROR;
    }
    // Step3. Init network search object.
    if (networkSearchManager_ != nullptr) {
        resultCode = networkSearchManager_->InitTelExtraModule(slotId);
        networkSearchManager_->InitAirplaneMode(slotId);
    }
    TELEPHONY_LOGI("InitExtraModule, resultCode of network: %{public}d", resultCode);
    if (resultCode != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERROR;
    }
    // only success set mark true.
    isInitExtraObj_ = true;
    return TELEPHONY_SUCCESS;
}

int32_t CoreManagerInner::GetDefaultSlotId(void)
{
    return DEFAULT_SIM_SLOT_ID;
}

int32_t CoreManagerInner::GetMaxSimCount(void)
{
    return SIM_SLOT_COUNT;
}

int32_t CoreManagerInner::RegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, int32_t *obj)
{
    if (what >= RadioEvent::RADIO_PS_CONNECTION_ATTACHED && what <= RadioEvent::RADIO_FACTORY_RESET) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        networkSearchManager_->RegisterCoreNotify(slotId, handler, what);
    } else if ((what >= RadioEvent::RADIO_SIM_STATE_CHANGE) && (what <= RadioEvent::RADIO_SIM_ACCOUNT_LOADED)) {
        if (simManager_ == nullptr) {
            TELEPHONY_LOGE("simManager_ is null");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        simManager_->RegisterCoreNotify(slotId, handler, what);
    } else {
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager is null!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return telRilManager_->RegisterCoreNotify(slotId, handler, what, obj);
    }
    return TELEPHONY_SUCCESS;
}

int32_t CoreManagerInner::UnRegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (what >= RadioEvent::RADIO_PS_CONNECTION_ATTACHED && what <= RadioEvent::RADIO_EMERGENCY_STATE_CLOSE) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        networkSearchManager_->UnRegisterCoreNotify(slotId, observerCallBack, what);
    } else if (what >= RadioEvent::RADIO_SIM_STATE_CHANGE && what <= RadioEvent::RADIO_SIM_RECORDS_LOADED) {
        if (simManager_ == nullptr) {
            TELEPHONY_LOGE("simManager_ is null");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        simManager_->UnRegisterCoreNotify(slotId, observerCallBack, what);
    } else {
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager is null!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return telRilManager_->UnRegisterCoreNotify(slotId, observerCallBack, what);
    }
    return TELEPHONY_SUCCESS;
}

void CoreManagerInner::RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return;
    }
    networkSearchManager_->RegisterCellularDataObject(callback);
}

void CoreManagerInner::UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return;
    }
    networkSearchManager_->UnRegisterCellularDataObject(callback);
}

void CoreManagerInner::RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return;
    }
    networkSearchManager_->RegisterCellularCallObject(callback);
}

void CoreManagerInner::UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return;
    }
    networkSearchManager_->UnRegisterCellularCallObject(callback);
}

int32_t CoreManagerInner::RegisterSimAccountCallback(
    const int32_t tokenId, const sptr<SimAccountCallback> &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->RegisterSimAccountCallback(tokenId, callback);
}

int32_t CoreManagerInner::UnregisterSimAccountCallback(const sptr<SimAccountCallback> &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnregisterSimAccountCallback(callback);
}

/******************** telRilManager start *******************/
int32_t CoreManagerInner::SetUssd(int32_t slotId, int32_t eventId, const std::string str,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set ussd telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set ussd response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetUssd(slotId, str, response);
}

int32_t CoreManagerInner::CloseUnFinishedUssd(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("close unfinished ussd telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("close unfinished ussd response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->CloseUnFinishedUssd(slotId, response);
}

int32_t CoreManagerInner::GetUssd(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get ussd telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get ussd response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetUssd(slotId, response);
}

int32_t CoreManagerInner::GetMute(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get mute telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get mute response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetMute(slotId, response);
}

int32_t CoreManagerInner::SetMute(
    int32_t slotId, int32_t eventId, int32_t mute, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set mute telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set mute response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetMute(slotId, mute, response);
}

int32_t CoreManagerInner::GetEmergencyCallList(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get emergency call list telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get emergency call list response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetEmergencyCallList(slotId, response);
}

int32_t CoreManagerInner::SetEmergencyCallList(int32_t slotId, int32_t eventId, std::vector<EmergencyCall> &eccVec,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    TELEPHONY_LOGI("SetEmergencyCallList start");
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set emergency call list telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set emergency call list response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetEmergencyCallList(slotId, eccVec, response);
}

int32_t CoreManagerInner::GetCallFailReason(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get call fail reason telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get call fail reason response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCallFailReason(slotId, response);
}

int32_t CoreManagerInner::SetCallPreferenceMode(
    int32_t slotId, int32_t eventId, int32_t mode, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set call preference mode telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set call preference mode response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetCallPreferenceMode(slotId, mode, response);
}

int32_t CoreManagerInner::GetCallPreferenceMode(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get call preference mode telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get call preference mode response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCallPreferenceMode(slotId, response);
}

int32_t CoreManagerInner::SetPreferredNetworkPara(int32_t slotId, int32_t eventId, int32_t preferredNetworkType,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set preferred network telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set preferred network response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetPreferredNetwork(slotId, preferredNetworkType, response);
}

int32_t CoreManagerInner::GetPreferredNetworkPara(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get preferred network telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get preferred network response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetPreferredNetwork(slotId, response);
}

int32_t CoreManagerInner::GetOperatorInfo(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get operator info telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get operator info response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetOperatorInfo(slotId, response);
}

int32_t CoreManagerInner::GetNeighboringCellInfoList(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get neighboring cell info list telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get neighboring cell info list response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetNeighboringCellInfoList(slotId, response);
}

int32_t CoreManagerInner::GetCurrentCellInfo(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get current cell info telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get current cell info response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCurrentCellInfo(slotId, response);
}

int32_t CoreManagerInner::SendGsmSms(int32_t slotId, int32_t eventId, GsmSimMessageParam &gsmMessage,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("send gsm sms telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, gsmMessage.refId);
    if (response == nullptr) {
        TELEPHONY_LOGE("send gsm sms response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SendGsmSms(slotId, gsmMessage.smscPdu, gsmMessage.pdu, response);
}

int32_t CoreManagerInner::SendCdmaSms(int32_t slotId, int32_t eventId, std::string pdu, int64_t refId,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("send cdma sms telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, refId);
    if (response == nullptr) {
        TELEPHONY_LOGE("send cdma sms response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SendCdmaSms(slotId, pdu, response);
}

int32_t CoreManagerInner::AddSimMessage(int32_t slotId, int32_t eventId, const SimMessageParam &simMessage,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("add sim message telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("add sim message response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->AddSimMessage(slotId, simMessage, response);
}

int32_t CoreManagerInner::DelSimMessage(
    int32_t slotId, int32_t eventId, int32_t gsmIndex, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("delete sim message telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("delete sim message response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->DelSimMessage(slotId, gsmIndex, response);
}

int32_t CoreManagerInner::GetSmscAddr(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get smsc address telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get smsc address response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetSmscAddr(slotId, response);
}

int32_t CoreManagerInner::SetSmscAddr(int32_t slotId, int32_t eventId, int32_t tosca, std::string address,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set smsc address telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set smsc address response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetSmscAddr(slotId, tosca, address, response);
}

int32_t CoreManagerInner::SetCBConfig(int32_t slotId, int32_t eventId, const CBConfigParam &cbConfig,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set CB config telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set CB config response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetCBConfig(slotId, cbConfig, response);
}

int32_t CoreManagerInner::SetCdmaCBConfig(int32_t slotId, int32_t eventId, CdmaCBConfigInfoList &cdmaCBConfigInfoList,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set cdma CB config telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set cdma CB config response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetCdmaCBConfig(slotId, cdmaCBConfigInfoList, response);
}

int32_t CoreManagerInner::GetCBConfig(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get CB config telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get CB config response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCBConfig(slotId, response);
}

int32_t CoreManagerInner::GetCdmaCBConfig(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get cdma CB config telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get cdma CB config response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCdmaCBConfig(slotId, response);
}

int32_t CoreManagerInner::SendSmsMoreMode(int32_t slotId, int32_t eventId, GsmSimMessageParam &gsmMessage,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("send sms more mode telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, gsmMessage.refId);
    if (response == nullptr) {
        TELEPHONY_LOGE("send sms more mode response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SendSmsMoreMode(slotId, gsmMessage.smscPdu, gsmMessage.pdu, response);
}

int32_t CoreManagerInner::SendSmsAck(int32_t slotId, int32_t eventId, bool success, int32_t cause,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("send sms ack telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("send sms ack response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SendSmsAck(slotId, success, cause, response);
}

int32_t CoreManagerInner::AddCdmaSimMessage(int32_t slotId, int32_t eventId, int32_t status, std::string pdu,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("add cdma sim message telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("add cdma sim message response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->AddCdmaSimMessage(slotId, status, pdu, response);
}

int32_t CoreManagerInner::DelCdmaSimMessage(
    int32_t slotId, int32_t eventId, int32_t cdmaIndex, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("delete cdma sim message telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("delete cdma sim message response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->DelCdmaSimMessage(slotId, cdmaIndex, response);
}

int32_t CoreManagerInner::UpdateCdmaSimMessage(int32_t slotId, int32_t eventId, const CdmaSimMessageParam &cdmaSimMsg,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("update cdma sim message telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("update cdma sim message response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->UpdateCdmaSimMessage(slotId, cdmaSimMsg, response);
}

int32_t CoreManagerInner::GetNetworkSearchInformation(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get network search information telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get network search information response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetNetworkSearchInformation(slotId, response);
}

int32_t CoreManagerInner::GetNetworkSelectionMode(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get network selection mode telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get network selection mode response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetNetworkSelectionMode(slotId, response);
}

int32_t CoreManagerInner::SetNetworkSelectionMode(int32_t slotId, int32_t eventId, int32_t automaticFlag,
    std::string oper, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set network selection mode telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set network selection mode response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetNetworkSelectionMode(slotId, automaticFlag, oper, response);
}

int32_t CoreManagerInner::SetRadioState(
    int32_t slotId, int32_t eventId, int fun, int rst, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set radio state telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set radio state response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetRadioState(slotId, fun, rst, response);
}

int32_t CoreManagerInner::GetRadioState(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get radio state telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get radio state response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetRadioState(slotId, response);
}

int32_t CoreManagerInner::ShutDown(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("shut down telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("shut down response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->ShutDown(slotId, response);
}

int32_t CoreManagerInner::Dial(int32_t slotId, int32_t eventId, std::string address, int clirMode,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("dial telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("dial response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->Dial(slotId, address, clirMode, response);
}

int32_t CoreManagerInner::Reject(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("reject call telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("reject call response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->Reject(slotId, response);
}

int32_t CoreManagerInner::Hangup(
    int32_t slotId, int32_t eventId, int32_t gsmIndex, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("hung up call telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("hung up call response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->Hangup(slotId, gsmIndex, response);
}

int32_t CoreManagerInner::Answer(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("answer call telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("answer call response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->Answer(slotId, response);
}

int32_t CoreManagerInner::GetCallList(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get call list telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get call list response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCallList(slotId, response);
}

int32_t CoreManagerInner::HoldCall(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("hold call telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("hold call response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->HoldCall(slotId, response);
}

int32_t CoreManagerInner::UnHoldCall(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("unhold call telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("unhold call response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->UnHoldCall(slotId, response);
}

int32_t CoreManagerInner::SwitchCall(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("switch call telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("switch call response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SwitchCall(slotId, response);
}

int32_t CoreManagerInner::CombineConference(
    int32_t slotId, int32_t eventId, int32_t callType, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("combine conference telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("combine conference response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->CombineConference(slotId, callType, response);
}

int32_t CoreManagerInner::SeparateConference(int32_t slotId, int32_t eventId, int32_t callIndex, int32_t callType,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("separate conference telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("separate conference response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SeparateConference(slotId, callIndex, callType, response);
}

int32_t CoreManagerInner::CallSupplement(
    int32_t slotId, int32_t eventId, int32_t type, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("call supplement telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("call supplement response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->CallSupplement(slotId, type, response);
}

int32_t CoreManagerInner::GetClip(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetClip(slotId, response);
}

int32_t CoreManagerInner::SetClip(int32_t slotId, int32_t action, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetClip(slotId, action, response);
}

int32_t CoreManagerInner::GetClir(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetClir(slotId, response);
}

int32_t CoreManagerInner::SetClir(int32_t slotId, int32_t action, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetClir(slotId, action, response);
}

int32_t CoreManagerInner::SetCallWaiting(
    int32_t slotId, int32_t activate, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetCallWaiting(slotId, activate, response);
}

int32_t CoreManagerInner::SetCallTransferInfo(
    int32_t slotId, const CallTransferParam &callTransfer, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetCallTransferInfo(slotId, callTransfer, response);
}

int32_t CoreManagerInner::GetCallTransferInfo(
    int32_t slotId, const int32_t reason, const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetCallTransferInfo(slotId, reason, response);
}

int32_t CoreManagerInner::GetCallWaiting(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetCallWaiting(slotId, response);
}

int32_t CoreManagerInner::GetCallRestriction(
    int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetCallRestriction(slotId, fac, response);
}

int32_t CoreManagerInner::SetCallRestriction(
    int32_t slotId, const CallRestrictionParam &callRestriction, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetCallRestriction(slotId, callRestriction, response);
}

int32_t CoreManagerInner::SetBarringPassword(int32_t slotId, const char *oldPassword,
    const char *newPassword, const std::string &restrictionType, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetBarringPassword(slotId, oldPassword, newPassword, restrictionType, response);
}

int32_t CoreManagerInner::SetVoNRSwitch(
    int32_t slotId, int32_t state, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set NR voice switch telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set NR voice switch response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetVoNRSwitch(slotId, state, response);
}

int32_t CoreManagerInner::SendDTMF(int32_t slotId, int32_t eventId, const DtmfParam &dtmfParam,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("send DTMF telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("send DTMF response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SendDtmf(slotId, dtmfParam, response);
}

int32_t CoreManagerInner::SendDTMF(int32_t slotId, int32_t eventId, char cDTMFCode, int32_t index,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("send DTMF telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, index);
    if (response == nullptr) {
        TELEPHONY_LOGE("send DTMF response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SendDtmf(slotId, cDTMFCode, index, response);
}

int32_t CoreManagerInner::StartDTMF(int32_t slotId, int32_t eventId, char cDTMFCode, int32_t index,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("start DTMF telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("start DTMF response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->StartDtmf(slotId, cDTMFCode, index, response);
}

int32_t CoreManagerInner::StopDTMF(
    int32_t slotId, int32_t eventId, int32_t index, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("stop DTMF telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("stop DTMF response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->StopDtmf(slotId, index, response);
}

int32_t CoreManagerInner::SetDataPermitted(
    int32_t slotId, int32_t eventId, int32_t dataPermitted, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set data permitted telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set data permitted response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetDataPermitted(slotId, dataPermitted, response);
}

int32_t CoreManagerInner::SetInitApnInfo(int32_t slotId, int32_t eventId, const DataProfile &dataProfile,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set init apn info telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set init apn info response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetInitApnInfo(slotId, dataProfile, response);
}

int32_t CoreManagerInner::ActivatePdpContext(int32_t slotId, int32_t eventId, const ActivateDataParam &activateData,
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("activate pdp context telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, activateData.param);
    if (response == nullptr) {
        TELEPHONY_LOGE("activate pdp context response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->ActivatePdpContext(slotId, activateData, response);
}

int32_t CoreManagerInner::DeactivatePdpContext(int32_t slotId, int32_t eventId,
    const DeactivateDataParam &deactivateData, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("deactivate pdp context telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId, deactivateData.param);
    if (response == nullptr) {
        TELEPHONY_LOGE("deactivate pdp context response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->DeactivatePdpContext(slotId, deactivateData.cid, deactivateData.reason, response);
}

int32_t CoreManagerInner::GetPdpContextList(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get pdp context list telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get pdp context list response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetPdpContextList(slotId, response);
}

int32_t CoreManagerInner::SetLinkBandwidthReportingRule(int32_t slotId, int32_t eventId,
    LinkBandwidthRule linkBandwidth, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("set link bandwidth reporting rule telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("set link bandwidth reporting rule response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->SetLinkBandwidthReportingRule(slotId, linkBandwidth, response);
}

int32_t CoreManagerInner::GetLinkBandwidthInfo(
    int32_t slotId, int32_t eventId, const int32_t cid, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get link bandwidth info telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get link bandwidth info response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetLinkBandwidthInfo(slotId, cid, response);
}

int32_t CoreManagerInner::GetLinkCapability(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get link capability telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get link capability response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetLinkCapability(slotId, response);
}

int32_t CoreManagerInner::CleanAllConnections(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("clean all connections telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("clean all connections response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->CleanAllConnections(slotId, response);
}

int32_t CoreManagerInner::GetSignalStrength(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get signal strength telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get signal strength response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetSignalStrength(slotId, response);
}

int32_t CoreManagerInner::GetCsRegStatus(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get cs register status telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get cs register status response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetCsRegStatus(slotId, response);
}

int32_t CoreManagerInner::GetPsRegStatus(
    int32_t slotId, int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("get ps register status telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventId);
    if (response == nullptr) {
        TELEPHONY_LOGE("get ps register status response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response->SetOwner(handler);
    return telRilManager_->GetPsRegStatus(slotId, response);
}
/******************** telRilManager end *******************/
/******************** networkSearchManager start *******************/
int32_t CoreManagerInner::GetPsRadioTech(int32_t slotId, int32_t &psRadioTech)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetPsRadioTech(slotId, psRadioTech);
}

int32_t CoreManagerInner::GetCsRadioTech(int32_t slotId, int32_t &csRadioTech)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetCsRadioTech(slotId, csRadioTech);
}

int32_t CoreManagerInner::GetPsRegState(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRegState(slotId);
}

int32_t CoreManagerInner::GetCsRegState(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetCsRegState(slotId);
}

int32_t CoreManagerInner::GetPsRoamingState(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRoamingState(slotId);
}

bool CoreManagerInner::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetNetworkSelectionMode(
        slotId, selectMode, networkInformation, resumeSelection, callback);
}

int32_t CoreManagerInner::GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetSignalInfoList(slotId, signals);
}

std::u16string CoreManagerInner::GetOperatorNumeric(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorNumeric(slotId);
}

int32_t CoreManagerInner::GetOperatorName(int32_t slotId, std::u16string &operatorName)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetOperatorName(slotId, operatorName);
}

int32_t CoreManagerInner::GetNetworkStatus(int32_t slotId, sptr<NetworkState> &networkState)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkStatus(slotId, networkState);
}

int32_t CoreManagerInner::SetRadioState(
    int32_t slotId, bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->SetRadioState(slotId, isOn, rst, callback);
}

int32_t CoreManagerInner::GetRadioState(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetRadioState(slotId);
}

int32_t CoreManagerInner::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetRadioState(slotId, callback);
}

int32_t CoreManagerInner::GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetIsoCountryCodeForNetwork(slotId, countryCode);
}

int32_t CoreManagerInner::GetImei(int32_t slotId, std::u16string &imei)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetImei(slotId, imei);
}

int32_t CoreManagerInner::GetImeiSv(int32_t slotId, std::u16string &imeiSv)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetImeiSv(slotId, imeiSv);
}

int32_t CoreManagerInner::GetMeid(int32_t slotId, std::u16string &meid)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetMeid(slotId, meid);
}

int32_t CoreManagerInner::GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetUniqueDeviceId(slotId, deviceId);
}

PhoneType CoreManagerInner::GetPhoneType(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return PhoneType::PHONE_TYPE_IS_NONE;
    }
    return networkSearchManager_->GetPhoneType(slotId);
}

sptr<CellLocation> CoreManagerInner::GetCellLocation(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return nullptr;
    }
    return networkSearchManager_->GetCellLocation(slotId);
}

int32_t CoreManagerInner::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkSearchInformation(slotId, callback);
}

int32_t CoreManagerInner::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetNetworkSelectionMode(slotId, callback);
}

int32_t CoreManagerInner::GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetCellInfoList(slotId, cellInfo);
}

int32_t CoreManagerInner::SendUpdateCellLocationRequest(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->SendUpdateCellLocationRequest(slotId);
}

int32_t CoreManagerInner::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetPreferredNetwork(slotId, callback);
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t CoreManagerInner::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->SetPreferredNetwork(slotId, networkMode, callback);
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

bool CoreManagerInner::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->SetPreferredNetwork(slotId, networkMode);
    }
    return false;
}

bool CoreManagerInner::IsNrSupported(int32_t slotId)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->IsNrSupported(slotId);
    }
    return false;
}

bool CoreManagerInner::IsSatelliteEnabled()
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->IsSatelliteEnabled();
    }
    return false;
}

void CoreManagerInner::DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive)
{
    if (networkSearchManager_ != nullptr) {
        networkSearchManager_->DcPhysicalLinkActiveUpdate(slotId, isActive);
    }
}

int32_t CoreManagerInner::NotifyCallStatusToNetworkSearch(int32_t slotId, int32_t callStatus)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->NotifyCallStatusToNetworkSearch(slotId, callStatus);
}

int32_t CoreManagerInner::GetNrOptionMode(int32_t slotId, NrMode &mode)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetNrOptionMode(slotId, mode);
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

FrequencyType CoreManagerInner::GetFrequencyType(int32_t slotId) const
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetFrequencyType(slotId);
    }
    return FrequencyType::FREQ_TYPE_UNKNOWN;
}

NrState CoreManagerInner::GetNrState(int32_t slotId) const
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetNrState(slotId);
    }
    return NrState::NR_STATE_NOT_SUPPORT;
}

int32_t CoreManagerInner::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetImsRegStatus(slotId, imsSrvType, info);
}

int32_t CoreManagerInner::GetAirplaneMode(bool &airplaneMode)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->GetAirplaneMode(airplaneMode);
}

int32_t CoreManagerInner::UpdateRadioOn(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->UpdateRadioOn(slotId);
}

int32_t CoreManagerInner::UpdateOperatorName(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->UpdateOperatorName(slotId);
}

/******************** networkSearchManager end ************************/
/******************** simManager_ start *******************/

int32_t CoreManagerInner::ObtainSpnCondition(int32_t slotId, bool roaming, std::string operatorNum)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return 0;
    }
    return simManager_->ObtainSpnCondition(slotId, roaming, operatorNum);
}

int32_t CoreManagerInner::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimSpn(slotId, spn);
}

std::u16string CoreManagerInner::GetSimEons(
    int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return std::u16string();
    }
    return simManager_->GetSimEons(slotId, plmn, lac, longNameRequired);
}

int32_t CoreManagerInner::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t CoreManagerInner::QueryIccDiallingNumbers(
    int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->QueryIccDiallingNumbers(slotId, type, result);
}

int32_t CoreManagerInner::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreManagerInner::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreManagerInner::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreManagerInner::AddSmsToIcc(int slotId, int status, std::string &pdu, std::string &smsc)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->AddSmsToIcc(slotId, status, pdu, smsc);
}

int32_t CoreManagerInner::UpdateSmsIcc(int slotId, int index, int status, std::string &pduData, std::string &smsc)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UpdateSmsIcc(slotId, index, status, pduData, smsc);
}

std::vector<std::string> CoreManagerInner::ObtainAllSmsOfIcc(int slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        std::vector<std::string> result;
        return result;
    }
    return simManager_->ObtainAllSmsOfIcc(slotId);
}

int32_t CoreManagerInner::DelSmsIcc(int slotId, int index)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->DelSmsIcc(slotId, index);
}

bool CoreManagerInner::IsSimActive(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return false;
    }
    return simManager_->IsSimActive(slotId);
}

int32_t CoreManagerInner::SetActiveSim(int32_t slotId, int32_t enable)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetActiveSim(slotId, enable);
}

int32_t CoreManagerInner::ResetSimLoadAccount(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->ResetSimLoadAccount(slotId);
}

int32_t CoreManagerInner::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimAccountInfo(slotId, false, info);
}

int32_t CoreManagerInner::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetDefaultVoiceSlotId(slotId);
}

int32_t CoreManagerInner::SetDefaultSmsSlotId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetDefaultSmsSlotId(slotId);
}

int32_t CoreManagerInner::SetDefaultCellularDataSlotId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetDefaultCellularDataSlotId(slotId);
}

int32_t CoreManagerInner::SetPrimarySlotId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetPrimarySlotId(slotId);
}

int32_t CoreManagerInner::SetShowNumber(int32_t slotId, const std::u16string &number)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetShowNumber(slotId, number);
}

int32_t CoreManagerInner::SetShowName(int32_t slotId, const std::u16string &name)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetShowName(slotId, name);
}

int32_t CoreManagerInner::GetDefaultVoiceSlotId()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetDefaultVoiceSlotId();
}

int32_t CoreManagerInner::GetDefaultVoiceSimId(int32_t &simId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetDefaultVoiceSimId(simId);
}

int32_t CoreManagerInner::GetDefaultSmsSlotId()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetDefaultSmsSlotId();
}

int32_t CoreManagerInner::GetDefaultSmsSimId(int32_t &simId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetDefaultSmsSimId(simId);
}

int32_t CoreManagerInner::GetDefaultCellularDataSlotId()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetDefaultCellularDataSlotId();
}

int32_t CoreManagerInner::GetDefaultCellularDataSimId(int32_t &simId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetDefaultCellularDataSimId(simId);
}

int32_t CoreManagerInner::GetDsdsMode(int32_t &dsdsMode)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetDsdsMode(dsdsMode);
}

int32_t CoreManagerInner::SetDsdsMode(int32_t dsdsMode)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetDsdsMode(dsdsMode);
}

int32_t CoreManagerInner::SendSimMatchedOperatorInfo(
    int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SendSimMatchedOperatorInfo(slotId, state, operName, operKey);
}

int32_t CoreManagerInner::GetPrimarySlotId(int32_t &slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetPrimarySlotId(slotId);
}

int32_t CoreManagerInner::GetShowNumber(int32_t slotId, std::u16string &showNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetShowNumber(slotId, showNumber);
}

int32_t CoreManagerInner::GetShowName(int32_t slotId, std::u16string &showName)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetShowName(slotId, showName);
}

int32_t CoreManagerInner::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetActiveSimAccountInfoList(false, iccAccountInfoList);
}

int32_t CoreManagerInner::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOperatorConfigs(slotId, poc);
}

int32_t CoreManagerInner::UpdateOperatorConfigs()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t slotCount = SIM_SLOT_COUNT;
    int32_t failSlotCount = slotCount;
    for (int32_t slotId = 0; slotId < slotCount; slotId++) {
        TELEPHONY_LOGD("select slotId %{public}d in slotCount %{public}d", slotId, slotCount);
        int32_t err = simManager_->UpdateOperatorConfigs(slotId);
        if (err == TELEPHONY_ERR_SUCCESS) {
            failSlotCount--;
        } else {
            TELEPHONY_LOGE("slotId %{public}d return error %{public}d", slotId, err);
        }
    }
    return failSlotCount;
}

int32_t CoreManagerInner::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimOperatorNumeric(slotId, operatorNumeric);
}

int32_t CoreManagerInner::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetISOCountryCodeForSim(slotId, countryCode);
}

int32_t CoreManagerInner::GetSimIccId(int32_t slotId, std::u16string &iccId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimIccId(slotId, iccId);
}

int32_t CoreManagerInner::GetIMSI(int32_t slotId, std::u16string &imsi)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetIMSI(slotId, imsi);
}

std::u16string CoreManagerInner::GetLocaleFromDefaultSim(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return u"";
    }
    return simManager_->GetLocaleFromDefaultSim(slotId);
}

std::int32_t CoreManagerInner::GetSlotId(int32_t simId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetSlotId(simId);
}

std::int32_t CoreManagerInner::GetSimId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetSimId(slotId);
}

int32_t CoreManagerInner::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimGid1(slotId, gid1);
}

std::u16string CoreManagerInner::GetSimGid2(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return u"";
    }
    return simManager_->GetSimGid2(slotId);
}

int32_t CoreManagerInner::GetOpName(int32_t slotId, std::u16string &opname)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpName(slotId, opname);
}

int32_t CoreManagerInner::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpKeyExt(slotId, opkeyExt);
}

int32_t CoreManagerInner::GetOpKey(std::u16string &opkey)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t slotId = INVALID_VALUE;
    simManager_->GetPrimarySlotId(slotId);
    return GetOpKey(slotId, opkey);
}

int32_t CoreManagerInner::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpKey(slotId, opkey);
}

int32_t CoreManagerInner::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimTelephoneNumber(slotId, telephoneNumber);
}

std::u16string CoreManagerInner::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return u"";
    }
    return simManager_->GetSimTeleNumberIdentifier(slotId);
}

int32_t CoreManagerInner::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
}

int32_t CoreManagerInner::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailNumber(slotId, voiceMailNumber);
}

int32_t CoreManagerInner::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreManagerInner::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreManagerInner::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceCallForwarding(slotId, enable, number);
}

int32_t CoreManagerInner::HasSimCard(int32_t slotId, bool &hasSimCard)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->HasSimCard(slotId, hasSimCard);
}

int32_t CoreManagerInner::GetSimState(int32_t slotId, SimState &simState)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimState(slotId, simState);
}

int32_t CoreManagerInner::GetSimIccStatus(int32_t slotId, IccSimStatus &iccStatus)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimIccStatus(slotId, iccStatus);
}

int32_t CoreManagerInner::GetCardType(int32_t slotId, CardType &cardType)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetCardType(slotId, cardType);
}

int32_t CoreManagerInner::SetModemInit(int32_t slotId, bool state)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetModemInit(slotId, state);
}

int32_t CoreManagerInner::UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockPin(slotId, pin, response);
}

int32_t CoreManagerInner::UnlockPuk(
    int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockPuk(slotId, newPin, puk, response);
}

int32_t CoreManagerInner::AlterPin(
    int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->AlterPin(slotId, newPin, oldPin, response);
}

int32_t CoreManagerInner::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetLockState(slotId, options, response);
}

int32_t CoreManagerInner::GetLockState(int32_t slotId, LockType lockType, LockState &lockState)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetLockState(slotId, lockType, lockState);
}

int32_t CoreManagerInner::RefreshSimState(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return false;
    }
    return simManager_->RefreshSimState(slotId);
}

int32_t CoreManagerInner::UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockPin2(slotId, pin2, response);
}

int32_t CoreManagerInner::UnlockPuk2(
    int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockPuk2(slotId, newPin2, puk2, response);
}

int32_t CoreManagerInner::AlterPin2(
    int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->AlterPin2(slotId, newPin2, oldPin2, response);
}

int32_t CoreManagerInner::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SendEnvelopeCmd(slotId, cmd);
}

int32_t CoreManagerInner::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SendTerminalResponseCmd(slotId, cmd);
}

int32_t CoreManagerInner::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SendCallSetupRequestResult(slotId, accept);
}

int32_t CoreManagerInner::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockSimLock(slotId, lockInfo, response);
}

int32_t CoreManagerInner::HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges)
{
    TELEPHONY_LOGI("CoreManagerInner::HasOperatorPrivileges slotId:%{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ can not be null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->HasOperatorPrivileges(slotId, hasOperatorPrivileges);
}

std::u16string CoreManagerInner::GetSimIst(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return u"";
    }
    return simManager_->GetSimIst(slotId);
}

int32_t CoreManagerInner::SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->SaveImsSwitch(slotId, imsSwitchValue);
}

int32_t CoreManagerInner::QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->QueryImsSwitch(slotId, imsSwitchValue);
}

int32_t CoreManagerInner::IsCTSimCard(int32_t slotId, bool &isCTSimCard)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->IsCTSimCard(slotId, isCTSimCard);
}

int32_t CoreManagerInner::IsGsm(int32_t slotId, bool &isGsm)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->IsGsm(slotId, isGsm);
}

int32_t CoreManagerInner::IsCdma(int32_t slotId, bool &isCdma)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->IsCdma(slotId, isCdma);
}

int32_t CoreManagerInner::ProcessSignalIntensity(int32_t slotId, const Rssi &signalIntensity)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->ProcessSignalIntensity(slotId, signalIntensity);
}

int32_t CoreManagerInner::StartRadioOnState(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->StartRadioOnState(slotId);
}

int32_t CoreManagerInner::StartGetRilSignalIntensity(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return networkSearchManager_->StartGetRilSignalIntensity(slotId);
}

bool CoreManagerInner::IsSetActiveSimInProgress(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->IsSetActiveSimInProgress(slotId);
}

bool CoreManagerInner::IsSetPrimarySlotIdInProgress()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERROR;
    }
    return simManager_->IsSetPrimarySlotIdInProgress();
}

int32_t CoreManagerInner::SavePrimarySlotId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SavePrimarySlotId(slotId);
}

bool CoreManagerInner::IsDataShareError()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->IsDataShareError();
}

void CoreManagerInner::ResetDataShareError()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return;
    }
    simManager_->ResetDataShareError();
}

void CoreManagerInner::UpdateImsCapFromChip(int32_t slotId, const ImsCapFromChip &imsCapFromChip)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return;
    }
    return simManager_->UpdateImsCapFromChip(slotId, imsCapFromChip);
}
#ifdef CORE_SERVICE_SUPPORT_ESIM
int32_t CoreManagerInner::GetEid(int32_t slotId, std::u16string &eId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetEid(slotId, eId);
}

int32_t CoreManagerInner::GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResult &euiccProfileInfoList)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetEuiccProfileInfoList(slotId, euiccProfileInfoList);
}

int32_t CoreManagerInner::GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetEuiccInfo(slotId, eUiccInfo);
}

int32_t CoreManagerInner::DisableProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
}

int32_t CoreManagerInner::GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSmdsAddress(slotId, portIndex, smdsAddress);
}

int32_t CoreManagerInner::GetRulesAuthTable(int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
}

int32_t CoreManagerInner::GetEuiccChallenge(int32_t slotId, int32_t portIndex, ResponseEsimResult &responseResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetEuiccChallenge(slotId, portIndex, responseResult);
}

int32_t CoreManagerInner::GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
}

int32_t CoreManagerInner::CancelSession(
    int32_t slotId, const std::u16string &transactionId, CancelReason cancelReason, ResponseEsimResult &responseResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->CancelSession(slotId, transactionId, cancelReason, responseResult);
}

int32_t CoreManagerInner::GetProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetProfile(slotId, portIndex, iccId, eUiccProfile);
}

int32_t CoreManagerInner::ResetMemory(int32_t slotId, ResetOption resetOption, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->ResetMemory(slotId, resetOption, enumResult);
}

int32_t CoreManagerInner::SetDefaultSmdpAddress(
    int32_t slotId, const std::u16string &defaultSmdpAddress, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, enumResult);
}

bool CoreManagerInner::IsSupported(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return false;
    }
    return simManager_->IsSupported(slotId);
}

int32_t CoreManagerInner::SendApduData(
    int32_t slotId, const std::u16string &aid, const EsimApduData &apduData, ResponseEsimResult &responseResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SendApduData(slotId, aid, apduData, responseResult);
}

int32_t CoreManagerInner::PrepareDownload(
    int32_t slotId, const DownLoadConfigInfo &downLoadConfigInfo, ResponseEsimResult &responseResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
}

int32_t CoreManagerInner::LoadBoundProfilePackage(int32_t slotId, int32_t portIndex,
    const std::u16string &boundProfilePackage, ResponseEsimBppResult &responseResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
}

int32_t CoreManagerInner::ListNotifications(
    int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->ListNotifications(slotId, portIndex, events, notificationList);
}

int32_t CoreManagerInner::RetrieveNotificationList(
    int32_t slotId, int32_t portIndex, Event events, EuiccNotificationList &notificationList)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->RetrieveNotificationList(slotId, portIndex, events, notificationList);
}

int32_t CoreManagerInner::RetrieveNotification(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->RetrieveNotification(slotId, portIndex, seqNumber, notification);
}

int32_t CoreManagerInner::RemoveNotificationFromList(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
}

int32_t CoreManagerInner::GetEuiccInfo2(int32_t slotId, int32_t portIndex, EuiccInfo2 &euiccInfo2)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
}

int32_t CoreManagerInner::AuthenticateServer(
    int32_t slotId, const AuthenticateConfigInfo &authenticateConfigInfo, ResponseEsimResult &responseResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
}

int32_t CoreManagerInner::DeleteProfile(int32_t slotId, const std::u16string &iccId, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->DeleteProfile(slotId, iccId, enumResult);
}

int32_t CoreManagerInner::SwitchToProfile(int32_t slotId, int32_t portIndex, const std::u16string &iccId,
    bool forceDisableProfile, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, enumResult);
}

int32_t CoreManagerInner::SetProfileNickname(
    int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, ResultCode &enumResult)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetProfileNickname(slotId, iccId, nickname, enumResult);
}
#endif
/******************** simManager_ end ************************/
} // namespace Telephony
} // namespace OHOS

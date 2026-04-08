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

#include "core_service_sim.h"
#include "telephony_permission.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "string_ex.h"
#include "sim_constant.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
void CoreServiceSim::AsyncSimGeneralExecute(const std::function<void()> task)
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

void CoreServiceSim::AsyncSimPinExecute(const std::function<void()> task)
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

void CoreServiceSim::SetSimManager(const std::shared_ptr<ISimManager> &simManager)
{
    simManager_ = simManager;
}

const std::shared_ptr<ISimManager> &CoreServiceSim::GetSimManager() const
{
    return simManager_;
}

int32_t CoreServiceSim::HasSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null || HasSimCard no callback");
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

int32_t CoreServiceSim::GetSimState(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or GetSimState no callback");
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

int32_t CoreServiceSim::GetDsdsMode(int32_t &dsdsMode)
{
    TELEPHONY_LOGI("CoreServiceSim::GetDsdsMode()");
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

int32_t CoreServiceSim::GetCardType(int32_t slotId, CardType &cardType)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return simManager_->GetCardType(slotId, cardType);
}

int32_t CoreServiceSim::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return simManager_->GetISOCountryCodeForSim(slotId, countryCode);
}

int32_t CoreServiceSim::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimSpn(slotId, spn);
}

int32_t CoreServiceSim::GetSimIccId(int32_t slotId, std::u16string &iccId)
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

int32_t CoreServiceSim::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimOperatorNumeric(slotId, operatorNumeric);
}

int32_t CoreServiceSim::GetIMSI(int32_t slotId, std::u16string &imsi)
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

int32_t CoreServiceSim::IsCTSimCard(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or IsCTSimCard no callback");
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

bool CoreServiceSim::IsSimActive(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or IsSimActive no callback");
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

int32_t CoreServiceSim::GetSlotId(int32_t simId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreServiceSimSim::GetSlotId(), simManager_ is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSlotId(simId);
}

int32_t CoreServiceSim::GetSimId(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreServiceSimSim::GetSimId(), simManager_ is nullptr!");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetSimId(slotId);
}

std::u16string CoreServiceSim::GetLocaleFromDefaultSim()
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::GetLocaleFromDefaultSim, Permission denied!");
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

int32_t CoreServiceSim::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::GetSimGid1, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetSimGid1(slotId, gid1);
}

std::u16string CoreServiceSim::GetSimGid2(int32_t slotId)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return std::u16string();
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::GetSimGid2, Permission denied!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return std::u16string();
    }
    return simManager_->GetSimGid2(slotId);
}

std::u16string CoreServiceSim::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreServiceSim::GetSimEons, Permission denied!");
        return std::u16string();
    }
    return simManager_->GetSimEons(slotId, plmn, lac, longNameRequired);
}

int32_t CoreServiceSim::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
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

int32_t CoreServiceSim::SetDefaultVoiceSlotId(int32_t slotId)
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

int32_t CoreServiceSim::GetDefaultVoiceSlotId()
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERROR;
    }
    return simManager_->GetDefaultVoiceSlotId();
}

int32_t CoreServiceSim::GetDefaultVoiceSimId(const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or GetDefaultVoiceSimId no callback");
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

int32_t CoreServiceSim::SetPrimarySlotId(int32_t slotId)
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
    return simManager_->SetPrimarySlotId(slotId, true);
}

int32_t CoreServiceSim::GetPrimarySlotId(int32_t &slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetPrimarySlotId(slotId);
}

int32_t CoreServiceSim::SetShowNumber(int32_t slotId, const std::u16string &number,
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
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or SetShowNumber no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, number, callback]() {
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

int32_t CoreServiceSim::GetShowNumber(int32_t slotId, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or GetShowNumber no callback");
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

int32_t CoreServiceSim::SetShowName(int32_t slotId, const std::u16string &name,
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
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null or SetShowName no callback");
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

int32_t CoreServiceSim::GetShowName(int32_t slotId, const sptr<IRawParcelCallback> &callback)
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

int32_t CoreServiceSim::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    bool denied = false;
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGW("permission denied!");
        denied = true;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetActiveSimAccountInfoList(denied, iccAccountInfoList);
}

int32_t CoreServiceSim::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
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

int32_t CoreServiceSim::UnlockPin(const int32_t slotId, const std::u16string &pin,
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

int32_t CoreServiceSim::UnlockPuk(const int slotId, const std::u16string &newPin, const std::u16string &puk,
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
    TELEPHONY_LOGI("CoreServiceSim::UnlockPuk(), newPinLen = %{public}lu, pukLen = %{public}lu, slotId = %{public}d",
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

int32_t CoreServiceSim::AlterPin(const int slotId, const std::u16string &newPin, const std::u16string &oldPin,
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
    TELEPHONY_LOGI("CoreServiceSim::AlterPin(), newPinLen = %{public}lu, oldPinLen = %{public}lu, slotId = %{public}d",
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

int32_t CoreServiceSim::UnlockPin2(const int32_t slotId, const std::u16string &pin2,
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
    TELEPHONY_LOGI("CoreServiceSim::UnlockPin2(), pin2Len = %{public}lu, slotId = %{public}d",
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

int32_t CoreServiceSim::UnlockPuk2(const int slotId, const std::u16string &newPin2, const std::u16string &puk2,
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
    TELEPHONY_LOGI("CoreServiceSim::UnlockPuk2(), newPin2Len = %{public}lu, puk2Len = %{public}lu, slotId = %{public}d",
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

int32_t CoreServiceSim::AlterPin2(const int slotId, const std::u16string &newPin2,
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
    TELEPHONY_LOGI("AlterPin2, newPin2Len = %{public}lu, oldPin2Len = %{public}lu, slotId = %{public}d",
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

int32_t CoreServiceSim::SetLockState(int32_t slotId, const LockInfo &options, const sptr<IRawParcelCallback> &callback)
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
        "CoreServiceSim::SetLockState(),lockType = %{public}d, pinLen = %{public}lu, lockState = %{public}d, slotId "
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

int32_t CoreServiceSim::GetLockState(int32_t slotId, LockType lockType, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::GetLockState, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreServiceSim::GetLockState(), lockType = %{public}d, slotId = %{public}d", lockType, slotId);
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

int32_t CoreServiceSim::RefreshSimState(int32_t slotId)
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

int32_t CoreServiceSim::SetActiveSim(int32_t slotId, int32_t enable)
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

int32_t CoreServiceSim::SetActiveSimSatellite(int32_t slotId, int32_t enable)
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

int32_t CoreServiceSim::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
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

std::u16string CoreServiceSim::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::GetSimTeleNumberIdentifier, Permission denied!");
        return std::u16string();
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return std::u16string();
    }
    return simManager_->GetSimTeleNumberIdentifier(slotId);
}

int32_t CoreServiceSim::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
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

int32_t CoreServiceSim::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
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

int32_t CoreServiceSim::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreServiceSim::GetVoiceMailCount(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreServiceSim::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreServiceSim::SetVoiceMailCount(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreServiceSim::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    TELEPHONY_LOGI("CoreServiceSim::SetVoiceCallForwarding(), slotId = %{public}d", slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->SetVoiceCallForwarding(slotId, enable, number);
}

int32_t CoreServiceSim::QueryIccDiallingNumbers(
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

int32_t CoreServiceSim::AddIccDiallingNumbers(
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

int32_t CoreServiceSim::DelIccDiallingNumbers(
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

int32_t CoreServiceSim::UpdateIccDiallingNumbers(
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

int32_t CoreServiceSim::SetVoiceMailInfo(
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

int32_t CoreServiceSim::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpKey(slotId, opkey);
}

int32_t CoreServiceSim::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpKeyExt(slotId, opkeyExt);
}

int32_t CoreServiceSim::GetOpName(int32_t slotId, std::u16string &opname)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->GetOpName(slotId, opname);
}

int32_t CoreServiceSim::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreServiceSim::SendEnvelopeCmd simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::SendEnvelopeCmd, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    return simManager_->SendEnvelopeCmd(slotId, cmd);
}

int32_t CoreServiceSim::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreServiceSim::SendEnvelopeCmd simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::SendTerminalResponseCmd, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    return simManager_->SendTerminalResponseCmd(slotId, cmd);
}

int32_t CoreServiceSim::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("CoreServiceSim::SendEnvelopeCmd simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("CoreServiceSim::SendCallSetupRequestResult, Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    return simManager_->SendCallSetupRequestResult(slotId, accept);
}

int32_t CoreServiceSim::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
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
        "CoreServiceSim::UnlockSimLock(), lockType = %{public}d, slotId = %{public}d", lockInfo.lockType, slotId);
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return simManager_->UnlockSimLock(slotId, lockInfo, response);
}

int32_t CoreServiceSim::HasOperatorPrivileges(const int32_t slotId, const sptr<IRawParcelCallback> &callback)
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

int32_t CoreServiceSim::SimAuthentication(
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

int32_t CoreServiceSim::GetSimIO(int32_t slotId, int32_t command,
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

int32_t CoreServiceSim::GetAllSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
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
    return simManager_->GetAllSimAccountInfoList(denied, iccAccountInfoList);
}

int32_t CoreServiceSim::GetSimLabel(int32_t slotId, SimLabel &simLabel, const sptr<IRawParcelCallback> &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), slotId, callback]() {
        SimLabel simLabel;
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager) {
            ret = simManager->GetSimLabel(slotId, simLabel);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            if (ret == TELEPHONY_ERR_SUCCESS) {
                data.WriteInt32(static_cast<int32_t>(simLabel.simType));
                data.WriteInt32(simLabel.index);
            }
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}

int32_t CoreServiceSim::GetRealSimCount()
{
    int32_t realSlotCount = SIM_SLOT_COUNT_REAL;
    if (simManager_ != nullptr) {
        return simManager_->GetRealSimCount();
    }
    return realSlotCount;
}

int32_t CoreServiceSim::SetSimLabelIndex(int32_t simId, int32_t simLabelIndex, const sptr<IRawParcelCallback> &callback)
{
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        TELEPHONY_LOGE("Non-system applications use system APIs!");
        return TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    }
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (simManager_ == nullptr || callback == nullptr) {
        TELEPHONY_LOGE("simManager_ is null || SetSimLabelIndex no callback");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AsyncSimGeneralExecute([wp = std::weak_ptr<ISimManager>(simManager_), simId, simLabelIndex, callback]() {
        MessageParcel dataTmp;
        auto simManager = wp.lock();
        int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
        if (simManager != nullptr) {
            ret = simManager->SetSimLabelIndex(simId, simLabelIndex);
        }
        callback->Transfer([=](MessageParcel &data) {
            data.WriteInt32(ret);
            }, dataTmp);
    });
    return TELEPHONY_ERR_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS

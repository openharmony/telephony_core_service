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
#include "core_service.h"
#include "phone_manager.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "telephony_log.h"

namespace OHOS {
const bool G_REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<CoreService>::GetInstance().get());

CoreService::CoreService() : SystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID, true) {}

CoreService::~CoreService() {}

void CoreService::OnStart()
{
    TELEPHONY_INFO_LOG("CoreService::OnStart start service");

    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TELEPHONY_INFO_LOG("CoreService has already started.");
        return;
    }
    if (!Init()) {
        TELEPHONY_ERR_LOG("failed to init CoreService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    TELEPHONY_INFO_LOG("CoreService::OnStart start service success.");
}

bool CoreService::Init()
{
    PhoneManager ::GetInstance().Init();

    TELEPHONY_INFO_LOG("CoreService::Init ready to init...........");
    if (!registerToService_) {
        bool ret = Publish(DelayedSingleton<CoreService>::GetInstance().get());
        if (!ret) {
            TELEPHONY_ERR_LOG("CoreService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    TELEPHONY_INFO_LOG("CoreService::Init init success.");

    return true;
}

void CoreService::OnStop()
{
    TELEPHONY_INFO_LOG("CoreService::OnStop ready to stop service.");
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
    TELEPHONY_INFO_LOG("CoreService::OnStop stop service success.");
}

int32_t CoreService::GetPsRadioTech(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetPsRadioTech");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->networkSearchManager_->GetPsRadioTech(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetPsRadioTech slotId invalid.");
        return -1;
    }
}

int32_t CoreService::GetCsRadioTech(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetCsRadioTech");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->networkSearchManager_->GetCsRadioTech(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetCsRadioTech slotId invalid.");
        return -1;
    }
}

std::vector<sptr<SignalInformation>> CoreService::GetSignalInfoList(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetSignalInfoList");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->networkSearchManager_->GetSignalInfoList(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetSignalInfoList slotId invalid.");
        return std::vector<sptr<SignalInformation>>();
    }
}

std::u16string CoreService::GetOperatorNumeric(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetOperatorNumeric");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        Phone *imp = PhoneManager ::GetInstance().phone_[slotId];
        std::u16string result = imp->networkSearchManager_->GetOperatorNumeric(slotId);
        std::string str = Str16ToStr8(result);
        TELEPHONY_INFO_LOG("CoreService GetOperatorNumeric %{public}s\n", str.c_str());
        return result;
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetOperatorNumeric slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetOperatorName(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetOperatorName");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->networkSearchManager_->GetOperatorName(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetOperatorName slotId invalid.");
        return std::u16string();
    }
}

const sptr<NetworkState> CoreService::GetNetworkStatus(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetNetworkStatus");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->networkSearchManager_->GetNetworkStatus(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetNetworkStatus slotId invalid.");
        return nullptr;
    }
}

void CoreService::SetHRilRadioState(int32_t slotId, bool isOn)
{
    TELEPHONY_INFO_LOG("CoreService::SetRadioState");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        PhoneManager ::GetInstance().phone_[slotId]->networkSearchManager_->SetHRilRadioState(isOn);
    } else {
        TELEPHONY_INFO_LOG("CoreService::SetRadioState slotId invalid.");
    }
}

int32_t CoreService::GetRadioState(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetRadioState");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        Phone *imp = PhoneManager ::GetInstance().phone_[slotId];
        return static_cast<int32_t>(imp->networkSearchManager_->GetRadioState(slotId));
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetRadioState slotId invalid.");
        return -1;
    }
}

bool CoreService::HasSimCard(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::HasSimCard");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simStateManager_->HasSimCard(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::HasSimCard slotId invalid.");
        return false;
    }
}

int32_t CoreService::GetSimState(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetSimState");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simStateManager_->GetSimState(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetSimState slotId invalid.");
        return -1;
    }
}

std::u16string CoreService::GetIsoCountryCode(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetIsoCountryCode");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simFileManager_->GetIsoCountryCode(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetIsoCountryCode slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetSpn(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetSpn");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simFileManager_->GetSpn(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetSpn slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetIccId(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetIccId");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simFileManager_->GetIccId(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetIccId slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetSimOperator(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetSimOperator");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simFileManager_->GetSimOperator(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetSimOperator slotId invalid.");
        return std::u16string();
    }
}

std::u16string CoreService::GetIMSI(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::GetIMSI");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simFileManager_->GetIMSI(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::GetIMSI slotId invalid.");
        return std::u16string();
    }
}

bool CoreService::IsSimActive(int32_t slotId)
{
    TELEPHONY_INFO_LOG("CoreService::IsSimActive");
    if (PhoneManager ::GetInstance().phone_.find(slotId) != PhoneManager ::GetInstance().phone_.end()) {
        return PhoneManager ::GetInstance().phone_[slotId]->simStateManager_->IsSimActive(slotId);
    } else {
        TELEPHONY_INFO_LOG("CoreService::IsSimActive slotId invalid.");
        return false;
    }
}
} // namespace OHOS

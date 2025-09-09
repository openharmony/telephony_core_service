/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MOCK_I_SYSTEM_ABILITY_MANAGER_H
#define MOCK_I_SYSTEM_ABILITY_MANAGER_H
#include <gmock/gmock.h>
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace Telephony {
class MockISystemAbilityManagerInner : public ISystemAbilityManager {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
    MOCK_METHOD(std::vector<std::u16string>, ListSystemAbilities, (unsigned int dumpFlags), (override));
    MOCK_METHOD(sptr<IRemoteObject>, GetSystemAbility, (int32_t systemAbilityId), (override));
    MOCK_METHOD(sptr<IRemoteObject>, CheckSystemAbility, (int32_t systemAbilityId), (override));
    MOCK_METHOD(int32_t, RemoveSystemAbility, (int32_t systemAbilityId), (override));
    MOCK_METHOD(int32_t, SubscribeSystemAbility,
        (int32_t systemAbilityId, const sptr<ISystemAbilityStatusChange> &listener), (override));
    MOCK_METHOD(int32_t, UnSubscribeSystemAbility,
        (int32_t systemAbilityId, const sptr<ISystemAbilityStatusChange> &listener), (override));
    MOCK_METHOD(
        sptr<IRemoteObject>, GetSystemAbility, (int32_t systemAbilityId, const std::string &deviceId), (override));
    MOCK_METHOD(
        sptr<IRemoteObject>, CheckSystemAbility, (int32_t systemAbilityId, const std::string &deviceId), (override));
    MOCK_METHOD(int32_t, AddOnDemandSystemAbilityInfo,
        (int32_t systemAbilityId, const std::u16string &localAbilityManagerName), (override));
    MOCK_METHOD(sptr<IRemoteObject>, CheckSystemAbility, (int32_t systemAbilityId, bool &isExist), (override));
    MOCK_METHOD(int32_t, AddSystemAbility,
        (int32_t systemAbilityId, const sptr<IRemoteObject> &ability, const SAExtraProp &extraProp), (override));
    MOCK_METHOD(
        int32_t, AddSystemProcess, (const std::u16string &procName, const sptr<IRemoteObject> &procObject), (override));
    MOCK_METHOD(sptr<IRemoteObject>, LoadSystemAbility, (int32_t systemAbilityId, int32_t timeout), (override));
    MOCK_METHOD(int32_t, LoadSystemAbility, (int32_t systemAbilityId, const sptr<ISystemAbilityLoadCallback> &callback),
        (override));
    MOCK_METHOD(int32_t, LoadSystemAbility,
        (int32_t systemAbilityId, const std::string &deviceId, const sptr<ISystemAbilityLoadCallback> &callback),
        (override));
    MOCK_METHOD(int32_t, UnloadSystemAbility, (int32_t systemAbilityId), (override));
    MOCK_METHOD(int32_t, CancelUnloadSystemAbility, (int32_t systemAbilityId), (override));
    MOCK_METHOD(int32_t, UnloadAllIdleSystemAbility, (), (override));

    MOCK_METHOD(
        int32_t, GetSystemProcessInfo, (int32_t systemAbilityId, SystemProcessInfo &systemProcessInfo), (override));
    MOCK_METHOD(int32_t, GetRunningSystemProcess, (std::list<SystemProcessInfo> & systemProcessInfos), (override));
    MOCK_METHOD(int32_t, SubscribeSystemProcess, (const sptr<ISystemProcessStatusChange> &listener), (override));
    MOCK_METHOD(int32_t, SendStrategy,
        (int32_t type, std::vector<int32_t> &systemAbilityIds, int32_t level, std::string &action), (override));
    MOCK_METHOD(int32_t, UnSubscribeSystemProcess, (const sptr<ISystemProcessStatusChange> &listener), (override));
    MOCK_METHOD(int32_t, GetExtensionSaIds, (const std::string &extension, std::vector<int32_t> &saIds), (override));
    MOCK_METHOD(int32_t, GetExtensionRunningSaList,
        (const std::string &extension, std::vector<sptr<IRemoteObject>> &saList), (override));
    MOCK_METHOD(int32_t, GetRunningSaExtensionInfoList,
        (const std::string &extension, std::vector<SaExtensionInfo> &infoList), (override));
    MOCK_METHOD(int32_t, GetCommonEventExtraDataIdlist,
        (int32_t saId, std::vector<int64_t> &extraDataIdList, const std::string &eventName), (override));
    MOCK_METHOD(int32_t, GetOnDemandReasonExtraData, (int64_t extraDataId, MessageParcel &extraDataParcel), (override));
    MOCK_METHOD(int32_t, GetOnDemandPolicy,
        (int32_t systemAbilityId, OnDemandPolicyType type,
            std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents),
        (override));
    MOCK_METHOD(int32_t, UpdateOnDemandPolicy,
        (int32_t systemAbilityId, OnDemandPolicyType type,
            const std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents),
        (override));
    MOCK_METHOD(int32_t, GetOnDemandSystemAbilityIds, (std::vector<int32_t> & systemAbilityIds), (override));
};

class MockISystemAbilityManagerHelper {
public:
    MockISystemAbilityManagerHelper();
    ~MockISystemAbilityManagerHelper();
};

class MockISystemAbilityManager : public ISystemAbilityManager {
    friend class MockISystemAbilityManagerHelper;

public:
    static sptr<MockISystemAbilityManager> GetInstance()
    {
        static sptr<MockISystemAbilityManager> instance = sptr<MockISystemAbilityManager>::MakeSptr();
        return instance;
    }

    MockISystemAbilityManager()
    {
        mockProxy_ = sptr<testing::NiceMock<MockISystemAbilityManagerInner>>::MakeSptr();
        realProxy_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        current_ = realProxy_;
    }

    MockISystemAbilityManagerInner &GetMock()
    {
        return *mockProxy_.GetRefPtr();
    }

    virtual sptr<IRemoteObject> AsObject()
    {
        return current_->AsObject();
    }

    std::vector<std::u16string> ListSystemAbilities(unsigned int dumpFlags) override
    {
        return current_->ListSystemAbilities(dumpFlags);
    }

    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId) override
    {
        return current_->GetSystemAbility(systemAbilityId);
    }

    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId) override
    {
        return current_->CheckSystemAbility(systemAbilityId);
    }

    int32_t RemoveSystemAbility(int32_t systemAbilityId) override
    {
        return current_->RemoveSystemAbility(systemAbilityId);
    }

    int32_t SubscribeSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityStatusChange> &listener) override
    {
        return mockProxy_->SubscribeSystemAbility(systemAbilityId, listener);
    }

    int32_t UnSubscribeSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityStatusChange> &listener) override
    {
        return mockProxy_->UnSubscribeSystemAbility(systemAbilityId, listener);
    }

    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        return current_->GetSystemAbility(systemAbilityId, deviceId);
    }

    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        return current_->CheckSystemAbility(systemAbilityId, deviceId);
    }

    int32_t AddOnDemandSystemAbilityInfo(
        int32_t systemAbilityId, const std::u16string &localAbilityManagerName) override
    {
        return current_->AddOnDemandSystemAbilityInfo(systemAbilityId, localAbilityManagerName);
    }

    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, bool &isExist) override
    {
        return current_->CheckSystemAbility(systemAbilityId, isExist);
    }

    int32_t AddSystemAbility(
        int32_t systemAbilityId, const sptr<IRemoteObject> &ability, const SAExtraProp &extraProp) override
    {
        return current_->AddSystemAbility(systemAbilityId, ability, extraProp);
    }

    int32_t AddSystemProcess(const std::u16string &procName, const sptr<IRemoteObject> &procObject) override
    {
        return current_->AddSystemProcess(procName, procObject);
    }

    sptr<IRemoteObject> LoadSystemAbility(int32_t systemAbilityId, int32_t timeout) override
    {
        return current_->LoadSystemAbility(systemAbilityId, timeout);
    }

    int32_t LoadSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityLoadCallback> &callback) override
    {
        return current_->LoadSystemAbility(systemAbilityId, callback);
    }

    int32_t LoadSystemAbility(
        int32_t systemAbilityId, const std::string &deviceId, const sptr<ISystemAbilityLoadCallback> &callback) override
    {
        return current_->LoadSystemAbility(systemAbilityId, deviceId, callback);
    }

    int32_t UnloadSystemAbility(int32_t systemAbilityId) override
    {
        return current_->UnloadSystemAbility(systemAbilityId);
    }

    int32_t CancelUnloadSystemAbility(int32_t systemAbilityId) override
    {
        return current_->CancelUnloadSystemAbility(systemAbilityId);
    }

    int32_t UnloadAllIdleSystemAbility() override
    {
        return current_->UnloadAllIdleSystemAbility();
    }

    int32_t GetSystemProcessInfo(int32_t systemAbilityId, SystemProcessInfo &systemProcessInfo) override
    {
        return current_->GetSystemProcessInfo(systemAbilityId, systemProcessInfo);
    }

    int32_t GetRunningSystemProcess(std::list<SystemProcessInfo> &systemProcessInfos) override
    {
        return current_->GetRunningSystemProcess(systemProcessInfos);
    }

    int32_t SubscribeSystemProcess(const sptr<ISystemProcessStatusChange> &listener) override
    {
        return current_->SubscribeSystemProcess(listener);
    }

    int32_t SendStrategy(
        int32_t type, std::vector<int32_t> &systemAbilityIds, int32_t level, std::string &action) override
    {
        return current_->SendStrategy(type, systemAbilityIds, level, action);
    }

    int32_t UnSubscribeSystemProcess(const sptr<ISystemProcessStatusChange> &listener) override
    {
        return current_->UnSubscribeSystemProcess(listener);
    }

    int32_t GetExtensionSaIds(const std::string &extension, std::vector<int32_t> &saIds) override
    {
        return current_->GetExtensionSaIds(extension, saIds);
    }

    int32_t GetExtensionRunningSaList(const std::string &extension, std::vector<sptr<IRemoteObject>> &saList) override
    {
        return current_->GetExtensionRunningSaList(extension, saList);
    }

    int32_t GetRunningSaExtensionInfoList(const std::string &extension, std::vector<SaExtensionInfo> &infoList) override
    {
        return current_->GetRunningSaExtensionInfoList(extension, infoList);
    }

    int32_t GetCommonEventExtraDataIdlist(
        int32_t saId, std::vector<int64_t> &extraDataIdList, const std::string &eventName) override
    {
        return current_->GetCommonEventExtraDataIdlist(saId, extraDataIdList, eventName);
    }

    int32_t GetOnDemandReasonExtraData(int64_t extraDataId, MessageParcel &extraDataParcel) override
    {
        return current_->GetOnDemandReasonExtraData(extraDataId, extraDataParcel);
    }

    int32_t GetOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents) override
    {
        return current_->GetOnDemandPolicy(systemAbilityId, type, abilityOnDemandEvents);
    }

    int32_t UpdateOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        const std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents) override
    {
        return current_->UpdateOnDemandPolicy(systemAbilityId, type, abilityOnDemandEvents);
    }

    int32_t GetOnDemandSystemAbilityIds(std::vector<int32_t> &systemAbilityIds) override
    {
        return current_->GetOnDemandSystemAbilityIds(systemAbilityIds);
    }

private:
    void UseMock()
    {
        mockProxy_ = sptr<testing::NiceMock<MockISystemAbilityManagerInner>>::MakeSptr();
        testing::Mock::AllowLeak(mockProxy_.GetRefPtr());
        current_ = mockProxy_;
    }

    void UseReal()
    {
        current_ = realProxy_;
    }

    sptr<MockISystemAbilityManagerInner> mockProxy_;
    sptr<ISystemAbilityManager> realProxy_;
    sptr<ISystemAbilityManager> current_;
};

inline MockISystemAbilityManagerHelper::MockISystemAbilityManagerHelper()
{
    MockISystemAbilityManager::GetInstance()->UseMock();
}

inline MockISystemAbilityManagerHelper::~MockISystemAbilityManagerHelper()
{
    MockISystemAbilityManager::GetInstance()->UseReal();
}

}  // namespace Telephony
}  // namespace OHOS
#endif
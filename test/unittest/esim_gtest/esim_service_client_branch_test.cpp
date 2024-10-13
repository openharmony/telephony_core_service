/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define private public
#define protected public

#include "esim_mock_iremote_object.h"
#include "esim_service_client.h"
#include "esim_state_type.h"
#include "if_system_ability_manager_mock.h"
#include "iservice_registry.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
constexpr int32_t SLOT_ID = 0;
class EsimServiceClientBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<ISystemAbilityManagerMock> samgr = std::make_shared<ISystemAbilityManagerMock>();
};

void EsimServiceClientBranchTest::SetUpTestCase()
{
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = sptr<ISystemAbilityManager>(samgr.get());
}

void EsimServiceClientBranchTest::TearDownTestCase()
{
    samgr = nullptr;
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = nullptr;
}

void EsimServiceClientBranchTest::SetUp() {}

void EsimServiceClientBranchTest::TearDown() {}

HWTEST_F(EsimServiceClientBranchTest, GetEid_0001, Function | MediumTest | Level1)
{
    std::string eId;
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetEid(SLOT_ID, eId);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, GetOsuStatus_0001, Function | MediumTest | Level1)
{
    int32_t osuStatus;
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetOsuStatus(SLOT_ID, osuStatus);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, StartOsu_0001, Function | MediumTest | Level1)
{
    int32_t startOsuResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().StartOsu(SLOT_ID, startOsuResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, GetDownloadableProfileMetadata_0001, Function | MediumTest | Level1)
{
    int32_t portIndex = 0;
    DownloadableProfile profile;
    bool forceDeactivateSim = false;
    GetDownloadableProfileMetadataResult profileMetadataResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetDownloadableProfileMetadata(
        SLOT_ID, portIndex, profile, forceDeactivateSim, profileMetadataResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, GetDownloadableProfiles_0001, Function | MediumTest | Level1)
{
    bool forceDeactivateSim = false;
    int32_t portIndex = 0;
    GetDownloadableProfilesResult profileListResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetDownloadableProfiles(
        SLOT_ID, portIndex, forceDeactivateSim, profileListResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, DownloadProfile_0001, Function | MediumTest | Level1)
{
    DownloadProfileConfigInfo configInfo;
    DownloadableProfile profile;
    DownloadProfileResult downloadProfileResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().DownloadProfile(
        SLOT_ID, configInfo, profile, downloadProfileResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, GetEuiccProfileInfoList_0001, Function | MediumTest | Level1)
{
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetEuiccProfileInfoList(SLOT_ID, euiccProfileInfoList);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, GetEuiccInfo_0001, Function | MediumTest | Level1)
{
    EuiccInfo eUiccInfo;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetEuiccInfo(SLOT_ID, eUiccInfo);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, DeleteProfile_0001, Function | MediumTest | Level1)
{
    std::string iccId = "98760000000000543210";
    int32_t deleteProfileResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().DeleteProfile(SLOT_ID, iccId, deleteProfileResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, SwitchToProfile_0001, Function | MediumTest | Level1)
{
    int32_t portIndex = 0;
    std::string iccId = "98760000000000543210";
    bool forceDeactivateSim = true;
    int32_t switchToProfileResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().SwitchToProfile(
        SLOT_ID, portIndex, iccId, forceDeactivateSim, switchToProfileResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, SetProfileNickname_0001, Function | MediumTest | Level1)
{
    std::string iccId = "98760000000000543210";
    std::string nickname = "nick";
    int32_t setProfileNicknameResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().SetProfileNickname(
        SLOT_ID, iccId, nickname, setProfileNicknameResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, ResetMemory_0001, Function | MediumTest | Level1)
{
    int32_t resetOption = static_cast<int32_t>(ResetOption::DELETE_FIELD_LOADED_TEST_PROFILES);
    int32_t resetMemoryResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().ResetMemory(SLOT_ID, resetOption, resetMemoryResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, ReserveProfilesForFactoryRestore_0001, Function | MediumTest | Level1)
{
    int32_t reserveProfilesForFactoryRestoreResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().ReserveProfilesForFactoryRestore(
        SLOT_ID, reserveProfilesForFactoryRestoreResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, SetDefaultSmdpAddress_0001, Function | MediumTest | Level1)
{
    std::string defaultSmdpAddress = "smdp.gsma.com";
    int32_t setAddressResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().SetDefaultSmdpAddress(
        SLOT_ID, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, GetDefaultSmdpAddress_0001, Function | MediumTest | Level1)
{
    std::string defaultSmdpAddress;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().GetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, CancelSession_0001, Function | MediumTest | Level1)
{
    std::string transactionId = "A1B2C3";
    const int32_t cancelReason = static_cast<int32_t>(CancelReason::CANCEL_REASON_POSTPONED);
    ResponseEsimResult responseResult;
    
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    int32_t result = EsimServiceClient::GetInstance().CancelSession(
        SLOT_ID, transactionId, cancelReason, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimServiceClientBranchTest, IsEsimSupported_0001, Function | MediumTest | Level1)
{
    EXPECT_CALL(*samgr, LoadSystemAbility(testing::_,
        testing::A<const sptr<ISystemAbilityLoadCallback>&>())).WillOnce(testing::Return(-1));
    bool result = EsimServiceClient::GetInstance().IsEsimSupported(SLOT_ID);
    EXPECT_EQ(result, false);
}

HWTEST_F(EsimServiceClientBranchTest, RemoveDeathRecipient_0001, Function | MediumTest | Level1)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    bool isRemoteDied = true;
    EsimServiceClient::GetInstance().RemoveDeathRecipient(remote, isRemoteDied);
    EXPECT_NE(remote, nullptr);
}

HWTEST_F(EsimServiceClientBranchTest, RemoveDeathRecipient_0002, Function | MediumTest | Level1)
{
    sptr<MockIRemoteObject> remote = nullptr;
    bool isRemoteDied = true;
    EsimServiceClient::GetInstance().RemoveDeathRecipient(remote, isRemoteDied);
    EXPECT_EQ(remote, nullptr);

    remote = new (std::nothrow) MockIRemoteObject();
    isRemoteDied = false;
    EsimServiceClient::GetInstance().RemoveDeathRecipient(remote, isRemoteDied);
    EXPECT_NE(remote, nullptr);
}

HWTEST_F(EsimServiceClientBranchTest, OnLoadSystemAbilitySuccess_0001, Function | MediumTest | Level1)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    EXPECT_NE(remote, nullptr);
    int32_t systemAbilityId = 66250;
    EsimServiceClientCallback call;
    call.OnLoadSystemAbilitySuccess(systemAbilityId, remote);
    EXPECT_NE(call.remoteObject_, nullptr);
}

HWTEST_F(EsimServiceClientBranchTest, OnLoadSystemAbilityFail_0001, Function | MediumTest | Level1)
{
    int32_t systemAbilityId = 66250;
    EsimServiceClientCallback call;
    call.OnLoadSystemAbilityFail(systemAbilityId);
    EXPECT_TRUE(call.isLoadSAFailed_);
}

HWTEST_F(EsimServiceClientBranchTest, IsFailed_0001, Function | MediumTest | Level1)
{
    EsimServiceClientCallback call;
    call.isLoadSAFailed_ = true;
    call.IsFailed();
    EXPECT_TRUE(call.isLoadSAFailed_);
}

HWTEST_F(EsimServiceClientBranchTest, GetRemoteObject_0001, Function | MediumTest | Level1)
{
    EsimServiceClientCallback call;
    call.remoteObject_ = new (std::nothrow) MockIRemoteObject();
    call.GetRemoteObject();
    EXPECT_NE(call.remoteObject_, nullptr);
}

HWTEST_F(EsimServiceClientBranchTest, OnRemoteDied_0001, Function | MediumTest | Level1)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    EXPECT_NE(remote, nullptr);
    EsimServiceClient::GetInstance().proxy_ = nullptr;
    EsimServiceClient::GetInstance().OnRemoteDied(remote);
    EXPECT_EQ(EsimServiceClient::GetInstance().proxy_, nullptr);
}
} // namespace Telephony
} // namespace OHOS
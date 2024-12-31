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

#include "gtest/gtest.h"
#include "core_manager_inner.h"
#include "core_service_proxy.h"
#include "network_search_manager.h"
#include "resource_utils.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"

#include "download_profile_config_info_parcel.h"
#include "download_profile_result_parcel.h"
#include "downloadable_profile_parcel.h"
#include "esim_state_type.h"
#include "euicc_info_parcel.h"
#include "get_downloadable_profiles_result_parcel.h"
#include "profile_info_list_parcel.h"
#include "profile_metadata_result_parcel.h"
#include "response_esim_result.h"
#include "tel_ril_sim_parcel.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
constexpr int32_t INVALID_SLOTID = -1;
constexpr int32_t INVALID_DEFAULT_SLOTID = -2;
} // namespace

class CoreServiceNativeBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CoreServiceNativeBranchTest::TearDownTestCase() {}

void CoreServiceNativeBranchTest::SetUp() {}

void CoreServiceNativeBranchTest::TearDown() {}

void CoreServiceNativeBranchTest::SetUpTestCase() {}

class TestIRemoteObject : public IRemoteObject {
public:
    uint32_t requestCode_ = -1;
    int32_t result_ = 0;

public:
    TestIRemoteObject() : IRemoteObject(u"test_remote_object") {}

    ~TestIRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        TELEPHONY_LOGI("Mock SendRequest");
        requestCode_ = code;
        reply.WriteInt32(result_);
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};

HWTEST_F(CoreServiceNativeBranchTest, Telephony_ResourceUtils, Function | MediumTest | Level1)
{
    ResourceUtils resourceUtils;

    resourceUtils.beSourceAdd_ = true;
    EXPECT_TRUE(resourceUtils.Init());

    resourceUtils.beSourceAdd_ = false;
    resourceUtils.resourceManager_ = nullptr;
    EXPECT_FALSE(resourceUtils.Init());

    std::string strValue = "";
    int intValue = 0;
    bool boolValue = false;
    std::vector<std::string> strVector;
    std::vector<int32_t> intVector;
    resourceUtils.resourceManager_ =
        std::unique_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager());
    ASSERT_NE(resourceUtils.resourceManager_, nullptr);
    EXPECT_FALSE(resourceUtils.GetStringByName("testName", strValue));
    EXPECT_FALSE(resourceUtils.GetIntegerByName("testName", intValue));
    EXPECT_FALSE(resourceUtils.GetBooleanByName("testName", boolValue));
    EXPECT_FALSE(resourceUtils.GetStringArrayByName("testName", strVector));
    EXPECT_FALSE(resourceUtils.GetIntArrayByName("testName", intVector));

    std::string name = "name";
    EXPECT_TRUE(resourceUtils.GetCallFailedMessageName(-1, name));
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreServiceProxy_001, Function | MediumTest | Level1)
{
    sptr<TestIRemoteObject> remote = new (std::nothrow) TestIRemoteObject();
    CoreServiceProxy coreServiceProxy(remote);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    EXPECT_EQ(coreServiceProxy.GetSimState(-1, simState), TELEPHONY_ERR_SLOTID_INVALID);

    std::u16string testU16Str = u"";
    EXPECT_EQ(coreServiceProxy.GetISOCountryCodeForSim(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetSimOperatorNumeric(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetSimSpn(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetSimIccId(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetIMSI(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);

    bool isCTSimCard = false;
    EXPECT_EQ(coreServiceProxy.IsCTSimCard(-1, isCTSimCard), TELEPHONY_ERR_SLOTID_INVALID);

    EXPECT_FALSE(coreServiceProxy.IsSimActive(-1));
    EXPECT_EQ(coreServiceProxy.GetSlotId(-1), -1);
    EXPECT_EQ(coreServiceProxy.GetSimId(-1), -1);

    EXPECT_EQ(coreServiceProxy.GetSimGid1(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ((coreServiceProxy.GetSimGid2(-1)), u"");

    std::string plmn = "";
    EXPECT_EQ((coreServiceProxy.GetSimEons(-1, plmn, 0, false)), u"");
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreServiceProxy_002, Function | MediumTest | Level1)
{
    sptr<TestIRemoteObject> remote = new (std::nothrow) TestIRemoteObject();
    CoreServiceProxy coreServiceProxy(remote);

    IccAccountInfo info;
    EXPECT_EQ(coreServiceProxy.GetSimAccountInfo(INVALID_SLOTID, info), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SetDefaultVoiceSlotId(INVALID_DEFAULT_SLOTID), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SetPrimarySlotId(INVALID_SLOTID), TELEPHONY_ERR_SLOTID_INVALID);

    std::u16string testU16Str = u"";
    EXPECT_EQ(coreServiceProxy.SetShowNumber(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetShowNumber(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SetShowName(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetShowName(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);

    OperatorConfig poc;
    EXPECT_EQ(coreServiceProxy.GetOperatorConfigs(INVALID_SLOTID, poc), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_FALSE(coreServiceProxy.IsValidSlotIdEx(INVALID_SLOTID));
    EXPECT_FALSE(coreServiceProxy.IsValidSlotIdForDefault(INVALID_DEFAULT_SLOTID));
    EXPECT_EQ(coreServiceProxy.SetActiveSim(INVALID_SLOTID, -1), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SetActiveSimSatellite(INVALID_SLOTID, -1), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetSimTelephoneNumber(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetSimTeleNumberIdentifier(INVALID_SLOTID), u"");
    EXPECT_EQ(coreServiceProxy.GetVoiceMailIdentifier(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetVoiceMailNumber(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);

    int32_t voiceMailCount = 0;
    EXPECT_EQ(coreServiceProxy.GetVoiceMailCount(INVALID_SLOTID, voiceMailCount), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SetVoiceMailCount(INVALID_SLOTID, voiceMailCount), TELEPHONY_ERR_SLOTID_INVALID);

    testU16Str = u"test";
    EXPECT_TRUE(coreServiceProxy.IsValidStringLength(testU16Str));
    testU16Str = u"testABCDEFGHIJKLMNOPQRSTUVWXYZtestabcdefg";
    EXPECT_FALSE(coreServiceProxy.IsValidStringLength(testU16Str));

    std::string number = "";
    EXPECT_EQ(coreServiceProxy.SetVoiceCallForwarding(INVALID_SLOTID, false, number), TELEPHONY_ERR_SLOTID_INVALID);

    std::vector<std::shared_ptr<DiallingNumbersInfo>> reslut = {};
    EXPECT_EQ(coreServiceProxy.QueryIccDiallingNumbers(INVALID_SLOTID, 1, reslut), TELEPHONY_ERR_SLOTID_INVALID);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreServiceProxy_003, Function | MediumTest | Level1)
{
    sptr<TestIRemoteObject> remote = new (std::nothrow) TestIRemoteObject();
    CoreServiceProxy coreServiceProxy(remote);

    const std::shared_ptr<DiallingNumbersInfo> diallingNumber = nullptr;
    EXPECT_EQ(coreServiceProxy.AddIccDiallingNumbers(INVALID_SLOTID, 1, diallingNumber), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.DelIccDiallingNumbers(INVALID_SLOTID, 1, diallingNumber), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.UpdateIccDiallingNumbers(INVALID_SLOTID, 1, diallingNumber),
        TELEPHONY_ERR_SLOTID_INVALID);

    std::u16string testU16Str = u"";
    EXPECT_EQ(coreServiceProxy.SetVoiceMailInfo(INVALID_SLOTID, testU16Str, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetOpKey(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetOpKeyExt(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.GetOpName(INVALID_SLOTID, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);

    std::string cmd = "";
    EXPECT_EQ(coreServiceProxy.SendEnvelopeCmd(INVALID_SLOTID, cmd), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SendTerminalResponseCmd(INVALID_SLOTID, cmd), TELEPHONY_ERR_SLOTID_INVALID);

    LockStatusResponse response;
    PersoLockInfo lockInfo;
    EXPECT_EQ(coreServiceProxy.UnlockSimLock(INVALID_SLOTID, lockInfo, response), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(coreServiceProxy.SendTerminalResponseCmd(INVALID_SLOTID, cmd), TELEPHONY_ERR_SLOTID_INVALID);

    ImsServiceType imsSrvType = ImsServiceType::TYPE_VOICE;
    ImsRegInfo info;
    EXPECT_EQ(coreServiceProxy.GetImsRegStatus(INVALID_SLOTID, imsSrvType, info), TELEPHONY_ERR_SLOTID_INVALID);

    sptr<ImsRegInfoCallback> callback = nullptr;
    EXPECT_EQ(coreServiceProxy.RegisterImsRegInfoCallback(INVALID_SLOTID, imsSrvType, callback),
        TELEPHONY_ERR_ARGUMENT_NULL);
    EXPECT_EQ(coreServiceProxy.UnregisterImsRegInfoCallback(INVALID_SLOTID, imsSrvType), TELEPHONY_ERR_SLOTID_INVALID);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_001, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    std::shared_ptr<AppExecFwk::EventHandler> handler;

    mInner.networkSearchManager_ = networkSearchManager;
    EXPECT_EQ(mInner.RegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_PS_CONNECTION_ATTACHED, nullptr),
        TELEPHONY_SUCCESS);
    EXPECT_EQ(mInner.UnRegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_EMERGENCY_STATE_CLOSE),
        TELEPHONY_SUCCESS);

    mInner.simManager_ = simManager;
    EXPECT_EQ(mInner.RegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_SIM_STATE_CHANGE, nullptr),
        TELEPHONY_SUCCESS);
    EXPECT_EQ(mInner.UnRegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_SIM_RECORDS_LOADED),
        TELEPHONY_SUCCESS);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_002, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);

    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    sptr<SimAccountCallback> simAccountCallback;
    EXPECT_EQ(mInner.RegisterSimAccountCallback(-1, simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnregisterSimAccountCallback(simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.telRilManager_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::string testStr = "";
    EXPECT_EQ(mInner.SetNetworkSelectionMode(-1, -1, 0, testStr, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);

    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    EXPECT_EQ(mInner.GetClip(-1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetClip(-1, -1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetClir(-1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetClir(-1, -1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetCallWaiting(-1, -1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);

    CallTransferParam param;
    CallRestrictionParam reParam;
    EXPECT_EQ(mInner.SetCallTransferInfo(-1, param, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetCallTransferInfo(-1, -1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetCallWaiting(-1, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetCallRestriction(-1, testStr, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetCallRestriction(-1, reParam, response), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_003, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    EXPECT_EQ(mInner.SetBarringPassword(-1, "", "", "", response), TELEPHONY_ERR_LOCAL_PTR_NULL);

    int32_t testTech = 0;
    mInner.networkSearchManager_ = networkSearchManager;
    EXPECT_EQ(mInner.GetPsRadioTech(-1, testTech), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetCsRadioTech(-1, testTech), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetPsRegState(-1), TELEPHONY_ERROR);
    EXPECT_EQ(mInner.GetCsRegState(-1), TELEPHONY_ERROR);
    EXPECT_EQ(mInner.GetPsRoamingState(-1), TELEPHONY_ERROR);

    sptr<INetworkSearchCallback> callback = nullptr;
    networkSearchManager->eventSender_ = nullptr;
    mInner.networkSearchManager_ = networkSearchManager;
    std::vector<sptr<SignalInformation>> signals;

    EXPECT_EQ(mInner.GetSignalInfoList(-1, signals), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetOperatorNumeric(-1), u"");

    std::u16string testU16Str = u"";
    EXPECT_EQ(mInner.GetOperatorName(-1, testU16Str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(mInner.SetRadioState(-1, true, 0, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetRadioState(-1), ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE);
    EXPECT_EQ(mInner.GetRadioState(-1, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetIsoCountryCodeForNetwork(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetImei(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetImeiSv(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetMeid(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetUniqueDeviceId(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetPhoneType(-1), PhoneType::PHONE_TYPE_IS_NONE);
    EXPECT_EQ(mInner.GetCellLocation(-1), nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_004, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    networkSearchManager->eventSender_ = nullptr;
    mInner.networkSearchManager_ = networkSearchManager;
    sptr<INetworkSearchCallback> callback = nullptr;
    std::vector<sptr<CellInformation>> cellInfoList;

    EXPECT_EQ(mInner.GetNetworkSearchInformation(-1, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetNetworkSelectionMode(-1, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetCellInfoList(-1, cellInfoList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SendUpdateCellLocationRequest(-1), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetPreferredNetwork(-1, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);

    networkSearchManager->simManager_ = nullptr;
    mInner.networkSearchManager_ = networkSearchManager;
    EXPECT_EQ(mInner.SetPreferredNetwork(-1, -1, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_FALSE(mInner.IsNrSupported(-1));
    mInner.DcPhysicalLinkActiveUpdate(-1, true);
    EXPECT_EQ(mInner.NotifyCallStatusToNetworkSearch(-1, -1), TELEPHONY_ERR_LOCAL_PTR_NULL);

    NrMode mode = NrMode::NR_MODE_UNKNOWN;
    EXPECT_EQ(mInner.GetNrOptionMode(-1, mode), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetFrequencyType(-1), FrequencyType::FREQ_TYPE_UNKNOWN);
    EXPECT_EQ(mInner.GetNrState(-1), NrState::NR_STATE_NOT_SUPPORT);

    ImsRegInfo info;
    EXPECT_EQ(mInner.GetImsRegStatus(-1, ImsServiceType::TYPE_VOICE, info), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UpdateRadioOn(-1), TELEPHONY_ERROR);

    int32_t networkMode = static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA);
    EXPECT_FALSE(mInner.SetPreferredNetwork(-1, networkMode));
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_005, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.simManager_ = simManager;
    EXPECT_EQ(mInner.ObtainSpnCondition(-1, false, ""), TELEPHONY_ERROR);

    std::u16string testU16Str = u"";
    EXPECT_EQ(mInner.GetSimSpn(-1, testU16Str), TELEPHONY_ERR_NO_SIM_CARD);
    EXPECT_EQ(mInner.SetVoiceMailInfo(-1, testU16Str, testU16Str), TELEPHONY_ERR_NO_SIM_CARD);

    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    EXPECT_EQ(mInner.QueryIccDiallingNumbers(-1, 0, result), TELEPHONY_ERR_LOCAL_PTR_NULL);

    std::shared_ptr<DiallingNumbersInfo> diallingNumbers = std::make_shared<DiallingNumbersInfo>();
    EXPECT_EQ(mInner.AddIccDiallingNumbers(-1, 0, diallingNumbers), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.DelIccDiallingNumbers(-1, 0, diallingNumbers), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UpdateIccDiallingNumbers(-1, 0, diallingNumbers), TELEPHONY_ERR_LOCAL_PTR_NULL);

    std::string testStr = "";
    EXPECT_EQ(mInner.AddSmsToIcc(-1, 0, testStr, testStr), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(mInner.UpdateSmsIcc(-1, 0, 0, testStr, testStr), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ((mInner.ObtainAllSmsOfIcc(-1)).size(), 0);
    EXPECT_EQ(mInner.DelSmsIcc(-1, 0), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_FALSE(mInner.IsSimActive(-1));
    EXPECT_EQ(mInner.SetActiveSim(-1, 0), TELEPHONY_ERR_LOCAL_PTR_NULL);

    IccAccountInfo info;
    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    EXPECT_EQ(mInner.GetSimAccountInfo(-1, info), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetDefaultVoiceSlotId(INVALID_DEFAULT_SLOTID), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(mInner.SetDefaultSmsSlotId(INVALID_DEFAULT_SLOTID), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(mInner.SetDefaultCellularDataSlotId(-1), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(mInner.SetPrimarySlotId(-1), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(mInner.SetShowNumber(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_006, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    std::u16string testU16Str = u"";
    mInner.simManager_ = nullptr;
    EXPECT_EQ(mInner.SetShowNumber(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);

    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    EXPECT_EQ(mInner.SetShowName(-1, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);

    simManager->slotCount_ = 1;
    mInner.simManager_ = simManager;
    EXPECT_EQ(mInner.GetDefaultVoiceSlotId(), DEFAULT_SIM_SLOT_ID);

    int32_t simId = 0;
    EXPECT_EQ(mInner.GetDefaultVoiceSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmsSlotId(), DEFAULT_SIM_SLOT_ID);
    EXPECT_EQ(mInner.GetDefaultSmsSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultCellularDataSlotId(), DEFAULT_SIM_SLOT_ID);
    EXPECT_EQ(mInner.GetDefaultCellularDataSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);

    int32_t dsdsMode = 0;
    EXPECT_EQ(mInner.GetDsdsMode(dsdsMode), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(static_cast<DsdsMode>(dsdsMode), DsdsMode::DSDS_MODE_V2);
    EXPECT_EQ(mInner.SetDsdsMode(dsdsMode), TELEPHONY_ERR_SUCCESS);

    int32_t slotId = -1;
    EXPECT_EQ(mInner.GetPrimarySlotId(slotId), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(slotId, 0);

    EXPECT_EQ(mInner.GetShowNumber(slotId, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetShowName(slotId, testU16Str), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_007, Function | MediumTest | Level1)
{
    ResourceUtils resourceUtils;
    resourceUtils.beSourceAdd_ = false;
    resourceUtils.resourceManager_ =
        std::unique_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager());
    ASSERT_NE(resourceUtils.resourceManager_, nullptr);
    resourceUtils.beSourceAdd_ = true;
    EXPECT_TRUE(resourceUtils.Init());

    int reason = 1;
    std::string value = "test";
    bool temp = resourceUtils.GetCallFailedMessageName(reason, value);
    EXPECT_TRUE(temp);
    temp = resourceUtils.GetIntegerValueByName(value, reason);
    EXPECT_FALSE(temp);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_008, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    sptr<SimAccountCallback> simAccountCallback;
    EXPECT_EQ(mInner.RegisterSimAccountCallback(-1, simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnregisterSimAccountCallback(simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.telRilManager_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::string testStr = "";
    EXPECT_EQ(mInner.SetNetworkSelectionMode(-1, -1, 0, testStr, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);

    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    mInner.SetNetworkSelectionMode(-1, -1, 0, testStr, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_009, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    sptr<SimAccountCallback> simAccountCallback;
    EXPECT_EQ(mInner.RegisterSimAccountCallback(-1, simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnregisterSimAccountCallback(simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.telRilManager_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler;

    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    mInner.GetNetworkSelectionMode(-1, 0, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0010, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    sptr<SimAccountCallback> simAccountCallback;
    EXPECT_EQ(mInner.RegisterSimAccountCallback(-1, simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnregisterSimAccountCallback(simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.telRilManager_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    DtmfParam dtmfParam;

    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    mInner.GetRadioState(-1, 0, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    mInner.ShutDown(-1, 0, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    mInner.Dial(1, 1, "test", 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    mInner.SendDTMF(1, 1, dtmfParam, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    mInner.SendDTMF(1, 1, 'a', 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0011, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    simManager->multiSimMonitor_ = nullptr;
    mInner.simManager_ = simManager;
    sptr<SimAccountCallback> simAccountCallback;
    EXPECT_EQ(mInner.RegisterSimAccountCallback(-1, simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnregisterSimAccountCallback(simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.telRilManager_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler;

    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.Answer(-1, 0, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.Hangup(-1, 0, 1, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.GetCallList(-1, 0, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.Reject(-1, 0, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.HoldCall(-1, 0, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.UnHoldCall(-1, 0, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.SwitchCall(-1, 0, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.CombineConference(-1, 0, -1, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.SetActiveSim(-1, 0), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0012, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);

    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    mInner.simManager_ = nullptr;
    EXPECT_EQ(mInner.simManager_, nullptr);
    int32_t simId = -1;
    EXPECT_EQ(mInner.SetActiveSim(-1, 0), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultVoiceSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmsSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.simManager_ = simManager;
    std::u16string u16str = u"test";
    mInner.GetSimOperatorNumeric(1, u16str);
    EXPECT_NE(mInner.simManager_, nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0013, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    mInner.isInitExtraObj_ = true;
    EXPECT_EQ(mInner.InitExtraModule(1), TELEPHONY_SUCCESS);
    mInner.InitExtraModule(1);
    EXPECT_FALSE(SIM_SLOT_COUNT != DUAL_SLOT_COUNT);
    mInner.telRilManager_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::string testStr = "";
    EXPECT_EQ(mInner.SetNetworkSelectionMode(-1, -1, 0, testStr, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    AppExecFwk::InnerEvent::Pointer response(nullptr, nullptr);
    mInner.telRilManager_ = telRilManager;
    mInner.SetNetworkSelectionMode(-1, -1, 0, testStr, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(mInner.simManager_, nullptr);
    mInner.InitExtraModule(1);
    int32_t simId = -1;
    EXPECT_EQ(mInner.SetActiveSim(-1, 0), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultVoiceSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmsSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.simManager_ = simManager;
    std::u16string u16str = u"test";
    mInner.GetSimOperatorNumeric(1, u16str);
    mInner.InitExtraModule(1);
    EXPECT_NE(mInner.simManager_, nullptr);
    mInner.networkSearchManager_ = networkSearchManager;
    mInner.InitExtraModule(1);
    EXPECT_NE(mInner.networkSearchManager_, nullptr);
    EXPECT_NE(mInner.simManager_, nullptr);
    EXPECT_NE(mInner.telRilManager_, nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0014, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    mInner.simManager_ = nullptr;
    EXPECT_EQ(mInner.simManager_, nullptr);
    int32_t simId = -1;
    EXPECT_EQ(mInner.SetActiveSim(-1, 0), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultVoiceSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmsSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.telRilManager_ = telRilManager;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::string str = "test";
    std::vector<EmergencyCall> eccVec;
    auto core = mInner.SetUssd(1, 1, str, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core1 = mInner.CloseUnFinishedUssd(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core1, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core2 = mInner.GetUssd(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core2, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core3 = mInner.GetMute(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core3, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core4 = mInner.SetMute(1, 1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core4, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core5 = mInner.GetEmergencyCallList(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core5, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core6 = mInner.GetCallFailReason(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core6, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0015, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    mInner.networkSearchManager_ = networkSearchManager;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    mInner.simManager_ = nullptr;
    EXPECT_EQ(mInner.simManager_, nullptr);
    int32_t simId = -1;
    EXPECT_EQ(mInner.SetActiveSim(-1, 0), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultVoiceSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmsSimId(simId), TELEPHONY_ERR_LOCAL_PTR_NULL);
    mInner.telRilManager_ = telRilManager;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::string str = "test";
    std::vector<EmergencyCall> eccVec;
    auto core = mInner.SetCallPreferenceMode(1, 1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core1 = mInner.GetCallPreferenceMode(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core1, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core2 = mInner.SetPreferredNetworkPara(1, 1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core2, TELEPHONY_ERR_LOCAL_PTR_NULL);
    auto core3 = mInner.GetPreferredNetworkPara(1, 1, handler);
    EXPECT_NE(mInner.telRilManager_, nullptr);
    EXPECT_EQ(core3, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0016, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);

    mInner.simManager_ = simManager;
    mInner.UpdateImsCapFromChip(0, {0, 0, 0, 0});
    EXPECT_NE(mInner.simManager_, nullptr);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0017, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;

    mInner.simManager_ = nullptr;
    mInner.UpdateImsCapFromChip(0, {0, 0, 0, 0});
    EXPECT_EQ(mInner.simManager_, nullptr);
}
#ifdef CORE_SERVICE_SUPPORT_ESIM
HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0018, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::u16string resultstr;
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    EuiccInfo eUiccInfo;
    ResponseEsimResult responseResult;
    CancelReason cancelReason = CancelReason::CANCEL_REASON_END_USER_REJECTION;
    ResultCode enumResult;
    int32_t portIndex = 0;
    int32_t slotId = -1;
    mInner.simManager_ = nullptr;
    const std::u16string iccId = u"122323123123122312";
    EsimApduData apduData {};
    const std::u16string aid = u"12232312";
    const std::u16string nickname = u"test profile";
    EuiccProfile eUiccProfile;
    std::u16string transactionId = u"12232312";
    
    EXPECT_EQ(mInner.simManager_, nullptr);
    EXPECT_EQ(mInner.GetEid(slotId, resultstr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetSmdsAddress(slotId, portIndex, resultstr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmdpAddress(slotId, resultstr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    
    EXPECT_EQ(mInner.GetEuiccProfileInfoList(slotId, euiccProfileInfoList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccInfo(slotId, eUiccInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccChallenge(slotId, portIndex, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.CancelSession(
        slotId, transactionId, cancelReason, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.DisableProfile(
        slotId, portIndex, iccId, true, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SendApduData(
        slotId, aid, apduData, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_FALSE(mInner.IsSupported(slotId));
    EXPECT_EQ(mInner.SetProfileNickname(
        slotId, iccId, nickname, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetProfile(
        slotId,  portIndex, iccId, eUiccProfile), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0019, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::u16string resultstr;
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    EuiccInfo eUiccInfo;
    ResponseEsimResult responseResult;
    CancelReason cancelReason = CancelReason::CANCEL_REASON_END_USER_REJECTION;
    ResultCode enumResult;
    int32_t portIndex = 0;
    int32_t slotId = -1;
    mInner.simManager_ = nullptr;
    const std::u16string iccId = u"122323123123122312";
    EsimApduData apduData {};
    const std::u16string aid = u"12232312";
    const std::u16string nickname = u"test profile";
    EuiccProfile eUiccProfile;
    std::u16string transactionId = u"12232312";
    EXPECT_EQ(mInner.simManager_, nullptr);
    EXPECT_EQ(mInner.GetEid(slotId, resultstr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetSmdsAddress(slotId, portIndex, resultstr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetDefaultSmdpAddress(slotId, resultstr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccProfileInfoList(slotId, euiccProfileInfoList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccInfo(slotId, eUiccInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccChallenge(slotId, portIndex, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.CancelSession(
        slotId, transactionId, cancelReason, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.DisableProfile(
        slotId, portIndex, iccId, true, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SendApduData(
        slotId, aid, apduData, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_FALSE(mInner.IsSupported(slotId));
    EXPECT_EQ(mInner.SetProfileNickname(
        slotId, iccId, nickname, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetProfile(
        slotId,  portIndex, iccId, eUiccProfile), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0020, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::u16string resultstr;
    AuthenticateConfigInfo authenticateConfigInfo;
    EuiccInfo eUiccInfo;
    ResponseEsimResult responseResult;
    ResponseEsimBppResult responseBppResult;
    ResultCode enumResult;
    int32_t portIndex = 0;
    int32_t slotId = -1;
    mInner.simManager_ = nullptr;
    Event events = Event::EVENT_ALL;
    EuiccNotification notification;
    EuiccNotificationList notificationList;
    const std::u16string iccId = u"122323123123122312";
    const std::u16string nickname = u"test profile";
    DownLoadConfigInfo downLoadConfigInfo;
    const std::u16string defaultSmdpAddress = u"xxx.xxx.xxx";
    const std::u16string boundProfilePackage = u"12232312";
    int32_t seqNumber = 122356;
    EuiccInfo2 euiccInfo2;
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    bool forceDisableProfile = true;
    EXPECT_EQ(mInner.simManager_, nullptr);
    EXPECT_EQ(mInner.GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.ResetMemory(slotId, resetOption, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetDefaultSmdpAddress(slotId, defaultSmdpAddress, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.PrepareDownload(slotId, downLoadConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.LoadBoundProfilePackage(slotId,  portIndex,
        boundProfilePackage, responseBppResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.ListNotifications(
        slotId, portIndex, events, notificationList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RetrieveNotificationList(
        slotId, portIndex, events, notificationList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RemoveNotificationFromList(
        slotId, portIndex, seqNumber, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccInfo2(slotId, portIndex, euiccInfo2), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.DeleteProfile(slotId, iccId, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SwitchToProfile(slotId, portIndex, iccId,
        forceDisableProfile, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.AuthenticateServer(slotId, authenticateConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.AuthenticateServer(slotId, authenticateConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RetrieveNotification(slotId, portIndex, seqNumber, notification), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceNativeBranchTest, Telephony_CoreManagerInner_0021, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::u16string resultstr;
    AuthenticateConfigInfo authenticateConfigInfo;
    EuiccInfo eUiccInfo;
    ResponseEsimResult responseResult;
    ResponseEsimBppResult responseBppResult;
    ResultCode enumResult;
    int32_t portIndex = 0;
    int32_t slotId = -1;
    mInner.simManager_ = simManager;
    Event events = Event::EVENT_ALL;
    EuiccNotification notification;
    EuiccNotificationList notificationList;
    const std::u16string iccId = u"122323123123122312";
    const std::u16string nickname = u"test profile";
    DownLoadConfigInfo downLoadConfigInfo;
    const std::u16string defaultSmdpAddress = u"xxx.xxx.xxx";
    const std::u16string boundProfilePackage = u"12232312";
    int32_t seqNumber = 122356;
    EuiccInfo2 euiccInfo2;
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    bool forceDisableProfile = true;
    EXPECT_EQ(mInner.simManager_, nullptr);
    EXPECT_EQ(mInner.GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.ResetMemory(slotId, resetOption, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SetDefaultSmdpAddress(slotId, defaultSmdpAddress, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.PrepareDownload(slotId, downLoadConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.LoadBoundProfilePackage(slotId,  portIndex,
        boundProfilePackage, responseBppResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.ListNotifications(slotId, portIndex, events, notificationList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RetrieveNotificationList(
        slotId, portIndex, events, notificationList), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RemoveNotificationFromList(
        slotId, portIndex, seqNumber, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetEuiccInfo2(slotId, portIndex, euiccInfo2), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.DeleteProfile(slotId, iccId, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.SwitchToProfile(slotId, portIndex, iccId,
        forceDisableProfile, enumResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.AuthenticateServer(slotId, authenticateConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.AuthenticateServer(slotId, authenticateConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RetrieveNotification(slotId, portIndex, seqNumber, notification), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
#endif

} // namespace Telephony
} // namespace OHOS
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "core_service_common_event_hub.h"
#include "core_service_common_event_callback.h"
#include "common_event_support.h"
#include "common_event_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;

class CoreServiceCommonEventHubTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp() override
    {}
    void TearDown() override
    {}

private:
    void EmitCommonEvent(const std::shared_ptr<CoreServiceCommonEventHub> &hub, const std::string &action)
    {
        AAFwk::Want want;
        want.SetAction(action);
        EventFwk::CommonEventData data;
        data.SetWant(want);
        hub->OnReceiveEvent(data);
    }
};

namespace {
class MockCoreServiceCommonEventCallback : public CoreServiceCommonEventCallback {
public:
    MOCK_METHOD(void, OnRadioStateChange, (int32_t slotId, int32_t state), (override));
    MOCK_METHOD(void, OnDataShareReady, (), (override));
    MOCK_METHOD(void, OnUserSwitched, (int32_t userId), (override));
    MOCK_METHOD(
        void, OnSimStateChanged, (int32_t slotId, int32_t simeType, int32_t simState, int32_t lockReason), (override));
    MOCK_METHOD(void, OnBluetoothRemoteDeviceNameUpdate, (const std::string &deviceAddr, const std::string &remoteName),
        (override));
    MOCK_METHOD(void, OnShutdown, (), (override));
    MOCK_METHOD(void, OnScreenUnlocked, (), (override));
    MOCK_METHOD(void, OnSpecialCode, (const std::string &specialCode), (override));
    MOCK_METHOD(void, OnOperatorConfigChanged, (int32_t slotId, int32_t state), (override));
    MOCK_METHOD(void, OnNetworkStateChanged, (int32_t slotId, const std::string &networkState), (override));
    MOCK_METHOD(void, OnCallStateChanged, (int32_t slotId, int32_t state), (override));
    MOCK_METHOD(void, OnSimCardDefaultDataSubscriptionChanged, (int32_t simId), (override));
    MOCK_METHOD(void, OnScreenOn, (), (override));
    MOCK_METHOD(void, OnScreenOff, (), (override));
    MOCK_METHOD(void, OnConnectivityChange, (int32_t netType, int32_t netConnState), (override));
    MOCK_METHOD(void, OnPowerSaveModeChanged, (uint32_t powerMode), (override));
    MOCK_METHOD(void, OnCharging, (uint32_t chargeType), (override));
    MOCK_METHOD(void, OnDischarging, (uint32_t chargeType), (override));
    MOCK_METHOD(void, OnLocaleChanged, (), (override));
    MOCK_METHOD(void, OnAirplaneModeChanged, (bool isAirplaneMode), (override));
    MOCK_METHOD(void, OnSetPrimarySlotStatus, (bool setDone), (override));
    MOCK_METHOD(void, OnSecondMounted, (), (override));
    MOCK_METHOD(void, OnBundleScanFinished, (), (override));
};

std::vector<TelCommonEvent> GetAllEvents()
{
    return {TelCommonEvent::UNKNOWN_ENENT,
        TelCommonEvent::RADIO_STATE_CHANGE,
        TelCommonEvent::DATA_SHARE_READY,
        TelCommonEvent::USER_SWITCHED,
        TelCommonEvent::SIM_STATE_CHANGED,
        TelCommonEvent::BLUETOOTH_REMOTEDEVICE_NAME_UPDATE,
        TelCommonEvent::SHUTDOWN,
        TelCommonEvent::SCREEN_UNLOCKED,
        TelCommonEvent::SPECIAL_CODE,
        TelCommonEvent::OPERATOR_CONFIG_CHANGED,
        TelCommonEvent::NETWORK_STATE_CHANGED,
        TelCommonEvent::CALL_STATE_CHANGED,
        TelCommonEvent::SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
        TelCommonEvent::SCREEN_ON,
        TelCommonEvent::SCREEN_OFF,
        TelCommonEvent::CONNECTIVITY_CHANGE,
        TelCommonEvent::POWER_SAVE_MODE_CHANGED,
        TelCommonEvent::CHARGING,
        TelCommonEvent::DISCHARGING,
        TelCommonEvent::LOCALE_CHANGED,
        TelCommonEvent::AIRPLANE_MODE_CHANGED,
        TelCommonEvent::SET_PRIMARY_SLOT_STATUS,
        TelCommonEvent::SECOND_MOUNTED,
        TelCommonEvent::BUNDLE_SCAN_FINISHED};
}
}  // namespace

HWTEST_F(CoreServiceCommonEventHubTest, RegisterCallback_001, Function | MediumTest | Level1)
{
    auto coreServiceCommonEventHub = std::make_shared<CoreServiceCommonEventHub>();
    coreServiceCommonEventHub->Init();
    auto callback = std::make_shared<MockCoreServiceCommonEventCallback>();
    auto callback2 = std::make_shared<MockCoreServiceCommonEventCallback>();

    coreServiceCommonEventHub->RegisterCallback(nullptr, GetAllEvents());
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() == 0);

    coreServiceCommonEventHub->RegisterCallback(callback, GetAllEvents());
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() > 0);

    coreServiceCommonEventHub->RegisterCallback(callback2, GetAllEvents());
    coreServiceCommonEventHub->UnregisterCallback(nullptr);
    coreServiceCommonEventHub->UnregisterCallback(callback);
    coreServiceCommonEventHub->UnregisterCallback(callback);
    coreServiceCommonEventHub->UnregisterCallback(callback2);
    coreServiceCommonEventHub->UnregisterCallback(callback2);
    coreServiceCommonEventHub->Unsubscribe(TelCommonEvent::UNKNOWN_ENENT);
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() == 0);
}

HWTEST_F(CoreServiceCommonEventHubTest, RegisterCallback_002, Function | MediumTest | Level1)
{
    auto coreServiceCommonEventHub = std::make_shared<CoreServiceCommonEventHub>();
    coreServiceCommonEventHub->Init();
    auto callback = std::make_shared<MockCoreServiceCommonEventCallback>();
    auto mockCommonEventManager = std::make_shared<EventFwk::MockCommonEventManager>();
    EventFwk::CommonEventManager::SetMock(mockCommonEventManager);
    EXPECT_CALL(*mockCommonEventManager, SubscribeCommonEvent(_)).WillRepeatedly(Return(false));
    coreServiceCommonEventHub->RegisterCallback(callback, GetAllEvents());
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() == 0);
    EventFwk::CommonEventManager::SetMock(nullptr);
}

HWTEST_F(CoreServiceCommonEventHubTest, UnregisterCallback_001, Function | MediumTest | Level1)
{
    auto coreServiceCommonEventHub = std::make_shared<CoreServiceCommonEventHub>();
    coreServiceCommonEventHub->Init();
    auto callback = std::make_shared<MockCoreServiceCommonEventCallback>();

    coreServiceCommonEventHub->RegisterCallback(callback, GetAllEvents());
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() > 0);

    auto mockCommonEventManager = std::make_shared<EventFwk::MockCommonEventManager>();
    EventFwk::CommonEventManager::SetMock(mockCommonEventManager);
    EXPECT_CALL(*mockCommonEventManager, UnSubscribeCommonEvent(_)).WillRepeatedly(Return(false));
    coreServiceCommonEventHub->UnregisterCallback(callback);
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() == 0);
    EventFwk::CommonEventManager::SetMock(nullptr);
}

HWTEST_F(CoreServiceCommonEventHubTest, Subscriber_OnReceiveEvent_001, Function | MediumTest | Level1)
{
    auto coreServiceCommonEventHub = std::make_shared<CoreServiceCommonEventHub>();
    coreServiceCommonEventHub->Init();
    auto callback = std::make_shared<MockCoreServiceCommonEventCallback>();
    coreServiceCommonEventHub->RegisterCallback(callback, GetAllEvents());
    EXPECT_TRUE(coreServiceCommonEventHub->callbacks_.size() > 0);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RADIO_STATE_CHANGE);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    auto subscribers = coreServiceCommonEventHub->subscribers_;
    for (auto &subscriber : subscribers) {
        subscriber.second->OnReceiveEvent(data);
    }
    coreServiceCommonEventHub = nullptr;
    for (auto &subscriber : subscribers) {
        subscriber.second->OnReceiveEvent(data);
    }
    Mock::VerifyAndClear(callback.get());
}

HWTEST_F(CoreServiceCommonEventHubTest, OnReceiveEvent_UnknownEvent_001, Function | MediumTest | Level1)
{
    auto hub = std::make_shared<CoreServiceCommonEventHub>();
    hub->Init();
    auto callback = std::make_shared<MockCoreServiceCommonEventCallback>();
    hub->RegisterCallback(callback, GetAllEvents());

    EXPECT_CALL(*callback, OnRadioStateChange).Times(0);
    EmitCommonEvent(hub, "UNKNOWN_EVENT");
    Mock::VerifyAndClear(callback.get());
}

HWTEST_F(CoreServiceCommonEventHubTest, OnReceiveEvent_NullptrFunc_001, Function | MediumTest | Level1)
{
    auto hub = std::make_shared<CoreServiceCommonEventHub>();
    hub->Init();
    auto callback = std::make_shared<MockCoreServiceCommonEventCallback>();
    hub->RegisterCallback(callback, GetAllEvents());

    EXPECT_CALL(*callback, OnRadioStateChange).Times(0);
    hub->actionHandlersMap_[TelCommonEvent::UNKNOWN_ENENT] = nullptr;
    EmitCommonEvent(hub, "UNKNOWN_EVENT");
    Mock::VerifyAndClear(callback.get());
}

#define TEST_EVENT_DYNAMIC(eventName, eventConst)                               \
    HWTEST_F(CoreServiceCommonEventHubTest,                                     \
        OnReceiveEvent_##eventName##_DynamicRegister_001,                       \
        Function | MediumTest | Level1)                                         \
    {                                                                           \
        auto hub = std::make_shared<CoreServiceCommonEventHub>();               \
        hub->Init();                                                            \
        auto callback = std::make_shared<MockCoreServiceCommonEventCallback>(); \
                                                                                \
        EXPECT_CALL(*callback, On##eventName).Times(0);                         \
        EmitCommonEvent(hub, EventFwk::CommonEventSupport::eventConst);         \
                                                                                \
        hub->RegisterCallback(callback, GetAllEvents());                        \
                                                                                \
        EXPECT_CALL(*callback, On##eventName).Times(1);                         \
        EmitCommonEvent(hub, EventFwk::CommonEventSupport::eventConst);         \
        Mock::VerifyAndClear(callback.get());                                   \
    }

TEST_EVENT_DYNAMIC(RadioStateChange, COMMON_EVENT_RADIO_STATE_CHANGE);
TEST_EVENT_DYNAMIC(DataShareReady, COMMON_EVENT_DATA_SHARE_READY);
TEST_EVENT_DYNAMIC(UserSwitched, COMMON_EVENT_USER_SWITCHED);
TEST_EVENT_DYNAMIC(SimStateChanged, COMMON_EVENT_SIM_STATE_CHANGED);
TEST_EVENT_DYNAMIC(BluetoothRemoteDeviceNameUpdate, COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE);
TEST_EVENT_DYNAMIC(Shutdown, COMMON_EVENT_SHUTDOWN);
TEST_EVENT_DYNAMIC(ScreenUnlocked, COMMON_EVENT_SCREEN_UNLOCKED);
TEST_EVENT_DYNAMIC(OperatorConfigChanged, COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
TEST_EVENT_DYNAMIC(NetworkStateChanged, COMMON_EVENT_NETWORK_STATE_CHANGED);
TEST_EVENT_DYNAMIC(CallStateChanged, COMMON_EVENT_CALL_STATE_CHANGED);
TEST_EVENT_DYNAMIC(SimCardDefaultDataSubscriptionChanged, COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
TEST_EVENT_DYNAMIC(ScreenOn, COMMON_EVENT_SCREEN_ON);
TEST_EVENT_DYNAMIC(ScreenOff, COMMON_EVENT_SCREEN_OFF);
TEST_EVENT_DYNAMIC(ConnectivityChange, COMMON_EVENT_CONNECTIVITY_CHANGE);
TEST_EVENT_DYNAMIC(PowerSaveModeChanged, COMMON_EVENT_POWER_SAVE_MODE_CHANGED);
TEST_EVENT_DYNAMIC(Charging, COMMON_EVENT_CHARGING);
TEST_EVENT_DYNAMIC(Discharging, COMMON_EVENT_DISCHARGING);
TEST_EVENT_DYNAMIC(LocaleChanged, COMMON_EVENT_LOCALE_CHANGED);
TEST_EVENT_DYNAMIC(AirplaneModeChanged, COMMON_EVENT_AIRPLANE_MODE_CHANGED);
TEST_EVENT_DYNAMIC(SetPrimarySlotStatus, COMMON_EVENT_SET_PRIMARY_SLOT_STATUS);
TEST_EVENT_DYNAMIC(SecondMounted, COMMON_EVENT_SECOND_MOUNTED);
TEST_EVENT_DYNAMIC(BundleScanFinished, COMMON_EVENT_BUNDLE_SCAN_FINISHED);

}  // namespace Telephony
}  // namespace OHOS
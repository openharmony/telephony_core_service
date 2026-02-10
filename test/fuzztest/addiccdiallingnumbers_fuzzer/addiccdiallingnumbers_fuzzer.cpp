/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "addiccdiallingnumbers_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "tel_ril_manager.h"
#include "sim_state_type.h"

#ifdef OHOS_BUILD_ENABLE_TELEPHONY_ESIM
#include "esim_service_stub.h"
#include "esim_service_proxy.h"
#include "if_system_ability_manager.h"
#include "singleton.h"
#include "system_ability.h"
#include "fuzzer/FuzzedDataProvider.h"
#endif

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SIZE_LIMIT = 4;
constexpr uint32_t FUCTION_SIZE = 100;
constexpr int32_t SLEEP_TIME_SECONDS = 2;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t TELEPHONY_ESIM_SERVICE_SYS_ABILITY_ID = 1003;

bool IsServiceInited()
{
    if (!g_isInited) {
        DelayedSingleton<CoreService>::GetInstance()->OnStart();
        if (DelayedSingleton<CoreService>::GetInstance()->GetServiceRunningState() ==
            static_cast<int32_t>(ServiceRunningState::STATE_RUNNING)) {
            g_isInited = true;
        }
    }
    return g_isInited;
}

#ifdef OHOS_BUILD_ENABLE_TELEPHONY_ESIM
class EsimService : public SystemAbility, public EsimServiceStub {
    DECLARE_DELAYED_SINGLETON(EsimService)
    DECLARE_SYSTEM_ABILITY(EsimService)

public:
    ErrCode GetEid(int32_t slotId, const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetOsuStatus(
        int32_t slotId,
        int32_t& osuStatus) override {return ERR_OK;};

    ErrCode StartOsu(
        int32_t slotId,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetDownloadableProfileMetadata(
        int32_t slotId,
        int32_t portIndex,
        const DownloadableProfile& profile,
        bool forceDisableProfile,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetDownloadableProfiles(
        int32_t slotId,
        int32_t portIndex,
        bool forceDisableProfile,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode DownloadProfile(
        int32_t slotId,
        const DownloadProfileConfigInfo& configInfo,
        const DownloadableProfile& profile,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetEuiccProfileInfoList(
        int32_t slotId,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetEuiccInfo(
        int32_t slotId,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode DeleteProfile(
        int32_t slotId,
        const std::string& iccId,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode SwitchToProfile(
        int32_t slotId,
        int32_t portIndex,
        const std::string& iccId,
        bool forceDisableProfile,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode SetProfileNickname(
        int32_t slotId,
        const std::string& iccId,
        const std::string& nickname,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode ResetMemory(
        int32_t slotId,
        int32_t resetOption,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode ReserveProfilesForFactoryRestore(
        int32_t slotId,
        int32_t& restoreResult) override {return ERR_OK;};

    ErrCode SetDefaultSmdpAddress(
        int32_t slotId,
        const std::string& defaultSmdpAddress,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetDefaultSmdpAddress(
        int32_t slotId,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode CancelSession(
        int32_t slotId,
        const std::string& transactionId,
        int32_t cancelReason,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode IsSupported(
        int32_t slotId) override {return ERR_OK;};

    ErrCode AddProfile(
        int32_t slotId,
        const DownloadableProfile& profile) override {return ERR_OK;};

    ErrCode GetSupportedPkids(
        int32_t slotId,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetContractInfo(
        int32_t slotId,
        const ContractRequestData& contractRequestData,
        const sptr<IEsimServiceCallback>& listener) override {return ERR_OK;};

    ErrCode GetEsimFreeStorage(
        int32_t& freeStorage) override {return ERR_OK;};
};

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

EsimService::EsimService() : SystemAbility(TELEPHONY_ESIM_SERVICE_SYS_ABILITY_ID, true) {}

EsimService::~EsimService() {}

void OnRemoteRequestEsim(const uint8_t *data, size_t size)
{
    if (size < SIZE_LIMIT) {
        return;
    }

    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(EsimServiceStub::GetDescriptor())) {
        return;
    }
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);

    uint32_t code = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                    (static_cast<uint32_t>(data[2]) << 8) | (static_cast<uint32_t>(data[3])) % FUCTION_SIZE;

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<EsimService>::GetInstance()->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void EsimServiceProxyTest(const uint8_t *data, size_t size)
{
    if (size < SIZE_LIMIT) {
        return;
    }
    
    sptr<TestIRemoteObject> remote = new (std::nothrow) TestIRemoteObject();
    EsimServiceProxy esimServiceProxy(remote);
    std::shared_ptr<FuzzedDataProvider> provider = std::make_shared<FuzzedDataProvider>(data, size);
    
    sptr<IEsimServiceCallback> listener = nullptr;
    DownloadableProfile profile;
    DownloadProfileConfigInfo info;
    int32_t slotId = provider->ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t inputData = provider->ConsumeIntegral<int32_t>();
    std::string str = "";
    int32_t result;
    std::string strResult;
    ContractRequestData reqData;
    
    esimServiceProxy.GetEid(slotId, listener);
    esimServiceProxy.GetOsuStatus(slotId, result);
    esimServiceProxy.StartOsu(slotId, listener);
    esimServiceProxy.GetDownloadableProfileMetadata(slotId, inputData, profile, true, listener);
    esimServiceProxy.GetDownloadableProfiles(slotId, inputData, true, listener);
    esimServiceProxy.DownloadProfile(slotId, info, profile, listener);
    esimServiceProxy.GetEuiccProfileInfoList(slotId, listener);
    esimServiceProxy.GetEuiccInfo(slotId, listener);
    esimServiceProxy.DeleteProfile(slotId, str, listener);
    esimServiceProxy.SwitchToProfile(slotId, inputData, str, true, listener);
    esimServiceProxy.SetProfileNickname(slotId, str, strResult, listener);
    esimServiceProxy.ResetMemory(slotId, inputData, listener);
    esimServiceProxy.ReserveProfilesForFactoryRestore(slotId, result);
    esimServiceProxy.SetDefaultSmdpAddress(slotId, strResult, listener);
    esimServiceProxy.GetDefaultSmdpAddress(slotId, listener);
    esimServiceProxy.CancelSession(slotId, strResult, inputData, listener);
    esimServiceProxy.IsSupported(slotId);
    esimServiceProxy.AddProfile(slotId, profile);
    esimServiceProxy.GetSupportedPkids(slotId, listener);
    esimServiceProxy.GetContractInfo(slotId, reqData, listener);
    esimServiceProxy.GetEsimFreeStorage(result);
}
#endif

void OnRemoteRequest(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    if (size < SIZE_LIMIT) {
        return;
    }

    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);

    uint32_t code = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                    (static_cast<uint32_t>(data[2]) << 8) | (static_cast<uint32_t>(data[3])) % FUCTION_SIZE;

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OnRemoteRequest(data, size);
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_ESIM
    OnRemoteRequestEsim(data, size);
    EsimServiceProxyTest(data, size);
#endif
    sleep(SLEEP_TIME_SECONDS);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

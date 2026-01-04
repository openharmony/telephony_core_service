/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sendsmsmoremode_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "event_runner.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "system_ability_definition.h"
#include "tel_ril_call.h"
#include "tel_ril_data.h"
#include "tel_ril_sim.h"
#include "tel_ril_sms.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t BOOL_NUM = 2;
bool g_flag = false;

void SendSmsMoreMode(FuzzedDataProvider& provider)
{
    int32_t slotId = provider.ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t success = provider.ConsumeIntegral<int32_t>() % BOOL_NUM;
    int32_t offset = 0;
    int32_t responseId = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t status = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t state = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t gsmIndex = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t cdmaIndex = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t tosca = provider.ConsumeIntegral<int32_t>() + offset;
    uint8_t hexChar = provider.ConsumeIntegral<uint8_t>();
    std::string smscPdu = provider.ConsumeRandomLengthString();
    std::string pdu = provider.ConsumeRandomLengthString();
    std::string address = provider.ConsumeRandomLengthString();
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(provider.ConsumeIntegral<uint8_t>());
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(responseId, object);
    auto rilInterface_ = HDI::Ril::V1_5::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSms = std::make_shared<TelRilSms>(slotId, rilInterface_, observerHandler, nullptr);
    telRilSms->SendSmsMoreMode(smscPdu, pdu, response);
    telRilSms->AddSimMessage(status, smscPdu, pdu, response);
    telRilSms->SendCdmaSms(pdu, response);
    telRilSms->DelSimMessage(gsmIndex, response);
    telRilSms->UpdateSimMessage(gsmIndex, state, smscPdu, pdu, response);
    telRilSms->SetSmscAddr(tosca, address, response);
    telRilSms->GetSmscAddr(response);
    telRilSms->GetCdmaCBConfig(response);
    telRilSms->GetCBConfig(response);
    telRilSms->DelCdmaSimMessage(cdmaIndex, response);
    telRilSms->UpdateCdmaSimMessage(cdmaIndex, state, pdu, response);
    telRilSms->ConvertHexCharToInt(hexChar);
    telRilSms->SendSmsAck(success, state, response);
    telRilSms->AddCdmaSimMessage(status, pdu, response);
}

void GetCallList(FuzzedDataProvider& provider)
{
    int32_t slotId = provider.ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t offset = 0;
    int32_t resultId = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t index = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t switchOn = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t switchOff = provider.ConsumeIntegral<int32_t>() + offset;
    std::string address = provider.ConsumeRandomLengthString();
    std::string fac = provider.ConsumeRandomLengthString();
    std::string password = provider.ConsumeRandomLengthString();
    std::string sDTMFCode = provider.ConsumeRandomLengthString();
    std::string oldPassword = provider.ConsumeRandomLengthString();
    std::string newPassword = provider.ConsumeRandomLengthString();
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(provider.ConsumeIntegral<uint8_t>());
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(resultId, object);
    auto rilInterface_ = HDI::Ril::V1_5::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(slotId, rilInterface_, observerHandler, nullptr);
    telRilCall->GetCallList(result);
    telRilCall->Dial(address, index, result);
    telRilCall->Reject(result);
    telRilCall->Hangup(index, result);
    telRilCall->SeparateConference(index, index, result);
    telRilCall->CombineConference(index, result);
    telRilCall->CallSupplement(index, result);
    telRilCall->GetCallWaiting(result);
    telRilCall->SetCallWaiting(index, result);
    telRilCall->GetCallTransferInfo(index, result);
    telRilCall->GetClip(result);
    telRilCall->SetClip(index, result);
    telRilCall->GetClir(result);
    telRilCall->SetClir(index, result);
    telRilCall->GetCallRestriction(fac, result);
    telRilCall->SetCallRestriction(fac, index, password, result);
    telRilCall->SendDtmfString(sDTMFCode, index, switchOn, switchOff, result);
    telRilCall->GetUssd(result);
    telRilCall->GetMute(result);
    telRilCall->GetEmergencyCallList(result);
    telRilCall->GetCallFailReason(result);
    telRilCall->SetBarringPassword(fac, oldPassword.c_str(), newPassword.c_str(), result);
}

void AnswerResponse(FuzzedDataProvider& provider)
{
    int32_t slotId = provider.ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t resultId = provider.ConsumeIntegral<int32_t>();
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(provider.ConsumeIntegral<uint8_t>());
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(resultId, object);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.slotId = slotId;
    auto rilInterface_ = HDI::Ril::V1_5::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilCall = std::make_shared<TelRilCall>(slotId, rilInterface_, observerHandler, nullptr);
    telRilCall->HoldCall(result);
    telRilCall->UnHoldCall(result);
    telRilCall->SwitchCall(result);
    telRilCall->AnswerResponse(responseInfo);
    telRilCall->HoldCallResponse(responseInfo);
    telRilCall->UnHoldCallResponse(responseInfo);
    telRilCall->SwitchCallResponse(responseInfo);
    telRilCall->DialResponse(responseInfo);
    telRilCall->HangupResponse(responseInfo);
    telRilCall->SetEmergencyCallListResponse(responseInfo);
}

void DeactivatePdpContext(FuzzedDataProvider& provider)
{
    int32_t slotId = provider.ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t offset = 0;
    int32_t cid = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t reason = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t responseId = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t dataPermitted = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t profileId = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t verType = provider.ConsumeIntegral<int32_t>() + offset;
    std::string apn = provider.ConsumeRandomLengthString();
    std::string protocol = provider.ConsumeRandomLengthString();
    std::string userName = provider.ConsumeRandomLengthString();
    std::string password = provider.ConsumeRandomLengthString();
    std::string roamingProtocol = provider.ConsumeRandomLengthString();
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.slotId = slotId;
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(provider.ConsumeIntegral<uint8_t>());
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(responseId, object);
    DataProfile dataProfile;
    dataProfile.profileId = profileId;
    dataProfile.apn = apn;
    dataProfile.protocol = protocol;
    dataProfile.verType = verType;
    dataProfile.userName = userName;
    dataProfile.password = password;
    dataProfile.roamingProtocol = roamingProtocol;
    auto rilInterface_ = HDI::Ril::V1_5::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilData = std::make_shared<TelRilData>(slotId, rilInterface_, observerHandler, nullptr);
    telRilData->DeactivatePdpContext(cid, reason, response);
    telRilData->DeactivatePdpContextResponse(responseInfo);
    telRilData->SetInitApnInfoResponse(responseInfo);
    telRilData->GetLinkBandwidthInfo(cid, response);
    telRilData->SetLinkBandwidthReportingRuleResponse(responseInfo);
    telRilData->SetDataPermitted(dataPermitted, response);
    telRilData->SetDataPermittedResponse(responseInfo);
    telRilData->GetLinkCapability(response);
    HDI::Ril::V1_1::DataLinkCapability dataLinkCapability;
    dataLinkCapability.primaryDownlinkKbps = provider.ConsumeIntegral<int32_t>();
    dataLinkCapability.primaryUplinkKbps = provider.ConsumeIntegral<int32_t>();
    dataLinkCapability.secondaryDownlinkKbps = provider.ConsumeIntegral<int32_t>();
    dataLinkCapability.secondaryUplinkKbps = provider.ConsumeIntegral<int32_t>();
    telRilData->GetLinkCapabilityResponse(responseInfo, dataLinkCapability);
    telRilData->SetInitApnInfo(dataProfile, response);
}

void SimStkProactiveNotify(FuzzedDataProvider& provider)
{
    int32_t slotId = provider.ConsumeIntegral<int32_t>() % SLOT_NUM;
    std::string response = provider.ConsumeRandomLengthString();
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.slotId = slotId;
    auto rilInterface_ = HDI::Ril::V1_5::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSim = std::make_shared<TelRilSim>(slotId, rilInterface_, observerHandler, nullptr);
    telRilSim->SimStkProactiveNotify(response);
    telRilSim->SimStkAlphaNotify(response);
    telRilSim->SimStkEventNotify(response);
    telRilSim->SetActiveSimResponse(responseInfo);
    telRilSim->SimStkSendTerminalResponseResponse(responseInfo);
    telRilSim->SimStkSendEnvelopeResponse(responseInfo);
    telRilSim->SimStkSendCallSetupRequestResultResponse(responseInfo);
    telRilSim->SimStkIsReadyResponse(responseInfo);
    telRilSim->SimStkSessionEndNotify();
    telRilSim->SimCloseLogicalChannelResponse(responseInfo);
    telRilSim->SimStateUpdated();
}

void GetSimStatus(FuzzedDataProvider& provider)
{
    int32_t slotId = provider.ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t accept = provider.ConsumeIntegral<int32_t>() % BOOL_NUM;
    int32_t offset = 0;
    int32_t resultId = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t serial = provider.ConsumeIntegral<int32_t>() + offset;
    offset += sizeof(int32_t);
    int32_t index = provider.ConsumeIntegral<int32_t>() + offset;
    std::string simIoInfoData = provider.ConsumeRandomLengthString();
    std::string path = provider.ConsumeRandomLengthString();
    std::string pin2 = provider.ConsumeRandomLengthString();
    std::string aid = provider.ConsumeRandomLengthString();
    std::string fac = provider.ConsumeRandomLengthString();
    std::string password = provider.ConsumeRandomLengthString();
    std::string pin = provider.ConsumeRandomLengthString();
    std::string puk = provider.ConsumeRandomLengthString();
    std::string puk2 = provider.ConsumeRandomLengthString();
    std::string strCmd = provider.ConsumeRandomLengthString();
    SimIoRequestInfo simIoInfo;
    simIoInfo.data = simIoInfoData;
    simIoInfo.path = path;
    simIoInfo.serial = serial;
    simIoInfo.pin2 = pin2;
    simIoInfo.aid = aid;
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(provider.ConsumeIntegral<uint8_t>());
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(resultId, object);
    auto rilInterface_ = HDI::Ril::V1_5::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto telRilSim = std::make_shared<TelRilSim>(slotId, rilInterface_, observerHandler, nullptr);
    telRilSim->GetSimStatus(result);
    telRilSim->GetSimIO(simIoInfo, result);
    telRilSim->GetSimLockStatus(fac, result);
    telRilSim->SetSimLock(fac, serial, password, result);
    telRilSim->UnlockPin(pin, result);
    telRilSim->UnlockPuk(puk, pin, result);
    telRilSim->UnlockPin2(pin2, result);
    telRilSim->UnlockPuk2(puk2, pin2, result);
    telRilSim->SetActiveSim(index, serial, result);
    telRilSim->SimStkSendTerminalResponse(strCmd, result);
    telRilSim->SimStkSendEnvelope(strCmd, result);
    telRilSim->SimStkSendCallSetupRequestResult(accept, result);
    telRilSim->SimStkIsReady(result);
    telRilSim->GetRadioProtocol(result);
    telRilSim->UnlockSimLock(index, password, result);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    if (g_flag) {
        return;
    }
    g_flag = true;

    FuzzedDataProvider provider(data, size);
    SendSmsMoreMode(provider);
    GetCallList(provider);
    AnswerResponse(provider);
    DeactivatePdpContext(provider);
    SimStkProactiveNotify(provider);
    GetSimStatus(provider);
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

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

void SendSmsMoreMode(const uint8_t *data, size_t size)
{
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t success = static_cast<int32_t>(size % BOOL_NUM);
    int32_t responseId = static_cast<int32_t>(size);
    int32_t status = static_cast<int32_t>(size);
    int32_t state = static_cast<int32_t>(size);
    int32_t gsmIndex = static_cast<int32_t>(size);
    int32_t cdmaIndex = static_cast<int32_t>(size);
    int32_t tosca = static_cast<int32_t>(size);
    int32_t mode = static_cast<int32_t>(size);
    uint32_t code = static_cast<uint32_t>(size);
    uint8_t hexChar = static_cast<uint8_t>(size);
    std::string smscPdu(reinterpret_cast<const char *>(data), size);
    std::string pdu(reinterpret_cast<const char *>(data), size);
    std::string address(reinterpret_cast<const char *>(data), size);
    std::string idList(reinterpret_cast<const char *>(data), size);
    std::string dcsList(reinterpret_cast<const char *>(data), size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(responseId, object);
    auto rilInterface_ = HDI::Ril::V1_2::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Failed to create EventRunner");
        return;
    }
    auto handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_ = nullptr;
    auto telRilSms = std::make_shared<TelRilSms>(slotId, rilInterface_, observerHandler, handler_);
    telRilSms->SendSmsMoreMode(smscPdu, pdu, response);
    telRilSms->IsSmsRespOrNotify(code);
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
    telRilSms->SetCBConfig(mode, idList, dcsList, response);
}

void GetCallList(const uint8_t *data, size_t size)
{
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t resultId = static_cast<int32_t>(size);
    int32_t index = static_cast<int32_t>(size);
    int32_t switchOn = static_cast<int32_t>(size);
    int32_t switchOff = static_cast<int32_t>(size);
    std::string address(reinterpret_cast<const char *>(data), size);
    std::string fac(reinterpret_cast<const char *>(data), size);
    std::string password(reinterpret_cast<const char *>(data), size);
    std::string sDTMFCode(reinterpret_cast<const char *>(data), size);
    std::string oldPassword(reinterpret_cast<const char *>(data), size);
    std::string newPassword(reinterpret_cast<const char *>(data), size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(resultId, object);
    auto rilInterface_ = HDI::Ril::V1_2::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Failed to create EventRunner");
        return;
    }
    auto handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_ = nullptr;
    auto telRilCall = std::make_shared<TelRilCall>(slotId, rilInterface_, observerHandler, handler_);
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
    telRilCall->SendDtmf(sDTMFCode, index, switchOn, switchOff, result);
    telRilCall->GetUssd(result);
    telRilCall->GetMute(result);
    telRilCall->GetEmergencyCallList(result);
    telRilCall->GetCallFailReason(result);
    telRilCall->SetBarringPassword(fac, oldPassword.c_str(), newPassword.c_str(), result);
}

void AnswerResponse(const uint8_t *data, size_t size)
{
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t resultId = static_cast<int32_t>(size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(resultId, object);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.slotId = slotId;
    auto rilInterface_ = HDI::Ril::V1_2::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Failed to create EventRunner");
        return;
    }
    auto handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_ = nullptr;
    auto telRilCall = std::make_shared<TelRilCall>(slotId, rilInterface_, observerHandler, handler_);
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

void DeactivatePdpContext(const uint8_t *data, size_t size)
{
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t cid = static_cast<int32_t>(size);
    int32_t reason = static_cast<int32_t>(size);
    int32_t responseId = static_cast<int32_t>(size);
    int32_t dataPermitted = static_cast<int32_t>(size);
    int32_t profileId = static_cast<int32_t>(size);
    int32_t verType = static_cast<int32_t>(size);
    std::string apn(reinterpret_cast<const char *>(data), size);
    std::string protocol(reinterpret_cast<const char *>(data), size);
    std::string userName(reinterpret_cast<const char *>(data), size);
    std::string password(reinterpret_cast<const char *>(data), size);
    std::string roamingProtocol(reinterpret_cast<const char *>(data), size);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.slotId = slotId;
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(responseId, object);
    DataProfile dataProfile;
    dataProfile.profileId = profileId;
    dataProfile.apn = apn;
    dataProfile.protocol = protocol;
    dataProfile.verType = verType;
    dataProfile.userName = userName;
    dataProfile.password = password;
    dataProfile.roamingProtocol = roamingProtocol;
    auto rilInterface_ = HDI::Ril::V1_2::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        return;
    }
    auto handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_ = nullptr;
    auto telRilData = std::make_shared<TelRilData>(slotId, rilInterface_, observerHandler, handler_);
    telRilData->DeactivatePdpContext(cid, reason, response);
    telRilData->DeactivatePdpContextResponse(responseInfo);
    telRilData->SetInitApnInfoResponse(responseInfo);
    telRilData->GetLinkBandwidthInfo(cid, response);
    telRilData->SetLinkBandwidthReportingRuleResponse(responseInfo);
    telRilData->SetDataPermitted(dataPermitted, response);
    telRilData->SetDataPermittedResponse(responseInfo);
    telRilData->GetLinkCapability(response);
    HDI::Ril::V1_1::DataLinkCapability dataLinkCapability;
    dataLinkCapability.primaryDownlinkKbps = static_cast<int32_t>(size);
    dataLinkCapability.primaryUplinkKbps = static_cast<int32_t>(size);
    dataLinkCapability.secondaryDownlinkKbps = static_cast<int32_t>(size);
    dataLinkCapability.secondaryUplinkKbps = static_cast<int32_t>(size);
    telRilData->GetLinkCapabilityResponse(responseInfo, dataLinkCapability);
    telRilData->SetInitApnInfo(dataProfile, response);
}

void SimStkProactiveNotify(const uint8_t *data, size_t size)
{
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    std::string response(reinterpret_cast<const char *>(data), size);
    HDI::Ril::V1_1::RilRadioResponseInfo responseInfo;
    responseInfo.slotId = slotId;
    auto rilInterface_ = HDI::Ril::V1_2::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Failed to create EventRunner");
        return;
    }
    auto handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_ = nullptr;
    auto telRilSim = std::make_shared<TelRilSim>(slotId, rilInterface_, observerHandler, handler_);
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

void GetSimStatus(const uint8_t *data, size_t size)
{
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t accept = static_cast<int32_t>(size % BOOL_NUM);
    int32_t resultId = static_cast<int32_t>(size);
    int32_t serial = static_cast<int32_t>(size);
    int32_t index = static_cast<int32_t>(size);
    std::string simIoInfoData(reinterpret_cast<const char *>(data), size);
    std::string path(reinterpret_cast<const char *>(data), size);
    std::string pin2(reinterpret_cast<const char *>(data), size);
    std::string aid(reinterpret_cast<const char *>(data), size);
    std::string fac(reinterpret_cast<const char *>(data), size);
    std::string password(reinterpret_cast<const char *>(data), size);
    std::string pin(reinterpret_cast<const char *>(data), size);
    std::string puk(reinterpret_cast<const char *>(data), size);
    std::string puk2(reinterpret_cast<const char *>(data), size);
    std::string strCmd(reinterpret_cast<const char *>(data), size);
    SimIoRequestInfo simIoInfo;
    simIoInfo.data = simIoInfoData;
    simIoInfo.path = path;
    simIoInfo.serial = serial;
    simIoInfo.pin2 = pin2;
    simIoInfo.aid = aid;
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer result = AppExecFwk::InnerEvent::Get(resultId, object);
    auto rilInterface_ = HDI::Ril::V1_2::IRil::Get();
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    auto eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Failed to create EventRunner");
        return;
    }
    auto handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_ = nullptr;
    auto telRilSim = std::make_shared<TelRilSim>(slotId, rilInterface_, observerHandler, handler_);
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

    SendSmsMoreMode(data, size);
    GetCallList(data, size);
    AnswerResponse(data, size);
    DeactivatePdpContext(data, size);
    SimStkProactiveNotify(data, size);
    GetSimStatus(data, size);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

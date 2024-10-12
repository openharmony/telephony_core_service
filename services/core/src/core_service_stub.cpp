/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "core_service_stub.h"

#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#define XCOLLIE_TIMEOUT_SECONDS 30
#endif

namespace OHOS {
namespace Telephony {
constexpr int32_t INVALID_VALUE = -1;

CoreServiceStub::CoreServiceStub()
{
    AddHandlerNetWorkToMap();
    AddHandlerDeviceToMap();
    AddHandlerImsToMap();
    AddHandlerSimToMap();
    AddHandlerSimLockToMap();
    AddHandlerSimToMapExt();
    AddHandlerVoiceMailToMap();
    AddHandlerPdpProfileToMap();
    AddHandlerOpkeyVersionToMap();
}

void CoreServiceStub::AddHandlerNetWorkToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_PS_RADIO_TECH)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetPsRadioTech(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_CS_RADIO_TECH)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetCsRadioTech(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPERATOR_NUMERIC)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOperatorNumeric(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_RESIDENT_NETWORK_NUMERIC)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetResidentNetworkNumeric(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPERATOR_NAME)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOperatorName(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIGNAL_INFO_LIST)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSignalInfoList(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_NETWORK_STATE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetNetworkState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_RADIO_STATE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetRadioState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_RADIO_STATE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetRadioState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_NETWORK_SEARCH_RESULT)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetNetworkSearchInformation(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_NETWORK_SELECTION_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetNetworkSelectionMode(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_NETWORK_SELECTION_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetNetworkSelectionMode(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_ISO_COUNTRY_CODE_FOR_NETWORK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetIsoCountryCodeForNetwork(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_CELL_INFO_LIST)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetCellInfoList(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_CELL_LOCATION)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetCellLocation(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_PREFERRED_NETWORK_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetPreferredNetwork(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_PREFERRED_NETWORK_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetPreferredNetwork(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_NETWORK_CAPABILITY)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetNetworkCapability(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_NETWORK_CAPABILITY)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetNetworkCapability(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_NR_OPTION_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetNrOptionMode(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_NR_OPTION_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetNrOptionMode(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_NR_SSB_ID_INFO)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetNrSsbIdInfo(data, reply); };
}

void CoreServiceStub::AddHandlerDeviceToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_IMEI)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetImei(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_IMEISV)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetImeiSv(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_MEID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetMeid(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_UNIQUE_DEVICE_ID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetUniqueDeviceId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_BASEBAND_VERSION)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetBasebandVersion(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::FACTORY_RESET)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnFactoryReset(data, reply); };
}

void CoreServiceStub::AddHandlerImsToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_IMS_REG_STATUS)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetImsRegStatus(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::REG_IMS_CALLBACK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnRegisterImsRegInfoCallback(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::UN_REG_IMS_CALLBACK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUnregisterImsRegInfoCallback(data, reply); };
}

void CoreServiceStub::AddHandlerSimToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::HAS_SIM_CARD)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnHasSimCard(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_STATE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_DSDS_MODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetDsdsMode(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SPN)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimSpn(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_ICCID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimIccId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_OPERATOR_NUMERIC)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimOperatorNumeric(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_IMSI)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetIMSI(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::IS_CT_SIM_CARD)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnIsCTSimCard(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::IS_SIM_ACTIVE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnIsSimActive(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_LANGUAGE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetLocaleFromDefaultSim(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_GID1)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimGid1(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_GID2)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimGid2(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_EONS)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimEons(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_SUB_INFO)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimSubscriptionInfo(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_DEFAULT_VOICE_SLOTID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetDefaultVoiceSlotId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_DEFAULT_VOICE_SLOTID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetDefaultVoiceSlotId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_DEFAULT_VOICE_SIMID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetDefaultVoiceSimId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_PRIMARY_SLOTID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetPrimarySlotId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_PRIMARY_SLOTID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetPrimarySlotId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_SHOW_NUMBER)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetShowNumber(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SHOW_NUMBER)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetShowNumber(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_SHOW_NAME)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetShowName(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SHOW_NAME)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetShowName(data, reply); };
}

void CoreServiceStub::AddHandlerSimLockToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::UNLOCK_PIN)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUnlockPin(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::UNLOCK_PUK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUnlockPuk(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::ALTER_PIN)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnAlterPin(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::CHECK_LOCK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetLockState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SWITCH_LOCK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetLockState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::UNLOCK_PIN2)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUnlockPin2(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::UNLOCK_PUK2)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUnlockPuk2(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::ALTER_PIN2)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnAlterPin2(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::UNLOCK_SIMLOCK)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUnlockSimLock(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::HAS_OPERATOR_PRIVILEGES)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnHasOperatorPrivileges(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SIM_AUTHENTICATION)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSimAuthentication(data, reply); };
}

void CoreServiceStub::AddHandlerSimToMapExt()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_ISO_COUNTRY_CODE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetISOCountryCodeForSim(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_ACTIVE_ACCOUNT_INFO_LIST)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetActiveSimAccountInfoList(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPERATOR_CONFIG)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOperatorConfig(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::REFRESH_SIM_STATE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnRefreshSimState(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_SIM_ACTIVE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetActiveSim(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_PHONE_NUMBER)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimPhoneNumber(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_TELENUMBER_IDENTIFIER)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimTeleNumberIdentifier(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_VOICE_CALL_FORWARDING)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetVoiceCallForwarding(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_GET)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnDiallingNumbersGet(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_INSERT)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnAddIccDiallingNumbers(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_UPDATE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnUpdateIccDiallingNumbers(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::ICC_DIALLING_NUMBERS_DELETE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnDelIccDiallingNumbers(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_MAX_SIM_COUNT)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetMaxSimCount(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::STK_CMD_FROM_APP_ENVELOPE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSendEnvelopeCmd(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::STK_CMD_FROM_APP_TERMINAL_RESPONSE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSendTerminalResponseCmd(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::STK_RESULT_FROM_APP_CALL_SETUP_REQUEST)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSendCallSetupRequestResult(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_CARD_TYPE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetCardType(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::IS_NR_SUPPORTED)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnIsNrSupported(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_SLOTID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSlotId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_SIMID)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimId(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_SIM_IO_DONE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetSimIO(data, reply); };
}

void CoreServiceStub::AddHandlerVoiceMailToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_VOICE_MAIL_TAG)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetVoiceMailInfor(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_VOICE_MAIL_NUMBER)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetVoiceMailNumber(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_VOICE_MAIL_COUNT)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetVoiceMailCount(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_VOICE_MAIL_COUNT)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetVoiceMailCount(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::SET_VOICE_MAIL)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetVoiceMailInfo(data, reply); };
}

void CoreServiceStub::AddHandlerPdpProfileToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::IS_ALLOWED_INSERT_APN)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnIsAllowedInsertApn(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_TARGET_OPKEY)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetTargetOpkey(data, reply); };
}

void CoreServiceStub::AddHandlerOpkeyVersionToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPKEY)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOpKey(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPNAME)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOpName(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPKEY_EXT)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOpKeyExt(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_OPKEY_VERSION)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnGetOpkeyVersion(data, reply); };
}

#ifdef CORE_SERVICE_SUPPORT_ESIM
void CoreServiceStub::AddHandlerEsimToMap()
{
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::PREPARE_DOWNLOAD)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnPrepareDownload(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::LOAD_BOUND_PROFILE_PACKAGE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnLoadBoundProfilePackage(data, reply); };
    memberFuncMap_[uint32_t(CoreServiceInterfaceCode::LIST_NOTIFICATIONS)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnListNotifications(data, reply); };
}
#endif

int32_t CoreServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_LOGD("CoreServiceStub OnRemoteRequest code %{public}u", code);
    std::u16string myDescripter = CoreServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        TELEPHONY_LOGE("descriptor checked fail");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            int32_t idTimer = SetTimer(code);
            int32_t result = memberFunc(data, reply);
            CancelTimer(idTimer);
            return result;
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t CoreServiceStub::SetTimer(uint32_t code)
{
#ifdef HICOLLIE_ENABLE
    int32_t idTimer = HiviewDFX::INVALID_ID;
    std::map<uint32_t, std::string>::iterator itCollieId = collieCodeStringMap_.find(code);
    if (itCollieId != collieCodeStringMap_.end()) {
        std::string collieStr = itCollieId->second;
        std::string collieName = "CoreServiceStub: " + collieStr;
        unsigned int flag = HiviewDFX::XCOLLIE_FLAG_NOOP;
        auto TimerCallback = [collieStr](void *) {
            TELEPHONY_LOGE("OnRemoteRequest timeout func: %{public}s", collieStr.c_str());
        };
        idTimer = HiviewDFX::XCollie::GetInstance().SetTimer(
            collieName, XCOLLIE_TIMEOUT_SECONDS, TimerCallback, nullptr, flag);
        TELEPHONY_LOGD("SetTimer id: %{public}d, name: %{public}s.", idTimer, collieStr.c_str());
    }
    return idTimer;
#else
    TELEPHONY_LOGD("No HICOLLIE_ENABLE");
    return -1;
#endif
}

void CoreServiceStub::CancelTimer(int32_t id)
{
#ifdef HICOLLIE_ENABLE
    if (id == HiviewDFX::INVALID_ID) {
        return;
    }
    TELEPHONY_LOGD("CancelTimer id: %{public}d.", id);
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
#else
    return;
#endif
}

int32_t CoreServiceStub::OnGetPsRadioTech(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    int32_t radioTech = 0;
    int32_t result = GetPsRadioTech(slotId, radioTech);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(radioTech));
    }
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCsRadioTech(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    int32_t radioTech = 0;
    int32_t result = GetCsRadioTech(slotId, radioTech);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(radioTech));
    }
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorNumeric(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::u16string result = GetOperatorNumeric(slotId);
    reply.WriteString16(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetResidentNetworkNumeric(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::string result = GetResidentNetworkNumeric(slotId);
    reply.WriteString(result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorName(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::u16string operatorName = u"";
    int32_t result = GetOperatorName(slotId, operatorName);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(operatorName));
    }
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSignalInfoList(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::vector<sptr<SignalInformation>> signals;
    int32_t result = GetSignalInfoList(slotId, signals);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        reply.WriteInt32(static_cast<int32_t>(signals.size()));
        for (const auto &v : signals) {
            v->Marshalling(reply);
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkState(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    sptr<NetworkState> networkState = nullptr;
    int32_t result = GetNetworkState(slotId, networkState);
    if ((networkState == nullptr) && (result != TELEPHONY_ERR_PERMISSION_ERR)) {
        TELEPHONY_LOGE("networkState is nullptr and permission is not denied.");
        result = TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        networkState->Marshalling(reply);
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetRadioState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetRadioState remoteCallback is nullptr.");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetRadioState callback is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    bool isOn = data.ReadBool();
    TELEPHONY_LOGD("CoreServiceStub::OnSetRadioState isOn:%{public}d", isOn);
    int32_t result = SetRadioState(slotId, isOn, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetRadioState write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetRadioState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetRadioState remoteCallback is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetRadioState callback is nullptr.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = GetRadioState(slotId, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetRadioState write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    TELEPHONY_LOGD("CoreServiceStub::OnGetRadioState result:%{public}d", result);
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIsoCountryCodeForNetwork(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string countryCode;
    int32_t result = GetIsoCountryCodeForNetwork(slotId, countryCode);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(countryCode));
    }
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetImei(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string imei = u"";
    int32_t result = GetImei(slotId, imei);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetImei write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(imei)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetImei write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetImeiSv(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string imeiSv = u"";
    int32_t result = GetImeiSv(slotId, imeiSv);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetImeiSv write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(imeiSv)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetImeiSv write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetMeid(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string meid = u"";
    int32_t result = GetMeid(slotId, meid);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetMeid write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(meid)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetMeid write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetUniqueDeviceId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string deviceId = u"";
    int32_t result = GetUniqueDeviceId(slotId, deviceId);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetUniqueDeviceId write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(deviceId)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetUniqueDeviceId write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsNrSupported(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = IsNrSupported(slotId);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::IS_NR_SUPPORTED write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetNrOptionMode(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t nrMode = data.ReadInt32();
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetNrOptionMode remoteCallback is nullptr.");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetNrOptionMode callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = SetNrOptionMode(slotId, nrMode, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetNrOptionMode write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNrOptionMode(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    sptr<INetworkSearchCallback> callback = nullptr;
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNrOptionMode remoteCallback is nullptr.");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNrOptionMode callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = GetNrOptionMode(slotId, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetNrOptionMode write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnHasSimCard(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool hasSimCard = false;
    int32_t result = HasSimCard(slotId, hasSimCard);
    TELEPHONY_LOGD("result is %{public}s", hasSimCard ? "true" : "false");
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteBool(hasSimCard));
    }
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    int32_t result = GetSimState(slotId, simState);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(static_cast<int32_t>(simState)));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_SIM_STATE write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetDsdsMode(MessageParcel &data, MessageParcel &reply)
{
    int32_t dsdsMode = 0; /*0 means DSDS_MODE_V2*/
    int32_t result = GetDsdsMode(dsdsMode);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(static_cast<int32_t>(dsdsMode)));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_DSDS_MODE write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCardType(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    CardType cardType = CardType::UNKNOWN_CARD;
    int32_t result = GetCardType(slotId, cardType);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(static_cast<int32_t>(cardType)));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_CARD_TYPE write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetISOCountryCodeForSim(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string countryCode;
    int32_t result = GetISOCountryCodeForSim(slotId, countryCode);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(countryCode));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_ISO_COUNTRY_CODE write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimSpn(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string spn;
    int32_t result = GetSimSpn(slotId, spn);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(spn));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_SPN write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimIccId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string iccId;
    int32_t result = GetSimIccId(slotId, iccId);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(iccId));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_ICCID write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimOperatorNumeric(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string operatorNumeric;
    int32_t result = GetSimOperatorNumeric(slotId, operatorNumeric);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(operatorNumeric));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_SIM_OPERATOR_NUMERIC write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetIMSI(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string imsi;
    int32_t result = GetIMSI(slotId, imsi);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(imsi));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GET_IMSI write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsCTSimCard(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool isCTSimCard = false;
    int32_t result = IsCTSimCard(slotId, isCTSimCard);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteBool(isCTSimCard));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::IS_CT_SIM_CARD write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsSimActive(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool result = IsSimActive(slotId);
    TELEPHONY_LOGD("OnRemoteRequest::IsSimActive result is %{public}d", result);
    bool ret = reply.WriteBool(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::IsSimActive write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t simId = data.ReadInt32();
    int32_t result = GetSlotId(simId);
    TELEPHONY_LOGD("OnRemoteRequest::OnGetSlotId result is %{public}d", result);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetSlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = GetSimId(slotId);
    TELEPHONY_LOGD("OnRemoteRequest::OnGetSimId result is %{public}d", result);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetSimId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkSearchInformation(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSearchInformation callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = GetNetworkSearchInformation(slotId, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetNetworkSearchInformation write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSelectionMode callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = GetNetworkSelectionMode(slotId, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetNetworkSelectionMode write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetNetworkSelectionMode(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    int32_t selectMode = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnSetNetworkSelectionMode selectMode:%{public}d", selectMode);
    bool resumeSelection = data.ReadBool();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnSetNetworkSelectionMode remoteCallback is null");
    }
    sptr<NetworkInformation> networkState = NetworkInformation::Unmarshalling(data);
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetNetworkSelectionMode callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = SetNetworkSelectionMode(slotId, selectMode, networkState, resumeSelection, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetNetworkSelectionMode write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetLocaleFromDefaultSim(MessageParcel &data, MessageParcel &reply)
{
    std::u16string result = GetLocaleFromDefaultSim();
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GetLocaleFromDefaultSim write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimGid1(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string gid1;
    int32_t result = GetSimGid1(slotId, gid1);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(gid1));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GetSimGid1 write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimGid2(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimGid2(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GetSimGid2 write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimEons(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    const std::string plmn = data.ReadString();
    int32_t lac = data.ReadInt32();
    bool longNameRequired = data.ReadBool();
    std::u16string result = GetSimEons(slotId, plmn, lac, longNameRequired);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::GetSimEons write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimSubscriptionInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    IccAccountInfo iccAccountInfo;
    int32_t result = GetSimAccountInfo(slotId, iccAccountInfo);
    bool ret = reply.WriteInt32(result);
    if (!iccAccountInfo.Marshalling(reply)) {
        TELEPHONY_LOGE("OnGetSimSubscriptionInfo IccAccountInfo reply Marshalling is false");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!ret) {
        TELEPHONY_LOGE("OnGetSimSubscriptionInfo write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = SetDefaultVoiceSlotId(slotId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetDefaultVoiceSlotId write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetDefaultVoiceSlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = GetDefaultVoiceSlotId();
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetDefaultVoiceSlotId write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetDefaultVoiceSimId(MessageParcel &data, MessageParcel &reply)
{
    int32_t simId = 0;
    int32_t result = GetDefaultVoiceSimId(simId);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("write int32 reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteInt32(simId)) {
            TELEPHONY_LOGE("write int32 reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetPrimarySlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = SetPrimarySlotId(slotId);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetPrimarySlotId write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetPrimarySlotId(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = INVALID_VALUE;
    int32_t result = GetPrimarySlotId(slotId);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(slotId));
    }
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPin(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t slotId = data.ReadInt32();
    std::u16string pin = data.ReadString16();
    int32_t result = UnlockPin(slotId, pin, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnUnlockPin, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPin write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPuk(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t slotId = data.ReadInt32();
    std::u16string newPin = data.ReadString16();
    std::u16string puk = data.ReadString16();
    int32_t result = UnlockPuk(slotId, newPin, puk, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnUnlockPuk, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPuk write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAlterPin(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t slotId = data.ReadInt32();
    std::u16string newPin = data.ReadString16();
    std::u16string oldPin = data.ReadString16();
    int32_t result = AlterPin(slotId, newPin, oldPin, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnAlterPin, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnAlterPin write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPin2(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t slotId = data.ReadInt32();
    std::u16string pin2 = data.ReadString16();
    int32_t result = UnlockPin2(slotId, pin2, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnUnlockPin2, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPin2 write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockPuk2(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t slotId = data.ReadInt32();
    std::u16string newPin2 = data.ReadString16();
    std::u16string puk2 = data.ReadString16();
    int32_t result = UnlockPuk2(slotId, newPin2, puk2, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnUnlockPuk2, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockPuk2 write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAlterPin2(MessageParcel &data, MessageParcel &reply)
{
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t slotId = data.ReadInt32();
    std::u16string newPin2 = data.ReadString16();
    std::u16string oldPin2 = data.ReadString16();
    int32_t result = AlterPin2(slotId, newPin2, oldPin2, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnAlterPin2, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnAlterPin2 write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetLockState(MessageParcel &data, MessageParcel &reply)
{
    LockInfo options;
    int32_t slotId = data.ReadInt32();
    options.lockType = static_cast<LockType>(data.ReadInt32());
    options.lockState = static_cast<LockState>(data.ReadInt32());
    options.password = data.ReadString16();
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    TELEPHONY_LOGI("CoreServiceStub::OnSetLockState(), lockType = %{public}d, lockState = %{public}d, "
                   "slotId = %{public}d",
        options.lockType, options.lockState, slotId);
    int32_t result = SetLockState(slotId, options, response);
    bool ret = reply.WriteInt32(result);
    TELEPHONY_LOGI(
        "OnSetLockState, response.result :%{public}d, response.remain :%{public}d", response.result, response.remain);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetLockState write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetLockState(MessageParcel &data, MessageParcel &reply)
{
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType;
    int32_t slotId = data.ReadInt32();
    lockType = static_cast<LockType>(data.ReadInt32());
    TELEPHONY_LOGI("CoreServiceStub::OnGetLockState(),lockType = %{public}d, slotId = %{public}d", lockType, slotId);
    int32_t result = GetLockState(slotId, lockType, lockState);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(static_cast<int32_t>(lockState)));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetLockState write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnRefreshSimState(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnRefreshSimState(), slotId = %{public}d", slotId);
    int32_t result = RefreshSimState(slotId);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnRefreshSimState write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetActiveSim(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t enable = data.ReadInt32();
    TELEPHONY_LOGD("CoreServiceStub::OnSetActiveSim(), slotId = %{public}d", slotId);
    int32_t result = SetActiveSim(slotId, enable);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetActiveSim write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetPreferredNetwork(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        TELEPHONY_LOGD("CoreServiceStub::OnGetPreferredNetwork remote callback is not null.");
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnGetPreferredNetwork callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = GetPreferredNetwork(slotId, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetPreferredNetwork write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNetworkCapability(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t networkCapabilityType = data.ReadInt32();
    int32_t networkCapabilityState = 0;
    int32_t result = GetNetworkCapability(slotId, networkCapabilityType, networkCapabilityState);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(networkCapabilityState));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetNetworkCapability write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetNetworkCapability(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t networkCapabilityType = data.ReadInt32();
    int32_t networkCapabilityState = data.ReadInt32();
    int32_t result = SetNetworkCapability(slotId, networkCapabilityType, networkCapabilityState);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetNetworkCapability write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetShowNumber(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string number = data.ReadString16();
    int32_t result = SetShowNumber(slotId, number);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetShowNumber write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return result;
}

int32_t CoreServiceStub::OnGetShowNumber(OHOS::MessageParcel &data, OHOS::MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string showNumber;
    int32_t result = GetShowNumber(slotId, showNumber);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(showNumber));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnGetShowNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetShowName(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string name = data.ReadString16();
    int32_t result = SetShowName(slotId, name);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetShowName write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetPreferredNetwork(MessageParcel &data, MessageParcel &reply)
{
    sptr<INetworkSearchCallback> callback = nullptr;
    int32_t slotId = data.ReadInt32();
    int32_t networkMode = data.ReadInt32();
    TELEPHONY_LOGI("CoreServiceStub::OnSetPreferredNetwork selectMode:%{public}d", networkMode);
    sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
    if (remoteCallback != nullptr) {
        callback = iface_cast<INetworkSearchCallback>(remoteCallback);
    } else {
        TELEPHONY_LOGE("CoreServiceStub::OnSetPreferredNetwork remoteCallback is null");
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnSetPreferredNetwork callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = SetPreferredNetwork(slotId, networkMode, callback);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetPreferredNetwork write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetShowName(OHOS::MessageParcel &data, OHOS::MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string showName;
    int32_t result = GetShowName(slotId, showName);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(showName));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnGetShowName write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetActiveSimAccountInfoList(MessageParcel &data, MessageParcel &reply)
{
    std::vector<IccAccountInfo> iccAccountInfoList;
    int32_t result = GetActiveSimAccountInfoList(iccAccountInfoList);
    int32_t size = static_cast<int32_t>(iccAccountInfoList.size());
    bool ret = reply.WriteInt32(result);
    ret = (ret && reply.WriteInt32(size));
    if (!ret) {
        TELEPHONY_LOGE("OnGetActiveSimAccountInfoList write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    std::vector<IccAccountInfo>::iterator it = iccAccountInfoList.begin();
    while (it != iccAccountInfoList.end()) {
        TELEPHONY_LOGI("OnGetActiveSimAccountInfoList slotIndex = %{public}d", (*it).slotIndex);
        if (!(*it).Marshalling(reply)) {
            TELEPHONY_LOGE("OnGetActiveSimAccountInfoList IccAccountInfo reply Marshalling is false");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
        ++it;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOperatorConfig(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    OperatorConfig operatorConfig;
    int32_t result = GetOperatorConfigs(slotId, operatorConfig);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetOperatorConfig write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!operatorConfig.Marshalling(reply)) {
            TELEPHONY_LOGE("OnGetOperatorConfig operatorConfig reply Marshalling is false");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimPhoneNumber(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string telephoneNumber;
    int32_t result = GetSimTelephoneNumber(slotId, telephoneNumber);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(telephoneNumber));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetSimPhoneNumber write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimTeleNumberIdentifier(MessageParcel &data, MessageParcel &reply)
{
    const int32_t slotId = data.ReadInt32();
    std::u16string result = GetSimTeleNumberIdentifier(slotId);
    bool ret = reply.WriteString16(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetSimPhoneNumber write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetVoiceMailInfor(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string voiceMailIdentifier;
    int32_t result = GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(voiceMailIdentifier));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetVoiceMailInfor write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetVoiceMailNumber(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string voiceMailNumber;
    int32_t result = GetVoiceMailNumber(slotId, voiceMailNumber);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteString16(voiceMailNumber));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetVoiceMailNumber write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetVoiceMailCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t voiceMailCount;
    int32_t result = GetVoiceMailCount(slotId, voiceMailCount);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(voiceMailCount));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetVoiceMailCount write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetVoiceMailCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t voiceMailCount = data.ReadInt32();
    int32_t result = SetVoiceMailCount(slotId, voiceMailCount);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetVoiceMailCount write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetVoiceCallForwarding(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool enable = data.ReadBool();
    std::string number = data.ReadString();
    int32_t result = SetVoiceCallForwarding(slotId, enable, number);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSetVoiceCallForwarding write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnDiallingNumbersGet(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    int32_t result = QueryIccDiallingNumbers(slotId, type, diallingNumbers);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnDiallingNumbersGet write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        reply.WriteInt32(static_cast<int32_t>(diallingNumbers.size()));
        for (const auto &v : diallingNumbers) {
            v->Marshalling(reply);
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnAddIccDiallingNumbers(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(data);
    if (diallingNumber == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnAddIccDiallingNumbers diallingNumber is null");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    int32_t result = AddIccDiallingNumbers(slotId, type, diallingNumber);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnAddIccDiallingNumbers write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUpdateIccDiallingNumbers(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(data);
    if (diallingNumber == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnUpdateIccDiallingNumbers diallingNumber is null");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    int32_t result = UpdateIccDiallingNumbers(slotId, type, diallingNumber);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnUpdateIccDiallingNumbers write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnDelIccDiallingNumbers(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t type = data.ReadInt32();
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = DiallingNumbersInfo::UnMarshalling(data);
    if (diallingNumber == nullptr) {
        TELEPHONY_LOGE("CoreServiceStub::OnDelIccDiallingNumbers diallingNumber is null");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    int32_t result = DelIccDiallingNumbers(slotId, type, diallingNumber);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnDelIccDiallingNumbers write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSetVoiceMailInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string name = data.ReadString16();
    std::u16string number = data.ReadString16();
    int32_t result = SetVoiceMailInfo(slotId, name, number);

    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnSetVoiceMailInfo write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetMaxSimCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = GetMaxSimCount();
    int32_t ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnGetMaxSimCount write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOpKey(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string opkey;
    int32_t result = GetOpKey(slotId, opkey);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetOpKey write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(opkey)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetOpKey write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOpKeyExt(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string opkeyExt;
    int32_t result = GetOpKeyExt(slotId, opkeyExt);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetOpKeyExt write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(opkeyExt)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetOpKeyExt write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOpName(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string opname;
    int32_t result = GetOpName(slotId, opname);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetOpName write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString16(opname)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetOpName write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSendEnvelopeCmd(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::string cmd = data.ReadString();
    int32_t result = SendEnvelopeCmd(slotId, cmd);
    TELEPHONY_LOGI("OnRemoteRequest::OnSendEnvelopeCmd result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSendEnvelopeCmd write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSendTerminalResponseCmd(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::string cmd = data.ReadString();
    int32_t result = SendTerminalResponseCmd(slotId, cmd);
    TELEPHONY_LOGD("OnRemoteRequest::OnSendTerminalResponseCmd result is %{public}s", result ? "true" : "false");
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSendTerminalResponseCmd write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSendCallSetupRequestResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool accept = data.ReadInt32();
    int32_t result = SendCallSetupRequestResult(slotId, accept);
    TELEPHONY_LOGD("OnRemoteRequest::OnSendCallSetupRequestResult result is %{public}d", result);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("OnRemoteRequest::OnSendCallSetupRequestResult write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnlockSimLock(MessageParcel &data, MessageParcel &reply)
{
    PersoLockInfo lockInfo;
    int32_t slotId = data.ReadInt32();
    lockInfo.lockType = static_cast<PersoLockType>(data.ReadInt32());
    lockInfo.password = data.ReadString16();
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };

    TELEPHONY_LOGI("CoreServiceStub::OnUnlockSimLock(), lockType = %{public}d", lockInfo.lockType);
    int32_t result = UnlockSimLock(slotId, lockInfo, response);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(response.result));
        ret = (ret && reply.WriteInt32(response.remain));
    }
    if (!ret) {
        TELEPHONY_LOGE("CoreServiceStub::OnUnlockSimLock write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetImsRegStatus(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    ImsServiceType imsSrvType = static_cast<ImsServiceType>(data.ReadInt32());
    ImsRegInfo info;
    int32_t result = GetImsRegStatus(slotId, imsSrvType, info);
    bool ret = reply.WriteInt32(result);
    ret = (ret && reply.WriteInt32(info.imsRegState));
    ret = (ret && reply.WriteInt32(info.imsRegTech));
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return ERR_FLATTEN_OBJECT;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCellInfoList(MessageParcel &data, MessageParcel &reply)
{
    auto slotId = data.ReadInt32();
    std::vector<sptr<CellInformation>> cellInfo;
    int32_t result = GetCellInfoList(slotId, cellInfo);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetCellInfoList write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        reply.WriteInt32(static_cast<int32_t>(cellInfo.size()));
        for (const auto &v : cellInfo) {
            v->Marshalling(reply);
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetCellLocation(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = SendUpdateCellLocationRequest(slotId);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetCellLocation write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnHasOperatorPrivileges(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    bool hasOperatorPrivileges = false;
    int32_t result = HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteBool(hasOperatorPrivileges));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnHasOperatorPrivileges write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnSimAuthentication(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    AuthType authType = static_cast<AuthType>(data.ReadInt32());
    std::string authData = data.ReadString();
    SimAuthenticationResponse response = { 0 };
    int32_t result = SimAuthentication(slotId, authType, authData, response);
    reply.WriteInt32(result);
    reply.WriteInt32(response.sw1);
    reply.WriteInt32(response.sw2);
    reply.WriteString(response.response);

    return NO_ERROR;
}

int32_t CoreServiceStub::OnRegisterImsRegInfoCallback(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    ImsServiceType imsSrvType = static_cast<ImsServiceType>(data.ReadInt32());
    sptr<ImsRegInfoCallback> callback = iface_cast<ImsRegInfoCallback>(data.ReadRemoteObject());
    int32_t result;
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is nullptr!");
        result = TELEPHONY_ERR_ARGUMENT_NULL;
    } else {
        result = RegisterImsRegInfoCallback(slotId, imsSrvType, callback);
    }
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnUnregisterImsRegInfoCallback(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    ImsServiceType imsSrvType = static_cast<ImsServiceType>(data.ReadInt32());
    int32_t result = UnregisterImsRegInfoCallback(slotId, imsSrvType);
    bool ret = reply.WriteInt32(result);
    if (!ret) {
        TELEPHONY_LOGE("write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetBasebandVersion(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::string version = "";
    int32_t result = GetBasebandVersion(slotId, version);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("OnRemoteRequest::OnGetBasebandVersion write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!reply.WriteString(version)) {
            TELEPHONY_LOGE("OnRemoteRequest::OnGetBasebandVersion write reply failed.");
            return TELEPHONY_ERR_WRITE_REPLY_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetNrSsbIdInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::shared_ptr<NrSsbInformation> nrSsbInformation = std::make_shared<NrSsbInformation>();
    if (nrSsbInformation == nullptr) {
        TELEPHONY_LOGE("nrSsbInformation is null.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = GetNrSsbIdInfo(slotId, nrSsbInformation);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("Write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (result == TELEPHONY_ERR_SUCCESS) {
        if (!nrSsbInformation->Marshalling(reply)) {
            TELEPHONY_LOGE("Marshalling is failed.");
            return TELEPHONY_ERR_WRITE_DATA_FAIL;
        }
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnFactoryReset(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t result = FactoryReset(slotId);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("Write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnIsAllowedInsertApn(MessageParcel &data, MessageParcel &reply)
{
    std::string value = data.ReadString();
    bool result = IsAllowedInsertApn(value);
    if (!reply.WriteBool(result)) {
        TELEPHONY_LOGE("Write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetTargetOpkey(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    std::u16string opkey;
    int32_t result = GetTargetOpkey(slotId, opkey);
    if (!reply.WriteString16(opkey)) {
        TELEPHONY_LOGE("Write reply opkey failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("Write reply result failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetOpkeyVersion(MessageParcel &data, MessageParcel &reply)
{
    std::string versionInfo;
    int32_t result = GetOpkeyVersion(versionInfo);
    if (!reply.WriteString(versionInfo)) {
        TELEPHONY_LOGE("Write versionInfo result failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("Write reply result failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnGetSimIO(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t command = data.ReadInt32();
    int32_t fileId = data.ReadInt32();
    std::string dataStr = data.ReadString();
    std::string path = data.ReadString();
    SimAuthenticationResponse response = { 0 };
    int32_t result = GetSimIO(slotId, command, fileId, dataStr, path, response);
    if (!reply.WriteInt32(result)) {
        TELEPHONY_LOGE("Write reply result failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    reply.WriteInt32(result);
    reply.WriteInt32(response.sw1);
    reply.WriteInt32(response.sw2);
    reply.WriteString(response.response);

    return NO_ERROR;
}

#ifdef CORE_SERVICE_SUPPORT_ESIM
int32_t CoreServiceStub::OnPrepareDownload(MessageParcel &data, MessageParcel &reply)
{
    DownLoadConfigInfo downLoadConfigInfo;
    int32_t slotId = data.ReadInt32();
    downLoadConfigInfo.portIndex = data.ReadInt32();
    downLoadConfigInfo.hashCc = data.ReadString16();
    downLoadConfigInfo.smdpSigned2 = data.ReadString16();
    downLoadConfigInfo.smdpSignature2 = data.ReadString16();
    downLoadConfigInfo.smdpCertificate = data.ReadString16();

    ResponseEsimResult responseResult;
    int32_t result = PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(static_cast<int32_t>(responseResult.resultCode)));
        ret = (ret && reply.WriteString16(responseResult.response));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnPrepareDownload write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnLoadBoundProfilePackage(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t portIndex = data.ReadInt32();
    std::u16string boundProfilePackage = data.ReadString16();

    ResponseEsimBppResult responseResult;
    int32_t result = LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteInt32(responseResult.resultCode));
        ret = (ret && reply.WriteString16(responseResult.response));
        ret = (ret && reply.WriteInt32(responseResult.seqNumber));
        ret = (ret && reply.WriteInt32(responseResult.profileManagementOperation));
        ret = (ret && reply.WriteString16(responseResult.notificationAddress));
        ret = (ret && reply.WriteString16(responseResult.iccId));
    }
    if (!ret) {
        TELEPHONY_LOGE("OnLoadBoundProfilePackage write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}

int32_t CoreServiceStub::OnListNotifications(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t portIndex = data.ReadInt32();
    Event events = static_cast<Event>(data.ReadInt32());
    EuiccNotificationList notificationList;
    int32_t result = ListNotifications(slotId, portIndex, events, notificationList);
    bool ret = reply.WriteInt32(result);
    if (result == TELEPHONY_ERR_SUCCESS) {
        ret = (ret && reply.WriteUint32(notificationList.euiccNotification.size()));
        for (const auto &notification : notificationList.euiccNotification) {
            ret = (ret && reply.WriteInt32(notification.seq));
            ret = (ret && reply.WriteString16(notification.targetAddr));
            ret = (ret && reply.WriteInt32(notification.event));
            ret = (ret && reply.WriteString16(notification.data));
        }
    }
    if (!ret) {
        TELEPHONY_LOGE("OnListNotifications write reply failed.");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return NO_ERROR;
}
#endif
} // namespace Telephony
} // namespace OHOS

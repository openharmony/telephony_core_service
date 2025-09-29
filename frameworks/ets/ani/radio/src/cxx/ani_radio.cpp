/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ani_radio.h"
#include <memory>
#include <variant>
#include "ffrt.h"
#include "cxx.h"
#include "wrapper.rs.h"
#include "telephony_types.h"
#include "telephony_errors.h"
#include "telephony_permission.h"
#include "telephony_config.h"
#include "telephony_log_wrapper.h"
#include "core_service_client.h"
#include "signal_information.h"
#include "telephony_ext_utils_wrapper.h"
#include "network_search_callback.h"
#include "cell_information.h"
#include "network_information.h"
#include "napi_util.h"
#include "ani_radio_types.h"

namespace OHOS {
namespace Telephony {
namespace RadioAni {

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static inline bool IsValidSlotIdEx(int32_t slotId)
{
    // One more slot for VSim.
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT + 1));
}

static inline bool IsValidNetworkCapabilityType(int32_t networkCapabilityType)
{
    return ((networkCapabilityType == static_cast<int32_t>(NetworkCapabilityType::SERVICE_TYPE_LTE)) ||
        (networkCapabilityType == static_cast<int32_t>(NetworkCapabilityType::SERVICE_TYPE_NR)));
}

static inline bool IsValidNetworkCapabilityState(int32_t networkCapabilityState)
{
    return ((networkCapabilityState == static_cast<int32_t>(NetworkCapabilityState::SERVICE_CAPABILITY_OFF)) ||
        (networkCapabilityState == static_cast<int32_t>(NetworkCapabilityState::SERVICE_CAPABILITY_ON)));
}

static inline ArktsError ConvertArktsErrorWithPermission(int32_t errorCode, const std::string &funcName,
                                                         const std::string &permission)
{
    JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
        errorCode, funcName, permission);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

static inline ArktsError ConvertArktsError(int32_t errorCode)
{
    JsError error = NapiUtil::ConverErrorMessageForJs(errorCode);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

static std::string GetRadioTechName(int32_t radioTech)
{
    NetworkRat tech = static_cast<NetworkRat>(radioTech);
    switch (tech) {
        case NetworkRat::NETWORK_GSM_OR_GPRS: {
            return RADIO_TECH_NAME_GSM;
        }
        case NetworkRat::NETWORK_WCDMA: {
            return RADIO_TECH_NAME_WCDMA;
        }
        case NetworkRat::NETWORK_LTE: {
            return RADIO_TECH_NAME_LTE;
        }
        case NetworkRat::NETWORK_NR: {
            return RADIO_TECH_NAME_NR;
        }
        default: {
            return "";
        }
    }
}

static int32_t GetRatTechValue(std::string ratTechStr)
{
    if (!RADIO_TECH_NAME_GSM.compare(ratTechStr) || !RADIO_TECH_NAME_GPRS.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_GSM_OR_GPRS);
    }
    if (!RADIO_TECH_NAME_WCDMA.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_WCDMA);
    }
    if (!RADIO_TECH_NAME_LTE.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_LTE);
    }
    if (!RADIO_TECH_NAME_NR.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_NR);
    }
    return static_cast<int32_t>(NetworkRat::NETWORK_LTE);
}

static int32_t ConvertEtsNetworkSelectionMode(int32_t etsSelectionMode)
{
    switch (etsSelectionMode) {
        case ETS_NETWORK_SELECTION_AUTOMATIC:
            return static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO);
        case ETS_NETWORK_SELECTION_MANUAL:
            return static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL);
        default:
            return static_cast<int32_t>(SelectionMode::MODE_TYPE_UNKNOWN);
    }
}

static int32_t ConvertSelectionMode(int32_t selectionMode)
{
    switch (selectionMode) {
        case static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO):
            return ETS_NETWORK_SELECTION_AUTOMATIC;
        case static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL):
            return ETS_NETWORK_SELECTION_MANUAL;
        default:
            return ETS_NETWORK_SELECTION_UNKNOWN;
    }
}

static void JudgmentDataGsm(const sptr<CellInformation> info, CellInformationAni &infoAni)
{
    auto gsmCellInfo = static_cast<GsmCellInformation *>(info.GetRefPtr());
    if (gsmCellInfo != nullptr) {
        infoAni.lac = gsmCellInfo->GetLac();
        infoAni.cell_id = gsmCellInfo->GetCellId();
        infoAni.arfcn = gsmCellInfo->GetArfcn();
        infoAni.bsic = gsmCellInfo->GetBsic();
        infoAni.mcc = gsmCellInfo->GetMcc();
        infoAni.mnc = gsmCellInfo->GetMnc();
    }
}

static void JudgmentDataCdma(sptr<CellInformation> info, CellInformationAni &infoAni)
{
    auto cdmaCellInfo = static_cast<CdmaCellInformation *>(info.GetRefPtr());
    if (cdmaCellInfo != nullptr) {
        infoAni.base_id = cdmaCellInfo->GetBaseId();
        infoAni.latitude = cdmaCellInfo->GetLatitude();
        infoAni.longitude = cdmaCellInfo->GetLongitude();
        infoAni.nid = cdmaCellInfo->GetNid();
        infoAni.sid = cdmaCellInfo->GetSid();
    }
}

static void JudgmentDataWcdma(sptr<CellInformation> info, CellInformationAni &infoAni)
{
    auto wcdmaCellInfo = static_cast<WcdmaCellInformation *>(info.GetRefPtr());
    if (wcdmaCellInfo != nullptr) {
        infoAni.lac = wcdmaCellInfo->GetLac();
        infoAni.cell_id = wcdmaCellInfo->GetCellId();
        infoAni.psc = wcdmaCellInfo->GetPsc();
        infoAni.uarfcn = wcdmaCellInfo->GetArfcn();
        infoAni.mcc = wcdmaCellInfo->GetMcc();
        infoAni.mnc = wcdmaCellInfo->GetMnc();
    }
}

static void JudgmentDataTdscdma(sptr<CellInformation> info, CellInformationAni &infoAni)
{
    auto tdscdmaCellInfo = static_cast<TdscdmaCellInformation *>(info.GetRefPtr());
    if (tdscdmaCellInfo != nullptr) {
        infoAni.lac = tdscdmaCellInfo->GetLac();
        infoAni.cell_id = tdscdmaCellInfo->GetCellId();
        infoAni.cpid = tdscdmaCellInfo->GetCpid();
        infoAni.uarfcn = tdscdmaCellInfo->GetArfcn();
        infoAni.mcc = tdscdmaCellInfo->GetMcc();
        infoAni.mnc = tdscdmaCellInfo->GetMnc();
    }
}

static void JudgmentDataLte(sptr<CellInformation> info, CellInformationAni &infoAni)
{
    auto lteCellInfo = static_cast<LteCellInformation *>(info.GetRefPtr());
    if (lteCellInfo != nullptr) {
        infoAni.cgi = lteCellInfo->GetCellId();
        infoAni.pci = lteCellInfo->GetPci();
        infoAni.tac = lteCellInfo->GetTac();
        infoAni.earfcn = lteCellInfo->GetArfcn();
        infoAni.bandwidth = 0;
        infoAni.mcc = lteCellInfo->GetMcc();
        infoAni.mnc = lteCellInfo->GetMnc();
        infoAni.is_support_endc = false;
    }
}

static void JudgmentDataNr(sptr<CellInformation> info, CellInformationAni &infoAni)
{
    auto nrCellCellInfo = static_cast<NrCellInformation *>(info.GetRefPtr());
    if (nrCellCellInfo != nullptr) {
        infoAni.nr_arfcn = nrCellCellInfo->GetArfcn();
        infoAni.pci = nrCellCellInfo->GetPci();
        infoAni.tac = nrCellCellInfo->GetTac();
        infoAni.nci = nrCellCellInfo->GetNci();
        infoAni.mcc = nrCellCellInfo->GetMcc();
        infoAni.mnc = nrCellCellInfo->GetMnc();
    }
}

static void JudgmentData(sptr<CellInformation> info, CellInformationAni &infoAni)
{
    switch (info->GetNetworkType()) {
        case CellInformation::CellType::CELL_TYPE_GSM: {
            JudgmentDataGsm(info, infoAni);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_CDMA: {
            JudgmentDataCdma(info, infoAni);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            JudgmentDataWcdma(info, infoAni);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
            JudgmentDataTdscdma(info, infoAni);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_LTE: {
            JudgmentDataLte(info, infoAni);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_NR: {
            JudgmentDataNr(info, infoAni);
            break;
        }
        default: {
            JudgmentDataGsm(info, infoAni);
            break;
        }
    }
}

static rust::Vec<CellInformationAni> ConvertCellInformation(const std::vector<sptr<CellInformation>> &cellInfo)
{
    rust::Vec<CellInformationAni> info{};
    for (auto &item : cellInfo) {
        CellInformationAni cell;
        cell.network_type = static_cast<int32_t>(item->GetNetworkType());
        cell.is_camped = item->GetIsCamped();
        cell.time_stamp = static_cast<int64_t>(item->GetTimeStamp());
        cell.signal_type = static_cast<int32_t>(item->GetNetworkType());
        cell.signal_level = item->GetSignalLevel();
        cell.dbm = item->GetSignalIntensity();
        JudgmentData(item, cell);
        info.push_back(cell);
    }

    return info;
}

ArktsError GetBasebandVersion(int32_t slotId, rust::String &basebandVersion)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getBasebandVersion", Permission::GET_TELEPHONY_STATE);
    }

    std::string version = "";
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetBasebandVersion(slotId, version);
    if (errorCode == TELEPHONY_SUCCESS) {
        basebandVersion = version;
    }

    return ConvertArktsErrorWithPermission(errorCode, "getBasebandVersion", Permission::GET_TELEPHONY_STATE);
}

ArktsError SetNrOptionMode(int32_t slotId, int32_t nrMode)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "setNrOptionMode", Permission::SET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetNrOptionMode(slotId, nrMode, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        TELEPHONY_LOGI("NativeGetNrOptionMode after callback end");
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "setNrOptionMode", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetNrOptionMode(int32_t slotId, int32_t &nrMode)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNrOptionMode(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        if (std::holds_alternative<int32_t>(context->result)) {
            nrMode = std::get<int32_t>(context->result);
        }
        errorCode = context->errorCode;
    }

    return ConvertArktsError(errorCode);
}

ArktsError SetNetworkCapability(int32_t slotId, int32_t capType, int32_t capState)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    if (!IsValidNetworkCapabilityType(capType) || !IsValidNetworkCapabilityState(capState)) {
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsError(errorCode);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetNetworkCapability(slotId, capType, capState);
    return ConvertArktsError(errorCode);
}

ArktsError GetNetworkCapability(int32_t slotId, int32_t capType, int32_t &capState)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkCapability", Permission::GET_TELEPHONY_STATE);
    }

    if (!IsValidNetworkCapabilityType(capType)) {
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkCapability", Permission::GET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkCapability(slotId, capType, capState);
    return ConvertArktsErrorWithPermission(errorCode, "getNetworkCapability", Permission::GET_TELEPHONY_STATE);
}

ArktsError FactoryReset(int32_t slotId)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "factoryReset", Permission::SET_TELEPHONY_STATE);
    }
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().FactoryReset(slotId);
    return ConvertArktsErrorWithPermission(errorCode, "factoryReset", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetRadioTech(int32_t slotId, int32_t &psRadioTech, int32_t &csRadioTech)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getRadioTech", Permission::GET_NETWORK_INFO);
    }

    psRadioTech = static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_UNKNOWN);
    csRadioTech = static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_UNKNOWN);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPsRadioTech(slotId, psRadioTech);
    if (errorCode != TELEPHONY_SUCCESS) {
        return ConvertArktsErrorWithPermission(errorCode, "getRadioTech", Permission::GET_NETWORK_INFO);
    }
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCsRadioTech(slotId, csRadioTech);
    return ConvertArktsErrorWithPermission(errorCode, "getRadioTech", Permission::GET_NETWORK_INFO);
}

ArktsError SendUpdateCellLocationRequest(int32_t slotId)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "sendUpdateCellLocationRequest", Permission::CELL_LOCATION);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendUpdateCellLocationRequest(slotId);
    return ConvertArktsErrorWithPermission(errorCode, "sendUpdateCellLocationRequest", Permission::CELL_LOCATION);
}

ArktsError GetCellInformation(int32_t slotId, rust::Vec<CellInformationAni> &cellInfoVec)
{
    cellInfoVec.clear();
    int errorCode;
    if (!IsValidSlotIdEx(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getCellInformation", Permission::GET_TELEPHONY_STATE);
    }

    std::vector<sptr<CellInformation>> cellInformations{};
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCellInfoList(slotId, cellInformations);
    TELEPHONY_LOGD("GetCellInformation len = %{public}lu", static_cast<unsigned long>(cellInformations.size()));
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetCellInformation errorCode = %{public}d", errorCode);
    } else {
        if (cellInformations.size() == 0) {
            TELEPHONY_LOGE("NativeGetCellInformation cellInformations is empty.");
            errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
        } else {
            cellInfoVec = ConvertCellInformation(cellInformations);
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "getCellInformation", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetNetworkSelectionMode(int32_t slotId, int32_t &networkSelectionMode)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSelectionMode(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        if (std::holds_alternative<int32_t>(context->result)) {
            auto mode = std::get<int32_t>(context->result);
            networkSelectionMode = ConvertSelectionMode(mode);
        }
        errorCode = context->errorCode;
    }

    return ConvertArktsError(errorCode);
}

ArktsError SetNetworkSelectionMode(int32_t slotId, int32_t mode, const NetworkInformationAni &info, bool selection)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "setNetworkSelectionMode", Permission::SET_TELEPHONY_STATE);
    }

    auto networkInfo = OHOS::sptr<NetworkInformation>::MakeSptr();
    networkInfo->SetOperateInformation(std::string(info.operator_name), "", std::string(info.operator_numeric),
        info.state, GetRatTechValue(std::string(info.radio_tech)));
    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetNetworkSelectionMode(slotId,
        ConvertEtsNetworkSelectionMode(mode), networkInfo, selection, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "setNetworkSelectionMode", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetNetworkSearchInformation(int32_t slotId, rust::Vec<NetworkInformationAni> &networkInfoVec)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkSearchInformation",
            Permission::GET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSearchInformation(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_NETWORK_MANUAL_SEARCH_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        
        std::vector<NetworkInformation> infoList;
        if (std::holds_alternative<sptr<NetworkSearchResult>>(context->result)) {
            auto result = std::get<sptr<NetworkSearchResult>>(context->result);
            if (result != nullptr) {
                infoList = result->GetNetworkSearchInformation();
            }
        }
        for (auto &item : infoList) {
            NetworkInformationAni info = {};
            info.operator_name = item.GetOperatorLongName();
            info.operator_numeric = item.GetOperatorNumeric();
            info.state = item.GetNetworkState();
            info.radio_tech = GetRadioTechName(item.GetRadioTech());
            networkInfoVec.push_back(info);
        }
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "getNetworkSearchInformation", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetIsoCountryCodeForNetwork(int32_t slotId, rust::String &countryCode)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string countryCodeStr = u"";
    errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIsoCountryCodeForNetwork(slotId, countryCodeStr);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        countryCode = NapiUtil::ToUtf8(countryCodeStr);
    }

    return ConvertArktsError(errorCode);
}

ArktsError GetImeiSv(int32_t slotId, rust::String &imeiSv)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getImeiSv", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string imeiSvStr = u"";
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImeiSv(slotId, imeiSvStr);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        imeiSv = NapiUtil::ToUtf8(imeiSvStr);
    }

    return ConvertArktsErrorWithPermission(errorCode, "getImeiSv", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetImei(int32_t slotId, rust::String &imei)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getImei", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string imeiStr = u"";
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImei(slotId, imeiStr);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        imei = NapiUtil::ToUtf8(imeiStr);
    }

    return ConvertArktsErrorWithPermission(errorCode, "getImei", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetMeid(int32_t slotId, rust::String &meid)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getMeid", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string meidStr = u"";
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMeid(slotId, meidStr);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        meid = NapiUtil::ToUtf8(meidStr);
    }

    return ConvertArktsErrorWithPermission(errorCode, "getMeid", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetUniqueDeviceId(int32_t slotId, rust::String &uniqueDeviceId)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getUniqueDeviceId", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string deviceIdStr = u"";
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetUniqueDeviceId(slotId, deviceIdStr);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        uniqueDeviceId = NapiUtil::ToUtf8(deviceIdStr);
    }

    return ConvertArktsErrorWithPermission(errorCode, "getUniqueDeviceId", Permission::GET_TELEPHONY_STATE);
}

ArktsError SetPrimarySlotId(int32_t slotId)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "setPrimarySlotId", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetPrimarySlotId(slotId);
    return ConvertArktsErrorWithPermission(errorCode, "setPrimarySlotId", Permission::SET_TELEPHONY_STATE);
}

ArktsError IsRadioOn(int32_t slotId, bool &isRadioOn)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "isRadioOn", Permission::GET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetRadioState(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        if (std::holds_alternative<bool>(context->result)) {
            isRadioOn = std::get<bool>(context->result);
        }
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "isRadioOn", Permission::GET_TELEPHONY_STATE);
}

ArktsError TurnOnRadio(int32_t slotId)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "turnOnRadio", Permission::SET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetRadioState(slotId, true, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        TELEPHONY_LOGI("SetRadioState after callback");
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "turnOnRadio", Permission::SET_TELEPHONY_STATE);
}

ArktsError TurnOffRadio(int32_t slotId)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "turnOffRadio", Permission::SET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetRadioState(slotId, false, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "turnOffRadio", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetOperatorName(int32_t slotId, rust::String &operatorName)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string operatorNameStr = u"";
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorName(slotId, operatorNameStr);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        operatorName = NapiUtil::ToUtf8(operatorNameStr);
    }

    return ConvertArktsError(errorCode);
}

ArktsError SetPreferredNetwork(int32_t slotId, int32_t preferredNetworkMode)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "setPreferredNetwork", Permission::SET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetPreferredNetwork(slotId, preferredNetworkMode,
        callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "setPreferredNetwork", Permission::SET_TELEPHONY_STATE);
}
ArktsError GetPreferredNetwork(int32_t slotId, int32_t &preferredNetworkMode)
{
    int errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getPreferredNetwork", Permission::GET_TELEPHONY_STATE);
    }

    auto context = std::make_shared<AniCallbackContext>();
    auto callback = OHOS::sptr<AniNetworkSearchCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> lock(context->callbackMutex);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPreferredNetwork(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackComplete; });
        if (std::holds_alternative<int32_t>(context->result)) {
            preferredNetworkMode = std::get<int32_t>(context->result);
        }
        errorCode = context->errorCode;
    }

    return ConvertArktsErrorWithPermission(errorCode, "getPreferredNetwork", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetImsRegInfo(int32_t slotId, int32_t imsSrvType, ImsRegInfoAni &imsRegInfo)
{
    int32_t errorCode;
    ImsRegInfo info;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getImsRegInfo",
                                               Permission::GET_TELEPHONY_STATE);
    }
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImsRegStatus(
        slotId, static_cast<ImsServiceType>(imsSrvType), info);
    if (errorCode == TELEPHONY_SUCCESS) {
        ims_reg_info_conversion(imsRegInfo, static_cast<int32_t>(info.imsRegState),
                                static_cast<int32_t>(info.imsRegTech));
    }

    return ConvertArktsErrorWithPermission(errorCode, "getImsRegInfo",
                                           Permission::GET_TELEPHONY_STATE);
}

enum class NetworkType : int32_t {
    NETWORK_TYPE_UNKNOWN,
    NETWORK_TYPE_GSM,
    NETWORK_TYPE_CDMA,
    NETWORK_TYPE_WCDMA,
    NETWORK_TYPE_TDSCDMA,
    NETWORK_TYPE_LTE,
    NETWORK_TYPE_NR
};

static int32_t WrapSignalInformationType(SignalInformation::NetworkType type)
{
    switch (type) {
        case SignalInformation::NetworkType::GSM:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_GSM);
        case SignalInformation::NetworkType::CDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_CDMA);
        case SignalInformation::NetworkType::LTE:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_LTE);
        case SignalInformation::NetworkType::WCDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_WCDMA);
        case SignalInformation::NetworkType::TDSCDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_TDSCDMA);
        case SignalInformation::NetworkType::NR:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_NR);
        default:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
    }
}

ArktsError GetSignalInformation(int32_t slotId, rust::Vec<SignalInformationAni> &signalInfoList)
{
    int32_t errorCode;
    std::vector<sptr<SignalInformation>> infoList;
    if (!IsValidSlotIdEx(slotId)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSignalInfoList(
        slotId, infoList);
    if (errorCode == TELEPHONY_SUCCESS) {
        for (sptr<SignalInformation> infoItem : infoList) {
            int32_t signalType = static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
            int32_t signalLevel = 0;
            int32_t signalIntensity = 0;
            if (infoItem != nullptr) {
                signalType = WrapSignalInformationType(infoItem->GetNetworkType());
                signalLevel = infoItem->GetSignalLevel();
                signalIntensity = infoItem->GetSignalIntensity();
            }
            signal_information_push_data(signalInfoList, signalType, signalLevel, signalIntensity);
        }
    }
    return ConvertArktsError(errorCode);
}

ArktsError GetNetworkState(int32_t slotId, NetworkStateAni &networkState)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    if (!IsValidSlotIdEx(slotId)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                               Permission::GET_NETWORK_INFO);
    }

    sptr<NetworkState> state = nullptr;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkState(slotId, state);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Ani GetNetworkState errorCode = %{public}d", errorCode);
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                               Permission::GET_NETWORK_INFO);
    }

    if (state == nullptr) {
        TELEPHONY_LOGE("Ani GetNetworkState networkState is nullptr");
        errorCode = ERROR_NATIVE_API_EXECUTE_FAIL;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                               Permission::GET_NETWORK_INFO);
    }

    networkState.long_operator_name = rust::String(state->GetLongOperatorName());
    networkState.short_operator_name = rust::String(state->GetShortOperatorName());
    networkState.plmn_numeric = rust::String(state->GetPlmnNumeric());
    networkState.is_roaming = state->IsRoaming(),
    networkState.reg_state = static_cast<int32_t>(state->GetRegStatus());
    networkState.cfg_tech = static_cast<int32_t>(state->GetCfgTech());
    networkState.is_emergency = state->IsEmergency();
    return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                           Permission::GET_NETWORK_INFO);
}

bool IsNrSupported()
{
    TelephonyConfig telephonyConfig;
    bool isNrSupported = telephonyConfig.IsCapabilitySupport(
        static_cast<int32_t>(TelephonyConfig::ConfigType::MODEM_CAP_SUPPORT_NR));
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_EXT
    TELEPHONY_EXT_UTILS_WRAPPER.InitTelephonyExtUtilsWrapper();
    if (TELEPHONY_EXT_UTILS_WRAPPER.isChipsetNrSupported_ != nullptr) {
        isNrSupported = isNrSupported && TELEPHONY_EXT_UTILS_WRAPPER.isChipsetNrSupported_();
    }
#endif
    return isNrSupported;
}

ArktsError GetPrimarySlotId(int32_t &slotId)
{
    int32_t errorCode;
    int32_t id = 0;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId(id);
    if (errorCode == TELEPHONY_SUCCESS) {
        slotId = id;
    }
    return ConvertArktsError(errorCode);
}

int32_t AniImsRegInfoCallback::OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType,
                                                   const ImsRegInfo &info)
{
    on_ims_reg_info_change(slotId, static_cast<int32_t>(imsSrvType),
        static_cast<int32_t>(info.imsRegState), static_cast<int32_t>(info.imsRegTech));
    return TELEPHONY_SUCCESS;
}

static bool IsValidImsSrvType(int32_t imsSrvType)
{
    bool flag = true;
    switch (imsSrvType) {
        case ImsServiceType::TYPE_VOICE:
        case ImsServiceType::TYPE_VIDEO:
        case ImsServiceType::TYPE_UT:
        case ImsServiceType::TYPE_SMS:
            break;
        default:
            TELEPHONY_LOGE("imsSrvType %{public}d is invalid", imsSrvType);
            flag = false;
            break;
    }

    return flag;
}

ArktsError EventListenerRegister(int32_t slotId, int32_t imsSrvType)
{
    int32_t errorCode;
    if (!IsValidSlotIdEx(slotId) || !IsValidImsSrvType(imsSrvType)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "on_imsRegStateChange",
                                               Permission::GET_NETWORK_INFO);
    }

    sptr<ImsRegInfoCallback> imsCallback = new AniImsRegInfoCallback();
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().RegisterImsRegInfoCallback(
        slotId, static_cast<ImsServiceType>(imsSrvType), imsCallback);

    return ConvertArktsErrorWithPermission(errorCode, "on_imsRegStateChange",
                                           Permission::GET_TELEPHONY_STATE);
}

ArktsError EventListenerUnRegister(int32_t slotId, int32_t imsSrvType)
{
    int32_t errorCode;
    if (!IsValidSlotIdEx(slotId) || !IsValidImsSrvType(imsSrvType)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "off_imsRegStateChange",
                                               Permission::GET_NETWORK_INFO);
    }
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance()
        .UnregisterImsRegInfoCallback(slotId, static_cast<ImsServiceType>(imsSrvType));
    return ConvertArktsErrorWithPermission(errorCode, "off_imsRegStateChange",
                                           Permission::GET_TELEPHONY_STATE);
}

} // namespace RadioAni
} // namespace Telephony
} // namespace OHOS
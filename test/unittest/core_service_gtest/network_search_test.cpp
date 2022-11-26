/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "network_search_test.h"

#include "accesstoken_kit.h"
#include "cell_location.h"
#include "ims_reg_info_callback_gtest.h"
#include "iservice_registry.h"
#include "network_search_test_callback_stub.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
#ifndef TEL_TEST_UNSUPPORT
constexpr int32_t SLOT_ID = 0;
constexpr int32_t SLOT_ID1 = 1;
constexpr ImsServiceType DEFAULT_TYPE = TYPE_VOICE;
constexpr int32_t INVALID_SLOT_ID = -1;
constexpr int32_t INVALID_TYPE = -1;
constexpr int32_t WAIT_TIME_SECOND_LONG = 60;
#endif // TEL_TEST_UNSUPPORT

sptr<ICoreService> NetworkSearchTest::telephonyService_ = nullptr;
std::list<ImsRegStateCallback> NetworkSearchTest::imsRegStateCallbackList_;
void NetworkSearchTest::SetUpTestCase()
{
    TELEPHONY_LOGI("----------NetworkSearch gtest start ------------");
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    TELEPHONY_LOGI("NetworkSearch connect coreservice  server success!!!");
}

void NetworkSearchTest::TearDownTestCase()
{
    TELEPHONY_LOGI("----------NetworkSearch gtest end ------------");
}

void NetworkSearchTest::SetUp() {}

void NetworkSearchTest::TearDown() {}

sptr<ICoreService> NetworkSearchTest::GetProxy()
{
    TELEPHONY_LOGI("TelephonyTestService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Get ISystemAbilityManager failed!!!");
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        return telephonyService;
    } else {
        TELEPHONY_LOGI("TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ...");
        return nullptr;
    }
}

void NetworkSearchTest::PrintCellInformation(std::vector<sptr<CellInformation>> cellList)
{
    for (const auto &cell : cellList) {
        switch (cell->GetNetworkType()) {
            case CellInformation::CellType::CELL_TYPE_GSM: {
                PrintGsmCellInformation(cell);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_CDMA: {
                PrintCdmaCellInformation(cell);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_WCDMA: {
                PrintWcdmaCellInformation(cell);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
                PrintTdscdmaCellInformation(cell);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_LTE: {
                PrintLteCellInformation(cell);
                break;
            }
            case CellInformation::CellType::CELL_TYPE_NR: {
                PrintNrCellInformation(cell);
                break;
            }
            default:
                TELEPHONY_LOGE("CellInformation::CellType type error");
                break;
        }
    }
    sptr<LteCellInformation> cellLte = new LteCellInformation();
    Parcel parcel;
    cellLte->Unmarshalling(parcel);
    cellLte->Init(atoi(cellLte->GetMcc().c_str()), atoi(cellLte->GetMnc().c_str()), cellLte->GetCellId());
    cellLte->GetTimeStamp();
    cellLte->GetSignalLevel();
    cellLte->GetIsCamped();
    cellLte->SetIsCamped(false);
    cellLte->SetSignalLevel(0);
}

void NetworkSearchTest::PrintGsmCellInformation(sptr<CellInformation> cell)
{
    GsmCellInformation *gsm = reinterpret_cast<GsmCellInformation *>(cell.GetRefPtr());
    TELEPHONY_LOGD("CellInformation type:%{private}d, lac:%{private}d, bsic:%{private}d, arfcn:%{private}d",
        static_cast<int32_t>(gsm->GetNetworkType()), gsm->GetLac(), gsm->GetBsic(), gsm->GetArfcn());
    TELEPHONY_LOGI("CellInformation result:%{public}s", gsm->ToString().c_str());

    MessageParcel data;
    gsm->Marshalling(data);
    gsm->Unmarshalling(data);
    sptr<GsmCellInformation> gsmCell = new GsmCellInformation;
    gsmCell->UpdateLocation(0, 0);
    gsmCell->SetGsmParam(0, 0, 0);
    GsmCellInformation gsmCellInformation = *gsm;
    TELEPHONY_LOGI("CellInformation gsm is same as gsmCell:%{public}d", *gsmCell == gsmCellInformation);
    gsmCell->Init(0, 0, 0);

    sptr<GsmCellLocation> cellLocation = new GsmCellLocation;
    MessageParcel locationData;
    cellLocation->Marshalling(locationData);
    cellLocation->Unmarshalling(locationData);
    cellLocation->SetGsmParam(gsm->GetCellId(), gsm->GetLac());
    TELEPHONY_LOGD("GsmCellLocation type:%{private}d, lac:%{private}d, psc:%{private}d,",
        static_cast<int32_t>(cellLocation->GetCellLocationType()), cellLocation->GetLac(), cellLocation->GetPsc());

    sptr<GsmCellLocation> newCellLocation = new GsmCellLocation();
    Parcel parcel;
    newCellLocation->Unmarshalling(parcel);
    newCellLocation->GetTimeStamp();
}

void NetworkSearchTest::PrintCdmaCellInformation(sptr<CellInformation> cell)
{
    CdmaCellInformation *cdma = reinterpret_cast<CdmaCellInformation *>(cell.GetRefPtr());
    TELEPHONY_LOGD("CellInformation type:%{private}d, baseId:%{private}d, latitude:%{private}d, longitude:%{private}d"
        "nid:%{private}d, sid:%{private}d", static_cast<int32_t>(cdma->GetNetworkType()), cdma->GetBaseId(),
        cdma->GetLatitude(), cdma->GetLongitude(), cdma->GetNid(), cdma->GetSid());
    TELEPHONY_LOGI("CellInformation result:%{public}s", cdma->ToString().c_str());

    MessageParcel data;
    cdma->Marshalling(data);
    cdma->Unmarshalling(data);
    sptr<CdmaCellInformation> cdmaCell = new CdmaCellInformation;
    cdmaCell->UpdateLocation(0, 0, 0);
    cdmaCell->SetCdmaParam(0, 0, 0, 0, 0);
    CdmaCellInformation cdmaCellInformation = *cdma;
    TELEPHONY_LOGI("CellInformation cdma is same as cdmaCell:%{public}d", *cdmaCell == cdmaCellInformation);
    sptr<CdmaCellLocation> cellLocation = new CdmaCellLocation;
    MessageParcel locationData;
    cellLocation->Marshalling(locationData);
    cellLocation->Unmarshalling(locationData);
    cellLocation->SetCdmaParam(cdma->GetBaseId(), cdma->GetLatitude(), cdma->GetLongitude(), cdma->GetNid(),
        cdma->GetSid());
    TELEPHONY_LOGD(
        "CdmaCellLocation type:%{private}d, BaseId:%{private}d, Latitude:%{private}d, Longitude:%{private}d,"
        "Nid:%{private}d, Sid:%{private}d",
        static_cast<int32_t>(cellLocation->GetCellLocationType()), cellLocation->GetBaseId(),
        cellLocation->GetLatitude(), cellLocation->GetLongitude(), cellLocation->GetNid(), cellLocation->GetSid());
}

void NetworkSearchTest::PrintWcdmaCellInformation(sptr<CellInformation> cell)
{
    WcdmaCellInformation *wcdma = reinterpret_cast<WcdmaCellInformation *>(cell.GetRefPtr());
    TELEPHONY_LOGD("CellInformation type:%{private}d, psc:%{private}d, lac:%{private}d, arfcn:%{private}d",
        static_cast<int32_t>(wcdma->GetNetworkType()), wcdma->GetPsc(), wcdma->GetLac(), wcdma->GetArfcn());
    TELEPHONY_LOGI("CellInformation result:%{public}s", wcdma->ToString().c_str());
    MessageParcel data;
    wcdma->Marshalling(data);
    wcdma->Unmarshalling(data);
    sptr<WcdmaCellInformation> wcdmaCell = new WcdmaCellInformation();
    wcdmaCell->UpdateLocation(0, 0);
    wcdmaCell->SetWcdmaParam(0, 0, 0);
    WcdmaCellInformation wcdmaCellInformation = *wcdma;
    TELEPHONY_LOGI("CellInformation wcdma is same as wcdmaCell:%{public}d", *wcdmaCell == wcdmaCellInformation);
}

void NetworkSearchTest::PrintTdscdmaCellInformation(sptr<CellInformation> cell)
{
    TdscdmaCellInformation *tdscdma = reinterpret_cast<TdscdmaCellInformation *>(cell.GetRefPtr());
    TELEPHONY_LOGD("CellInformation type:%{private}d, cpid:%{private}d, lac:%{private}d, arfcn:%{private}d",
        static_cast<int32_t>(tdscdma->GetNetworkType()), tdscdma->GetCpid(), tdscdma->GetLac(), tdscdma->GetArfcn());
    TELEPHONY_LOGI("CellInformation result:%{public}s", tdscdma->ToString().c_str());
    MessageParcel data;
    tdscdma->Marshalling(data);
    tdscdma->Unmarshalling(data);
    sptr<TdscdmaCellInformation> tdscdmaCell = new TdscdmaCellInformation;
    tdscdmaCell->UpdateLocation(0, 0);
    tdscdmaCell->SetTdscdmaParam(0, 0, 0);
    TdscdmaCellInformation tdscdmaCellInformation = *tdscdma;
    TELEPHONY_LOGI("CellInformation tdscdma is same as tdscdmaCell:%{public}d", *tdscdmaCell == tdscdmaCellInformation);
}

void NetworkSearchTest::PrintLteCellInformation(sptr<CellInformation> cell)
{
    LteCellInformation *lte = reinterpret_cast<LteCellInformation *>(cell.GetRefPtr());
    TELEPHONY_LOGD("CellInformation type:%{private}d, pci:%{private}d, tac:%{private}d, arfcn:%{private}d",
        static_cast<int32_t>(lte->GetNetworkType()), lte->GetPci(), lte->GetTac(), lte->GetArfcn());
    TELEPHONY_LOGI("CellInformation result:%{public}s", lte->ToString().c_str());
    MessageParcel data;
    lte->Marshalling(data);
    lte->Unmarshalling(data);
    sptr<LteCellInformation> lteCell = new LteCellInformation;
    lteCell->UpdateLocation(0, 0);
    lteCell->SetLteParam(0, 0, 0);
    LteCellInformation lteCellInformation = *lte;
    TELEPHONY_LOGI("CellInformation lte is same as lteCell:%{public}d", *lteCell == *lte);
}

void NetworkSearchTest::PrintNrCellInformation(sptr<CellInformation> cell)
{
    NrCellInformation *nr = reinterpret_cast<NrCellInformation *>(cell.GetRefPtr());
    TELEPHONY_LOGD("CellInformation type:%{private}d, pci:%{private}d, tac:%{private}d, arfcn:%{private}d,"
        "nci:%{private}d", static_cast<int32_t>(nr->GetNetworkType()), nr->GetPci(), nr->GetTac(),
        nr->GetArfcn(), (int32_t)nr->GetNci());
    TELEPHONY_LOGI("CellInformation result:%{public}s", nr->ToString().c_str());
    MessageParcel data;
    nr->Marshalling(data);
    nr->Unmarshalling(data);
    sptr<NrCellInformation> nrCell = new NrCellInformation;
    nrCell->UpdateLocation(0, 0);
    nrCell->SetNrParam(0, 0, 0, 0);
    NrCellInformation nrCellInformation = *nr;
    TELEPHONY_LOGI("CellInformation nr is same as nrCell:%{public}d", *nrCell == nrCellInformation);
}

void NetworkSearchTest::PrintSignalInformation(std::vector<sptr<SignalInformation>> signalList)
{
    for (const auto &signal : signalList) {
        switch (signal->GetNetworkType()) {
            case SignalInformation::NetworkType::GSM: {
                PrintGsmSignalInformation(signal);
                break;
            }
            case SignalInformation::NetworkType::CDMA: {
                PrintCdmaSignalInformation(signal);
                break;
            }
            case SignalInformation::NetworkType::WCDMA: {
                PrintWcdmaSignalInformation(signal);
                break;
            }
            case SignalInformation::NetworkType::TDSCDMA: {
                PrintTdScdmaSignalInformation(signal);
                break;
            }
            case SignalInformation::NetworkType::LTE: {
                PrintLteSignalInformation(signal);
                break;
            }
            case SignalInformation::NetworkType::NR: {
                PrintNrSignalInformation(signal);
                break;
            }
            default:
                TELEPHONY_LOGE("SignalInformation::NetworkType type error");
                break;
        }
    }
}

void NetworkSearchTest::PrintGsmSignalInformation(sptr<SignalInformation> signal)
{
    GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(signal.GetRefPtr());
    TELEPHONY_LOGI("SignalInformation type:%{public}d, rssi:%{public}d, gsmBer:%{public}d, signalLevel:%{public}d,"
        "value:%{public}d", static_cast<int32_t>(gsm->GetNetworkType()), gsm->GetRssi(), gsm->GetGsmBer(),
        gsm->GetSignalLevel(), gsm->ValidateGsmValue());
    sptr<GsmSignalInformation> gsmSignal = new GsmSignalInformation;
    MessageParcel data;
    gsmSignal->Marshalling(data);
    gsmSignal->Unmarshalling(data);
    gsmSignal->SetValue(0, 0);
    TELEPHONY_LOGI("SignalInformation gsm is same as gsmSignal:%{public}d", *gsmSignal == *gsm);
}

void NetworkSearchTest::PrintCdmaSignalInformation(sptr<SignalInformation> signal)
{
    CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(signal.GetRefPtr());
    TELEPHONY_LOGI("SignalInformation type:%{public}d, cdmaRssi:%{public}d, signalLevel:%{public}d, value:%{public}d",
        static_cast<int32_t>(cdma->GetNetworkType()), cdma->GetCdmaRssi(), cdma->GetSignalLevel(),
        cdma->ValidateCdmaValue());
    sptr<CdmaSignalInformation> cdmaSignal = new CdmaSignalInformation;
    cdmaSignal->NewInstance();
    MessageParcel data;
    cdmaSignal->Marshalling(data);
    cdmaSignal->Unmarshalling(data);
    cdmaSignal->SetValue(0, 0);
    TELEPHONY_LOGI("SignalInformation cdma is same as cdmaSignal:%{public}d", *cdmaSignal == *cdma);
}

void NetworkSearchTest::PrintWcdmaSignalInformation(sptr<SignalInformation> signal)
{
    WcdmaSignalInformation *wcdma = reinterpret_cast<WcdmaSignalInformation *>(signal.GetRefPtr());
    TELEPHONY_LOGI("SignalInformation type:%{public}d, Rxlev:%{public}d, Rscp:%{public}d, Ecno:%{public}d,"
        "Ber:%{public}d, signalLevel:%{public}d, value:%{public}d", static_cast<int32_t>(wcdma->GetNetworkType()),
        wcdma->GetRxlev(), wcdma->GetRscp(), wcdma->GetEcno(), wcdma->GetBer(), wcdma->GetSignalLevel(),
        wcdma->ValidateWcdmaValue());
    sptr<WcdmaSignalInformation> wcdmaSignal = new WcdmaSignalInformation;
    wcdmaSignal->NewInstance();
    MessageParcel data;
    wcdmaSignal->Marshalling(data);
    wcdmaSignal->Unmarshalling(data);
    wcdmaSignal->SetValue(0, 0, 0, 0);
    TELEPHONY_LOGI("SignalInformation wcdma is same as wcdmaSignal:%{public}d", *wcdmaSignal == *wcdma);
}

void NetworkSearchTest::PrintTdScdmaSignalInformation(sptr<SignalInformation> signal)
{
    TdScdmaSignalInformation *tdscdma = reinterpret_cast<TdScdmaSignalInformation *>(signal.GetRefPtr());
    TELEPHONY_LOGI("SignalInformation type:%{public}d, Rscp:%{public}d, signalLevel:%{public}d, value:%{public}d",
        static_cast<int32_t>(tdscdma->GetNetworkType()), tdscdma->GetRscp(), tdscdma->GetSignalLevel(),
        tdscdma->ValidateTdScdmaValue());
    sptr<TdScdmaSignalInformation> tdscdmaSignal = new TdScdmaSignalInformation;
    tdscdmaSignal->NewInstance();
    MessageParcel data;
    tdscdmaSignal->Marshalling(data);
    tdscdmaSignal->Unmarshalling(data);
    tdscdmaSignal->SetValue(0);
    TELEPHONY_LOGI("SignalInformation tdscdma is same as tdscdmaSignal:%{public}d", *tdscdmaSignal == *tdscdma);
}

void NetworkSearchTest::PrintLteSignalInformation(sptr<SignalInformation> signal)
{
    LteSignalInformation *lte = reinterpret_cast<LteSignalInformation *>(signal.GetRefPtr());
    TELEPHONY_LOGI("SignalInformation type:%{public}d, Rxlev:%{public}d, Rsrp:%{public}d, Rsrq:%{public}d,"
        "Snr:%{public}d, signalLevel:%{public}d, value:%{public}d", static_cast<int32_t>(lte->GetNetworkType()),
        lte->GetRxlev(), lte->GetRsrp(), lte->GetRsrq(), lte->GetSnr(), lte->GetSignalLevel(),
        lte->ValidateLteValue());
    sptr<LteSignalInformation> lteSignal = new LteSignalInformation;
    MessageParcel data;
    lteSignal->Marshalling(data);
    lteSignal->Unmarshalling(data);
    lteSignal->SetValue(0, 0, 0, 0);
    TELEPHONY_LOGI("SignalInformation lte is same as lteSignal:%{public}d", *lteSignal == *lte);
}

void NetworkSearchTest::PrintNrSignalInformation(sptr<SignalInformation> signal)
{
    NrSignalInformation *nr = reinterpret_cast<NrSignalInformation *>(signal.GetRefPtr());
    TELEPHONY_LOGI("SignalInformation type:%{public}d, Rsrp:%{public}d, Rsrq:%{public}d, Sinr:%{public}d,"
        "SignalLevel:%{public}d, value:%{public}d", static_cast<int32_t>(nr->GetNetworkType()), nr->GetRsrp(),
        nr->GetRsrq(), nr->GetSinr(), nr->GetSignalLevel(), nr->ValidateNrValue());
    sptr<NrSignalInformation> nrSignal = new NrSignalInformation;
    nrSignal->NewInstance();
    MessageParcel data;
    nrSignal->Marshalling(data);
    nrSignal->Unmarshalling(data);
    nrSignal->SetValue(0, 0, 0);
    TELEPHONY_LOGI("SignalInformation nr is same as nrSignal:%{public}d", *nrSignal == *nr);
}

void NetworkSearchTest::PrintNetworkStateInformation(sptr<NetworkState> result)
{
    TELEPHONY_LOGI("NetworkState PsRegStatus:%{public}d, CsRegStatus:%{public}d, PsRoamingStatus:%{public}d,"
        "CsRoamingStatus:%{public}d, PsRadioTech:%{public}d, CsRadioTech:%{public}d, NrState:%{public}d,"
        "CfgTech:%{public}d, IsEmergency:%{public}d, IsRoaming:%{public}d",
        static_cast<int32_t>(result->GetPsRegStatus()), static_cast<int32_t>(result->GetCsRegStatus()),
        static_cast<int32_t>(result->GetPsRoamingStatus()), static_cast<int32_t>(result->GetCsRoamingStatus()),
        static_cast<int32_t>(result->GetPsRadioTech()), static_cast<int32_t>(result->GetCsRadioTech()),
        static_cast<int32_t>(result->GetNrState()), static_cast<int32_t>(result->GetCfgTech()), result->IsEmergency(),
        result->IsRoaming());
    sptr<NetworkState> networkState = new NetworkState;
    result->SetOperatorInfo("", "", "", DomainType::DOMAIN_TYPE_CS);
    result->SetEmergency(true);
    result->SetNetworkType(RadioTech::RADIO_TECHNOLOGY_LTE, DomainType::DOMAIN_TYPE_CS);
    result->SetRoaming(RoamingType::ROAMING_STATE_UNKNOWN, DomainType::DOMAIN_TYPE_CS);
    result->SetNetworkState(RegServiceState::REG_STATE_POWER_OFF, DomainType::DOMAIN_TYPE_CS);
    result->SetNrState(NrState::NR_STATE_NOT_SUPPORT);
    result->SetCfgTech(RadioTech::RADIO_TECHNOLOGY_LTE);
    TELEPHONY_LOGI("NetworkState result is same as networkState:%{public}d", *result == *networkState);
}

#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_NetworkSearch_GetPsRadioTech_0100
 * @tc.name     Get RAT of the PS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetPsRadioTech_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().GetPsRadioTech(SLOT_ID);
        TELEPHONY_LOGI("TelephonyTestService GetPsRadioTech result: %{public}d", result);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetPsRadioTech_0200
 * @tc.name     Get RAT of the PS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetPsRadioTech_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().GetPsRadioTech(SLOT_ID1);
        TELEPHONY_LOGI("TelephonyTestService GetPsRadioTech result: %{public}d", result);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetPsRadioTech_0300
 * @tc.name     Get RAT of the PS domain on the registered network without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetPsRadioTech_0300, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    int32_t result = CoreServiceClient::GetInstance().GetPsRadioTech(SLOT_ID);
    TELEPHONY_LOGI("TelephonyTestService GetPsRadioTech result: %{public}d", result);
    EXPECT_EQ(TELEPHONY_ERR_PERMISSION_ERR, result);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0100
 * @tc.name     Get RAT of the CS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCsRadioTech_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().GetCsRadioTech(SLOT_ID);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0200
 * @tc.name     Get RAT of the CS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCsRadioTech_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().GetCsRadioTech(SLOT_ID1);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0300
 * @tc.name     Get RAT of the CS domain on the registered network without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCsRadioTech_0300, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    int32_t result = CoreServiceClient::GetInstance().GetCsRadioTech(SLOT_ID);
    EXPECT_EQ(TELEPHONY_ERR_PERMISSION_ERR, result);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkState_0100
 * @tc.name     Get Network State
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkState_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkState> result = CoreServiceClient::GetInstance().GetNetworkState(SLOT_ID);
        if (result == nullptr) {
            TELEPHONY_LOGI("GetNetworkState result is null");
        } else {
            EXPECT_GT(static_cast<int32_t>(result->GetRegStatus()), -1);
            EXPECT_STRNE(result->GetLongOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetShortOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetPlmnNumeric().c_str(), "");
            PrintNetworkStateInformation(result);
            sptr<NetworkState> newState = new NetworkState();
            Parcel parcel;
            newState->Unmarshalling(parcel);
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkState_0200
 * @tc.name     Get Network State
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkState_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkState> result = CoreServiceClient::GetInstance().GetNetworkState(SLOT_ID1);
        if (result == nullptr) {
            TELEPHONY_LOGI("GetNetworkState result is null");
        } else {
            EXPECT_GT(static_cast<int32_t>(result->GetRegStatus()), -1);
            EXPECT_STRNE(result->GetLongOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetShortOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetPlmnNumeric().c_str(), "");
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkState_0300
 * @tc.name     Get Network State without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkState_0300, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkState> result = CoreServiceClient::GetInstance().GetNetworkState(SLOT_ID);
    ASSERT_TRUE(result == nullptr);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorNumeric_0100
 * @tc.name     Get Operator Numeric of PLMN
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorNumeric_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetOperatorNumeric(SLOT_ID);
        std::string plmn = Str16ToStr8(result);
        EXPECT_STRNE(plmn.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorNumeric_0200
 * @tc.name     Get Operator Numeric of PLMN
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorNumeric_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetOperatorNumeric(SLOT_ID1);
        std::string plmn = Str16ToStr8(result);
        EXPECT_STRNE(plmn.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorName_0100
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorName_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetOperatorName(SLOT_ID);
        std::string operatorName = Str16ToStr8(result);
        EXPECT_STRNE(operatorName.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorName_0200
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorName_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetOperatorName(SLOT_ID1);
        std::string operatorName = Str16ToStr8(result);
        EXPECT_STRNE(operatorName.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetSignalInfoList_0100
 * @tc.name     Get Signal Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetSignalInfoList_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        auto result = CoreServiceClient::GetInstance().GetSignalInfoList(SLOT_ID);
        SignalInformation::NetworkType type;
        for (const auto &v : result) {
            type = v->GetNetworkType();
            if (type == SignalInformation::NetworkType::GSM) {
                GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(gsm->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::CDMA) {
                CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(cdma->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::LTE) {
                LteSignalInformation *lte = reinterpret_cast<LteSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(lte->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::WCDMA) {
                WcdmaSignalInformation *wcdma = reinterpret_cast<WcdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(wcdma->ToString().c_str(), "");
            }
        }
        PrintSignalInformation(result);
        sptr<LteSignalInformation> singalLte = new LteSignalInformation();
        Parcel parcel;
        singalLte->Unmarshalling(parcel);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetSignalInfoList_0200
 * @tc.name     Get Signal Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetSignalInfoList_0200, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        auto result = CoreServiceClient::GetInstance().GetSignalInfoList(SLOT_ID1);
        SignalInformation::NetworkType type;
        for (const auto &v : result) {
            type = v->GetNetworkType();
            if (type == SignalInformation::NetworkType::GSM) {
                GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(gsm->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::CDMA) {
                CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(cdma->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::LTE) {
                LteSignalInformation *lte = reinterpret_cast<LteSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(lte->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::WCDMA) {
                WcdmaSignalInformation *wcdma = reinterpret_cast<WcdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(wcdma->ToString().c_str(), "");
            }
        }
        PrintSignalInformation(result);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_PrintSignalInfo_0100
 * @tc.name     Get Signal Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_PrintSignalInfo_0100, Function | MediumTest | Level3)
{
    sptr<GsmSignalInformation> gsm = new GsmSignalInformation();
    EXPECT_STRNE(gsm->ToString().c_str(), "");
    PrintGsmSignalInformation(gsm);

    sptr<WcdmaSignalInformation> wcdma = new WcdmaSignalInformation();
    EXPECT_STRNE(wcdma->ToString().c_str(), "");
    PrintWcdmaSignalInformation(wcdma);

    sptr<TdScdmaSignalInformation> tsScdma = new TdScdmaSignalInformation();
    EXPECT_STRNE(tsScdma->ToString().c_str(), "");
    PrintTdScdmaSignalInformation(tsScdma);

    sptr<NrSignalInformation> nr = new NrSignalInformation();
    EXPECT_STRNE(nr->ToString().c_str(), "");
    PrintNrSignalInformation(nr);

    sptr<LteSignalInformation> lte = new LteSignalInformation();
    EXPECT_STRNE(lte->ToString().c_str(), "");
    PrintLteSignalInformation(lte);

    sptr<CdmaSignalInformation> cdma = new CdmaSignalInformation();
    EXPECT_STRNE(cdma->ToString().c_str(), "");
    PrintCdmaSignalInformation(cdma);

    sptr<NetworkSearchResult> networkSearchResult = new NetworkSearchResult();
    networkSearchResult->GetNetworkSearchInformation();
    networkSearchResult->GetNetworkSearchInformationSize();
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCellInfoList_0100
 * @tc.name     Get Cell Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCellInfoList_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::vector<sptr<CellInformation>> cellList = CoreServiceClient::GetInstance().GetCellInfoList(SLOT_ID);
    PrintCellInformation(cellList);
    ASSERT_TRUE(!cellList.empty());
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCellInfoList_0200
 * @tc.name     Get Cell Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCellInfoList_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::vector<sptr<CellInformation>> cellList = CoreServiceClient::GetInstance().GetCellInfoList(SLOT_ID1);
    PrintCellInformation(cellList);
    ASSERT_TRUE(!cellList.empty());
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCellInfoList_0300
 * @tc.name     Get Cell Info List without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCellInfoList_0300, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::vector<sptr<CellInformation>> cellList = CoreServiceClient::GetInstance().GetCellInfoList(SLOT_ID);
    PrintCellInformation(cellList);
    ASSERT_TRUE(cellList.empty());
}

/**
 * @tc.number   Telephony_NetworkSearch_PrintCellInfoList_0100
 * @tc.name     Get Cell Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_PrintCellInfoList_0100, Function | MediumTest | Level3)
{
    sptr<GsmCellInformation> gsm = new GsmCellInformation();
    EXPECT_STRNE(gsm->ToString().c_str(), "");
    PrintGsmCellInformation(gsm);

    sptr<CdmaCellInformation> cdma = new CdmaCellInformation();
    EXPECT_STRNE(cdma->ToString().c_str(), "");
    PrintCdmaCellInformation(cdma);

    sptr<WcdmaCellInformation> wcdma = new WcdmaCellInformation();
    EXPECT_STRNE(wcdma->ToString().c_str(), "");
    PrintWcdmaCellInformation(wcdma);

    sptr<TdscdmaCellInformation> tdscdma = new TdscdmaCellInformation();
    EXPECT_STRNE(tdscdma->ToString().c_str(), "");
    PrintTdscdmaCellInformation(tdscdma);

    sptr<LteCellInformation> lte = new LteCellInformation();
    EXPECT_STRNE(lte->ToString().c_str(), "");
    PrintLteCellInformation(lte);

    sptr<NrCellInformation> nr = new NrCellInformation();
    EXPECT_STRNE(nr->ToString().c_str(), "");
    PrintNrCellInformation(nr);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0100
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetIsoCountryCodeForNetwork(SLOT_ID);
        std::string countryCode = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetIsoCountryCodeForNetwork countryCode: %{public}s", countryCode.c_str());
        EXPECT_STRNE(countryCode.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0200
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetIsoCountryCodeForNetwork(SLOT_ID1);
        std::string countryCode = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetIsoCountryCodeForNetwork countryCode: %{public}s", countryCode.c_str());
        EXPECT_STRNE(countryCode.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0100
 * @tc.name     Set Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }

    sptr<NetworkInformation> newNetworkInfo = new (std::nothrow) NetworkInformation();
    newNetworkInfo->SetOperateInformation(newNetworkInfo->GetOperatorLongName(), newNetworkInfo->GetOperatorShortName(),
        "46000", newNetworkInfo->GetNetworkState(), newNetworkInfo->GetRadioTech());

    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation(
        "CHINA MOBILE", "CMCC", "46000", static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0200
 * @tc.name     Set Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0300
 * @tc.name     Set Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0300, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0400
 * @tc.name     Set Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0500
 * @tc.name     Set Auto Network Selection Mode without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0500, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_FALSE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0100
 * @tc.name     Get Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0100 SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0100 SetNetworkModeCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetNetworkSelectionMode(SLOT_ID, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0100 GetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0100 GetNetworkModeCallbackResult mode: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL));
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0200
 * @tc.name     Get Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0200 SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0200 SetNetworkModeCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetNetworkSelectionMode(SLOT_ID, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0200 GetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0200 GetNetworkModeCallbackResult mode: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO));
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0300
 * @tc.name     Get Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0300, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0300 SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0300 SetNetworkModeCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetNetworkSelectionMode(SLOT_ID1, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0300 GetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0300 GetNetworkModeCallbackResult mode: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL));
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0400
 * @tc.name     Get Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0400 SetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0400 SetNetworkModeCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetNetworkSelectionMode(SLOT_ID1, callback);
    TELEPHONY_LOGI("GetNetworkSelectionMode_0400 GetNetworkSelectionMode result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("GetNetworkSelectionMode_0400 GetNetworkModeCallbackResult mode: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO));
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0100
 * @tc.name     Set Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID, false, callback);
    TELEPHONY_LOGI("SetRadioState_0100 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("SetRadioState_0100 SetRadioStateCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0200
 * @tc.name     Set Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID, true, callback);
    TELEPHONY_LOGI("SetRadioState_0200 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("SetRadioState_0200 SetRadioStateCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0300
 * @tc.name     Set Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0300, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID1, false, callback);
    TELEPHONY_LOGI("SetRadioState_0300 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("SetRadioState_0300 SetRadioStateCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0400
 * @tc.name     Set Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID1, true, callback);
    TELEPHONY_LOGI("SetRadioState_0400 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("SetRadioState_0400 SetRadioStateCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0500
 * @tc.name     Set radio state off without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0500, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID, false, callback);
    TELEPHONY_LOGI("SetRadioState_0100 SetRadioState result: %{public}d", result);
    ASSERT_FALSE(result);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0100
 * @tc.name     Get Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID, false, callback);
    TELEPHONY_LOGI("GetRadioState_0100 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0100 SetRadioStateCallbackResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetRadioState(SLOT_ID, callback);
    TELEPHONY_LOGI("GetRadioState_0100 GetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0100 GetRadioStateCallbackResult isRadioOn: %{public}d", isRadioOn);
    ASSERT_FALSE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0200
 * @tc.name     Get Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID, true, callback);
    TELEPHONY_LOGI("GetRadioState_0200 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0200 SetRadioStateCallbackResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetRadioState(SLOT_ID, callback);
    TELEPHONY_LOGI("GetRadioState_0200 GetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0200 GetRadioStateCallbackResult isRadioOn: %{public}d", isRadioOn);
    ASSERT_TRUE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0300
 * @tc.name     Get Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0300, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID1, false, callback);
    TELEPHONY_LOGI("GetRadioState_0300 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0300 SetRadioStateCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetRadioState(SLOT_ID1, callback);
    TELEPHONY_LOGI("GetRadioState_0300 GetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0300 GetRadioStateCallbackResult isRadioOn: %{public}d", isRadioOn);
    ASSERT_FALSE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0400
 * @tc.name     Get Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().SetRadioState(SLOT_ID1, true, callback);
    TELEPHONY_LOGI("GetRadioState_0400 SetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0400 SetRadioStateCallbackResult syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = CoreServiceClient::GetInstance().GetRadioState(SLOT_ID1, callback);
    TELEPHONY_LOGI("GetRadioState_0400 GetRadioState result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("GetRadioState_0400 GetRadioStateCallbackResult isRadioOn: %{public}d", isRadioOn);
    ASSERT_TRUE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0500
 * @tc.name     Get radio state off without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0500, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().GetRadioState(SLOT_ID, callback);
    TELEPHONY_LOGI("GetRadioState_0100 GetRadioState result: %{public}d", result);
    ASSERT_FALSE(result);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImei_0100
 * @tc.name     Get Imei
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImei_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetImei(SLOT_ID);
        std::string imei = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetImei Imei: %{public}s", imei.c_str());
        EXPECT_STRNE(imei.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImei_0200
 * @tc.name     Get Imei
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImei_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetImei(SLOT_ID1);
        std::string imei = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetImei Imei: %{public}s", imei.c_str());
        EXPECT_STRNE(imei.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImei_0300
 * @tc.name     Get Imei without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImei_0300, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::u16string result = CoreServiceClient::GetInstance().GetImei(SLOT_ID);
    std::string imei = Str16ToStr8(result);
    TELEPHONY_LOGI("TelephonyTestService GetImei Imei: %{public}s", imei.c_str());
    ASSERT_TRUE(imei.empty());
}

/**
 * @tc.number   Telephony_NetworkSearch_GetMeid_0100
 * @tc.name     Get Meid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetMeid_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetMeid(SLOT_ID);
        std::string meid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetMeid Meid: %{public}s", meid.c_str());
        EXPECT_STRNE(meid.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetMeid_0200
 * @tc.name     Get Meid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetMeid_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetMeid(SLOT_ID1);
        std::string meid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetMeid Meid: %{public}s", meid.c_str());
        EXPECT_STRNE(meid.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetMeid_0300
 * @tc.name     Get meid without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetMeid_0300, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::u16string result = CoreServiceClient::GetInstance().GetMeid(SLOT_ID);
    std::string meid = Str16ToStr8(result);
    TELEPHONY_LOGI("TelephonyTestService GetMeid Meid: %{public}s", meid.c_str());
    ASSERT_TRUE(meid.empty());
}

/**
 * @tc.number   Telephony_NetworkSearch_GetUniqueDeviceId_0100
 * @tc.name     Get unique device id
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetUniqueDeviceId_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetUniqueDeviceId(SLOT_ID);
        std::string deviceid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetUniqueDeviceId DeviceId: %{public}s", deviceid.c_str());
        EXPECT_STRNE(deviceid.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetUniqueDeviceId_0200
 * @tc.name     Get unique device id
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetUniqueDeviceId_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetUniqueDeviceId(SLOT_ID1);
        std::string deviceid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetUniqueDeviceId DeviceId: %{public}s", deviceid.c_str());
        EXPECT_STRNE(deviceid.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetUniqueDeviceId_0300
 * @tc.name     Get unique device id without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetUniqueDeviceId_0300, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    } else {
        std::u16string result = CoreServiceClient::GetInstance().GetUniqueDeviceId(SLOT_ID);
        std::string deviceid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetUniqueDeviceId DeviceId: %{public}s", deviceid.c_str());
        ASSERT_TRUE(deviceid.empty());
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SendUpdateCellLocationRequest_0100
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SendUpdateCellLocationRequest_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        bool result = CoreServiceClient::GetInstance().SendUpdateCellLocationRequest(SLOT_ID);
        TELEPHONY_LOGI("TelephonyTestService SendUpdateCellLocationRequest result: %{public}d", result);
        ASSERT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SendUpdateCellLocationRequest_0200
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SendUpdateCellLocationRequest_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        bool result = CoreServiceClient::GetInstance().SendUpdateCellLocationRequest(SLOT_ID1);
        TELEPHONY_LOGI("TelephonyTestService SendUpdateCellLocationRequest result: %{public}d", result);
        ASSERT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SendUpdateCellLocationRequest_0300
 * @tc.name     Send Cell Location Update without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SendUpdateCellLocationRequest_0300, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    } else {
        bool result = CoreServiceClient::GetInstance().SendUpdateCellLocationRequest(SLOT_ID);
        TELEPHONY_LOGI("TelephonyTestService SendUpdateCellLocationRequest result: %{public}d", result);
        ASSERT_FALSE(result);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSearchInformation_0100
 * @tc.name     Get Network Search Information
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSearchInformation_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().GetNetworkSearchInformation(SLOT_ID, callback);
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetNetworkSearchInformationCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->GetNetworkSearchInformationCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSearchInformation_0200
 * @tc.name     Get Network Search Information
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSearchInformation_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().GetNetworkSearchInformation(SLOT_ID1, callback);
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation result: %{public}d", result);
    ASSERT_TRUE(result);
    callback->WaitForGetNetworkSearchInformationCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->GetNetworkSearchInformationCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSearchInformation_0300
 * @tc.name     Get Network Search Information without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSearchInformation_0300, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = CoreServiceClient::GetInstance().GetNetworkSearchInformation(SLOT_ID, callback);
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation result: %{public}d", result);
    ASSERT_FALSE(result);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0100
 * @tc.name     Get ims register status
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegInfo info;
    int ret = CoreServiceClient::GetInstance().GetImsRegStatus(SLOT_ID, ImsServiceType::TYPE_VOICE, info);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0200
 * @tc.name     Get ims register status, but slot id is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    } else {
        ImsRegInfo info;
        ret = CoreServiceClient::GetInstance().GetImsRegStatus(INVALID_SLOT_ID, ImsServiceType::TYPE_VOICE, info);
        EXPECT_EQ(TELEPHONY_ERR_SLOTID_INVALID, ret);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0300
 * @tc.name     Get ims register status, but ImsServiceType is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0300, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegInfo info;
    int ret =
        CoreServiceClient::GetInstance().GetImsRegStatus(SLOT_ID, static_cast<ImsServiceType>(INVALID_TYPE), info);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0400
 * @tc.name     Get ims register status
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0400, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegInfo info;
    int ret = CoreServiceClient::GetInstance().GetImsRegStatus(SLOT_ID1, ImsServiceType::TYPE_VOICE, info);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0500
 * @tc.name     Get ims register status, but ImsServiceType is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0500, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegInfo info;
    int ret =
        CoreServiceClient::GetInstance().GetImsRegStatus(SLOT_ID1, static_cast<ImsServiceType>(INVALID_TYPE), info);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0600
 * @tc.name     Get ims register status without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0600, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegInfo info;
    int ret = CoreServiceClient::GetInstance().GetImsRegStatus(SLOT_ID, ImsServiceType::TYPE_VOICE, info);
    EXPECT_EQ(TELEPHONY_ERR_PERMISSION_ERR, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0100
 * @tc.name     Register ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegStateCallback imsRegStateCallback;
    imsRegStateCallback.slotId = SLOT_ID;
    imsRegStateCallback.imsSrvType = DEFAULT_TYPE;
    imsRegStateCallback.imsCallback = new ImsRegInfoCallbackGtest();
    int ret = CoreServiceClient::GetInstance().RegisterImsRegInfoCallback(
        imsRegStateCallback.slotId, imsRegStateCallback.imsSrvType, imsRegStateCallback.imsCallback);
    if (ret == TELEPHONY_SUCCESS) {
        NetworkSearchTest::imsRegStateCallbackList_.push_back(imsRegStateCallback);
    } else {
        if (imsRegStateCallback.imsCallback != nullptr) {
            delete imsRegStateCallback.imsCallback;
            imsRegStateCallback.imsCallback = nullptr;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0200
 * @tc.name     Register ims registation info callback, but slot id is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        INVALID_SLOT_ID, DEFAULT_TYPE, imsRegInfoCallback);
    delete imsRegInfoCallback;
    imsRegInfoCallback = nullptr;
    EXPECT_EQ(TELEPHONY_ERR_SLOTID_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0300
 * @tc.name     Register ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0300, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    int ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        SLOT_ID, static_cast<ImsServiceType>(INVALID_TYPE), imsRegInfoCallback);
    delete imsRegInfoCallback;
    imsRegInfoCallback = nullptr;
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0400
 * @tc.name     Register ims registation info callback, but callback is nullptr
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0400, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(SLOT_ID, DEFAULT_TYPE, nullptr);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_NULL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0500
 * @tc.name     Register ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0500, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegStateCallback imsRegStateCallback;
    imsRegStateCallback.slotId = SLOT_ID1;
    imsRegStateCallback.imsSrvType = DEFAULT_TYPE;
    imsRegStateCallback.imsCallback = new ImsRegInfoCallbackGtest();
    int ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        imsRegStateCallback.slotId, imsRegStateCallback.imsSrvType, imsRegStateCallback.imsCallback);
    if (ret == TELEPHONY_SUCCESS) {
        NetworkSearchTest::imsRegStateCallbackList_.push_back(imsRegStateCallback);
    } else {
        if (imsRegStateCallback.imsCallback != nullptr) {
            delete imsRegStateCallback.imsCallback;
            imsRegStateCallback.imsCallback = nullptr;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0600
 * @tc.name     Register ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0600, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    int ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        SLOT_ID1, static_cast<ImsServiceType>(INVALID_TYPE), imsRegInfoCallback);
    delete imsRegInfoCallback;
    imsRegInfoCallback = nullptr;
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0700
 * @tc.name     Register ims registation info callback, but callback is nullptr
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0700, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(SLOT_ID1, DEFAULT_TYPE, nullptr);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_NULL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0800
 * @tc.name     Register ims registation info callback without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0800, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegStateCallback imsRegStateCallback;
    imsRegStateCallback.slotId = SLOT_ID;
    imsRegStateCallback.imsSrvType = ImsServiceType::TYPE_VIDEO;
    imsRegStateCallback.imsCallback = new ImsRegInfoCallbackGtest();
    int ret = CoreServiceClient::GetInstance().RegisterImsRegInfoCallback(
        imsRegStateCallback.slotId, imsRegStateCallback.imsSrvType, imsRegStateCallback.imsCallback);
    EXPECT_EQ(TELEPHONY_ERR_PERMISSION_ERR, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0900
 * @tc.name     Register ims registation info callback with video type
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0900, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ImsRegStateCallback imsRegStateCallback;
    imsRegStateCallback.slotId = SLOT_ID;
    imsRegStateCallback.imsSrvType = ImsServiceType::TYPE_VIDEO;
    imsRegStateCallback.imsCallback = new ImsRegInfoCallbackGtest();
    int ret = CoreServiceClient::GetInstance().RegisterImsRegInfoCallback(
        imsRegStateCallback.slotId, imsRegStateCallback.imsSrvType, imsRegStateCallback.imsCallback);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0100
 * @tc.name     Unregister ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = CoreServiceClient::GetInstance().UnregisterImsRegInfoCallback(SLOT_ID, DEFAULT_TYPE);
    if (ret != TELEPHONY_SUCCESS) {
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    auto itor = NetworkSearchTest::imsRegStateCallbackList_.begin();
    for (; itor != NetworkSearchTest::imsRegStateCallbackList_.end(); ++itor) {
        if (itor->slotId == SLOT_ID && itor->imsSrvType == DEFAULT_TYPE) {
            if (itor->imsCallback != nullptr) {
                delete itor->imsCallback;
                itor->imsCallback = nullptr;
            }
            NetworkSearchTest::imsRegStateCallbackList_.erase(itor);
            break;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0200
 * @tc.name     Unregister ims registation info callback, but the callback it not registed
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID, TYPE_VIDEO);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0300
 * @tc.name     Unregister ims registation info callback, but slot id is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0300, Function | MediumTest | Level2)
{
    AccessToken token;
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(INVALID_SLOT_ID, DEFAULT_TYPE);
    EXPECT_EQ(TELEPHONY_ERR_SLOTID_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0400
 * @tc.name     Unregister ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0400, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(
        SLOT_ID, static_cast<ImsServiceType>(INVALID_TYPE));
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0500
 * @tc.name     Unregister ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0500, Function | MediumTest | Level2)
{
    AccessToken token;
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID1, DEFAULT_TYPE);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    auto itor = NetworkSearchTest::imsRegStateCallbackList_.begin();
    for (; itor != NetworkSearchTest::imsRegStateCallbackList_.end(); ++itor) {
        if (itor->slotId == SLOT_ID1 && itor->imsSrvType == DEFAULT_TYPE) {
            if (itor->imsCallback != nullptr) {
                delete itor->imsCallback;
                itor->imsCallback = nullptr;
            }
            NetworkSearchTest::imsRegStateCallbackList_.erase(itor);
            break;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0600
 * @tc.name     Unregister ims registation info callback, but the callback it not registed
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0600, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID1, TYPE_VIDEO);
    EXPECT_EQ(TELEPHONY_ERR_UNREGISTER_CALLBACK_FAIL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0700
 * @tc.name     Unregister ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0700, Function | MediumTest | Level2)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        return;
    }
    int ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(
        SLOT_ID1, static_cast<ImsServiceType>(INVALID_TYPE));
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0800
 * @tc.name     Unregister ims registation info callback without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0800, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID, ImsServiceType::TYPE_VIDEO);
    EXPECT_EQ(TELEPHONY_ERR_PERMISSION_ERR, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0900
 * @tc.name     Unregister ims registation info callback with video type
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0900, Function | MediumTest | Level2)
{
    AccessToken token;
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID, ImsServiceType::TYPE_VIDEO);
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

#else // TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_NetworkSearch_MockTest_0100
 * @tc.name     A test mock for unsupported platform
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_MockTest_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
    }
    EXPECT_TRUE(true);
}

#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS

// Copyright (C) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.ImsServiceType")]
#[repr(i32)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImsServiceType {
    TypeVoice = 0,
    TypeVideo = 1,
    TypeUt = 2,
    TypeSms = 3,
}

impl From<i32> for ImsServiceType {
    fn from(value: i32) -> Self {
        match value {
            0 => ImsServiceType::TypeVoice,
            1 => ImsServiceType::TypeVideo,
            2 => ImsServiceType::TypeUt,
            3 => ImsServiceType::TypeSms,
            _ => ImsServiceType::TypeVoice,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.ImsRegState")]
#[repr(i32)]
#[derive(Debug, Clone)]
enum ImsRegState {
    ImsUnregistered = 0,
    ImsRegistered = 1,
}

impl From<i32> for ImsRegState {
    fn from(value: i32) -> Self {
        match value {
            0 => ImsRegState::ImsUnregistered,
            1 => ImsRegState::ImsRegistered,
            _ => ImsRegState::ImsUnregistered,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.ImsRegTech")]
#[repr(i32)]
#[derive(Debug, Clone)]
enum ImsRegTech {
    RegistrationTechNone = 0,
    RegistrationTechLte = 1,
    RegistrationTechIwlan = 2,
    RegistrationTechNr = 3,
}

impl From<i32> for ImsRegTech {
    fn from(value: i32) -> Self {
        match value {
            0 => ImsRegTech::RegistrationTechNone,
            1 => ImsRegTech::RegistrationTechLte,
            2 => ImsRegTech::RegistrationTechIwlan,
            3 => ImsRegTech::RegistrationTechNr,
            _ => ImsRegTech::RegistrationTechNone,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkType")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NetworkType {
    NetworkTypeUnknown = 0,
    NetworkTypeGsm = 1,
    NetworkTypeCdma = 2,
    NetworkTypeWcdma = 3,
    NetworkTypeTdscdma = 4,
    NetworkTypeLte = 5,
    NetworkTypeNr = 6,
}

impl From<i32> for NetworkType {
    fn from(value: i32) -> Self {
        match value {
            0 => NetworkType::NetworkTypeUnknown,
            1 => NetworkType::NetworkTypeGsm,
            2 => NetworkType::NetworkTypeCdma,
            3 => NetworkType::NetworkTypeWcdma,
            4 => NetworkType::NetworkTypeTdscdma,
            5 => NetworkType::NetworkTypeLte,
            6 => NetworkType::NetworkTypeNr,
            _ => NetworkType::NetworkTypeUnknown,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.RegState")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum RegState {
    RegStateNoService = 0,
    RegStateInService = 1,
    RegStateEmergencyCallOnly = 2,
    RegStatePowerOff = 3,
}

impl From<i32> for RegState {
    fn from(value: i32) -> Self {
        match value {
            0 => RegState::RegStateNoService,
            1 => RegState::RegStateInService,
            2 => RegState::RegStateEmergencyCallOnly,
            3 => RegState::RegStatePowerOff,
            _ => RegState::RegStateNoService,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.RadioTechnology")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum RadioTechnology {
    RadioTechnologyUnknown = 0,
    RadioTechnologyGsm = 1,
    RadioTechnology_1xrtt = 2,
    RadioTechnologyWcdma = 3,
    RadioTechnologyHspa = 4,
    RadioTechnologyHspap = 5,
    RadioTechnologyTdScdma = 6,
    RadioTechnologyEvdo = 7,
    RadioTechnologyEhrpd = 8,
    RadioTechnologyLte = 9,
    RadioTechnologyLteCa = 10,
    RadioTechnologyIwlan = 11,
    RadioTechnologyNr = 12,
}

impl From<i32> for RadioTechnology {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::RadioTechnologyUnknown,
            1 => Self::RadioTechnologyGsm,
            2 => Self::RadioTechnology_1xrtt,
            3 => Self::RadioTechnologyWcdma,
            4 => Self::RadioTechnologyHspa,
            5 => Self::RadioTechnologyHspap,
            6 => Self::RadioTechnologyTdScdma,
            7 => Self::RadioTechnologyEvdo,
            8 => Self::RadioTechnologyEhrpd,
            9 => Self::RadioTechnologyLte,
            10 => Self::RadioTechnologyLteCa,
            11 => Self::RadioTechnologyIwlan,
            12 => Self::RadioTechnologyNr,
            _ => Self::RadioTechnologyUnknown,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NsaState")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NsaState {
    NsaStateNotSupport = 1,
    NsaStateNoDetect = 2,
    NsaStateConnectedDetect = 3,
    NsaStateIdleDetect = 4,
    NsaStateDualConnected = 5,
    NsaStateSaAttached = 6,
}

impl From<i32> for NsaState {
    fn from(value: i32) -> Self {
        match value {
            1 => NsaState::NsaStateNotSupport,
            2 => NsaState::NsaStateNoDetect,
            3 => NsaState::NsaStateConnectedDetect,
            4 => NsaState::NsaStateIdleDetect,
            5 => NsaState::NsaStateDualConnected,
            6 => NsaState::NsaStateSaAttached,
            _ => NsaState::NsaStateNotSupport,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.ImsRegInfoInner")]
#[derive(Debug, Clone)]
pub struct ImsRegInfoAni {
    ims_reg_state: ImsRegState,
    ims_reg_tech: ImsRegTech,
}

impl ImsRegInfoAni {
    pub fn new(ims_reg_state: i32, ims_reg_tech: i32) -> Self {
        Self {
            ims_reg_state: ImsRegState::from(ims_reg_state),
            ims_reg_tech: ImsRegTech::from(ims_reg_tech),
        }
    }
}

pub fn ims_reg_info_conversion(info: &mut ImsRegInfoAni, ims_reg_state: i32, ims_reg_tech: i32) {
    info.ims_reg_state = ImsRegState::from(ims_reg_state);
    info.ims_reg_tech = ImsRegTech::from(ims_reg_tech);
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.SignalInformationInner")]
#[derive(Debug, Clone)]
pub struct SignalInformationAni {
    signal_type: NetworkType,
    signal_level: i32,
    d_bm: i32,
}

impl SignalInformationAni {
    pub fn new(signal_type: i32, signal_level: i32, d_bm: i32) -> Self {
        Self {
            signal_type: NetworkType::from(signal_type),
            signal_level,
            d_bm,
        }
    }
}

pub fn signal_information_push_data(
    signal_info: &mut Vec<SignalInformationAni>,
    signal_type: i32,
    signal_level: i32,
    d_bm: i32,
) {
    let info = SignalInformationAni::new(signal_type, signal_level, d_bm);
    signal_info.push(info);
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.CellInformationInner")]
#[derive(Debug, Clone)]
pub struct CellInformation {
    pub network_type: NetworkType,
    pub is_camped: bool,
    pub time_stamp: i64,
    pub signal_information: SignalInformationAni,
    pub data: CellInformationData,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.CellInformationInner")]
#[derive(Debug, Clone)]
pub enum CellInformationData {
    Cdma(CdmaCellInformation),
    Gsm(GsmCellInformation),
    Lte(LteCellInformation),
    Nr(NrCellInformation),
    Tdscdma(TdscdmaCellInformation),
    Wcdma(WcdmaCellInformation),
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkStateInner")]
#[derive(Debug, Clone)]
pub struct NetworkState {
    pub long_operator_name: String,
    pub short_operator_name: String,
    pub plmn_numeric: String,
    pub is_roaming: bool,
    pub reg_state: RegState,
    pub cfg_tech: RadioTechnology,
    pub nsa_state: NsaState,
    pub is_emergency: bool,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkRadioTechInner")]
#[derive(Debug, Clone)]
pub struct NetworkRadioTech {
    pub ps_radio_tech: RadioTechnology,
    pub cs_radio_tech: RadioTechnology,
}

impl NetworkRadioTech {
    pub fn new(ps: i32, cs: i32) -> Self {
        Self {
            ps_radio_tech: RadioTechnology::from(ps),
            cs_radio_tech: RadioTechnology::from(cs),
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.PreferredNetworkMode")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum PreferredNetworkMode {
    PreferredNetworkModeGsm = 1,
    PreferredNetworkModeWcdma = 2,
    PreferredNetworkModeLte = 3,
    PreferredNetworkModeLteWcdma = 4,
    PreferredNetworkModeLteWcdmaGsm = 5,
    PreferredNetworkModeWcdmaGsm = 6,
    PreferredNetworkModeCdma = 7,
    PreferredNetworkModeEvdo = 8,
    PreferredNetworkModeEvdoCdma = 9,
    PreferredNetworkModeWcdmaGsmEvdoCdma = 10,
    PreferredNetworkModeLteEvdoCdma = 11,
    PreferredNetworkModeLteWcdmaGsmEvdoCdma = 12,
    PreferredNetworkModeTdscdma = 13,
    PreferredNetworkModeTdscdmaGsm = 14,
    PreferredNetworkModeTdscdmaWcdma = 15,
    PreferredNetworkModeTdscdmaWcdmaGsm = 16,
    PreferredNetworkModeLteTdscdma = 17,
    PreferredNetworkModeLteTdscdmaGsm = 18,
    PreferredNetworkModeLteTdscdmaWcdma = 19,
    PreferredNetworkModeLteTdscdmaWcdmaGsm = 20,
    PreferredNetworkModeTdscdmaWcdmaGsmEvdoCdma = 21,
    PreferredNetworkModeLteTdscdmaWcdmaGsmEvdoCdma = 22,
    PreferredNetworkModeNr = 31,
    PreferredNetworkModeNrLte = 32,
    PreferredNetworkModeNrLteWcdma = 33,
    PreferredNetworkModeNrLteWcdmaGsm = 34,
    PreferredNetworkModeNrLteEvdoCdma = 35,
    PreferredNetworkModeNrLteWcdmaGsmEvdoCdma = 36,
    PreferredNetworkModeNrLteTdscdma = 37,
    PreferredNetworkModeNrLteTdscdmaGsm = 38,
    PreferredNetworkModeNrLteTdscdmaWcdma = 39,
    PreferredNetworkModeNrLteTdscdmaWcdmaGsm = 40,
    PreferredNetworkModeNrLteTdscdmaWcdmaGsmEvdoCdma = 41,
    PreferredNetworkModeMaxValue = 99,
}

impl From<PreferredNetworkMode> for i32 {
    fn from(mode: PreferredNetworkMode) -> Self {
        mode as i32
    }
}

impl From<i32> for PreferredNetworkMode {
    fn from(value: i32) -> Self {
        match value {
            1 =>  PreferredNetworkMode::PreferredNetworkModeGsm,
            2 =>  PreferredNetworkMode::PreferredNetworkModeWcdma,
            3 =>  PreferredNetworkMode::PreferredNetworkModeLte,
            4 =>  PreferredNetworkMode::PreferredNetworkModeLteWcdma,
            5 =>  PreferredNetworkMode::PreferredNetworkModeLteWcdmaGsm,
            6 =>  PreferredNetworkMode::PreferredNetworkModeWcdmaGsm,
            7 =>  PreferredNetworkMode::PreferredNetworkModeCdma,
            8 =>  PreferredNetworkMode::PreferredNetworkModeEvdo,
            9 =>  PreferredNetworkMode::PreferredNetworkModeEvdoCdma,
            10 =>  PreferredNetworkMode::PreferredNetworkModeWcdmaGsmEvdoCdma,
            11 =>  PreferredNetworkMode::PreferredNetworkModeLteEvdoCdma,
            12 =>  PreferredNetworkMode::PreferredNetworkModeLteWcdmaGsmEvdoCdma,
            13 =>  PreferredNetworkMode::PreferredNetworkModeTdscdma,
            14 =>  PreferredNetworkMode::PreferredNetworkModeTdscdmaGsm,
            15 =>  PreferredNetworkMode::PreferredNetworkModeTdscdmaWcdma,
            16 =>  PreferredNetworkMode::PreferredNetworkModeTdscdmaWcdmaGsm,
            17 =>  PreferredNetworkMode::PreferredNetworkModeLteTdscdma,
            18 =>  PreferredNetworkMode::PreferredNetworkModeLteTdscdmaGsm,
            19 =>  PreferredNetworkMode::PreferredNetworkModeLteTdscdmaWcdma,
            20 =>  PreferredNetworkMode::PreferredNetworkModeLteTdscdmaWcdmaGsm,
            21 =>  PreferredNetworkMode::PreferredNetworkModeTdscdmaWcdmaGsmEvdoCdma,
            22 =>  PreferredNetworkMode::PreferredNetworkModeLteTdscdmaWcdmaGsmEvdoCdma,
            31 =>  PreferredNetworkMode::PreferredNetworkModeNr,
            32 =>  PreferredNetworkMode::PreferredNetworkModeNrLte,
            33 =>  PreferredNetworkMode::PreferredNetworkModeNrLteWcdma,
            34 =>  PreferredNetworkMode::PreferredNetworkModeNrLteWcdmaGsm,
            35 =>  PreferredNetworkMode::PreferredNetworkModeNrLteEvdoCdma,
            36 =>  PreferredNetworkMode::PreferredNetworkModeNrLteWcdmaGsmEvdoCdma,
            37 =>  PreferredNetworkMode::PreferredNetworkModeNrLteTdscdma,
            38 =>  PreferredNetworkMode::PreferredNetworkModeNrLteTdscdmaGsm,
            39 =>  PreferredNetworkMode::PreferredNetworkModeNrLteTdscdmaWcdma,
            40 =>  PreferredNetworkMode::PreferredNetworkModeNrLteTdscdmaWcdmaGsm,
            41 =>  PreferredNetworkMode::PreferredNetworkModeNrLteTdscdmaWcdmaGsmEvdoCdma,
            99 =>  PreferredNetworkMode::PreferredNetworkModeMaxValue,
            _ =>  PreferredNetworkMode::PreferredNetworkModeMaxValue,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkInformationState")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NetworkInformationState {
    NetworkUnknown = 0,
    NetworkAvailable,
    NetworkCurrent,
    NetworkForbidden
}

impl From<NetworkInformationState> for i32 {
    fn from(state: NetworkInformationState) -> i32 {
        state as i32
    }
}

impl From<i32> for NetworkInformationState {
    fn from(value: i32) -> Self {
        match value {
            0 => NetworkInformationState::NetworkUnknown,
            1 => NetworkInformationState::NetworkAvailable,
            2 => NetworkInformationState::NetworkCurrent,
            3 => NetworkInformationState::NetworkForbidden,
            _ => NetworkInformationState::NetworkUnknown,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkInformationInner")]
#[derive(Debug, Clone)]
pub struct NetworkInformation {
    pub operator_name: String,
    pub operator_numeric: String,
    pub state: NetworkInformationState,
    pub radio_tech: String,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkSearchResultInner")]
#[derive(Debug, Clone)]
pub struct NetworkSearchResult {
    pub is_network_search_success: bool,
    pub network_search_result: Vec<NetworkInformation>,
}

impl NetworkSearchResult {
    pub fn new() -> Self {
        Self {
            is_network_search_success: false,
            network_search_result: vec![],
        }
    }   
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkSelectionMode")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NetworkSelectionMode {
    NetworkSelectionUnknown,
    NetworkSelectionAutomatic,
    NetworkSelectionManual,
}

impl From<NetworkSelectionMode> for i32 {
    fn from(mode: NetworkSelectionMode) -> Self {
        mode as i32
    }
}

impl From<i32> for NetworkSelectionMode {
    fn from(value: i32) -> Self {
        match value {
            0 => NetworkSelectionMode::NetworkSelectionUnknown,
            1 => NetworkSelectionMode::NetworkSelectionAutomatic,
            2 => NetworkSelectionMode::NetworkSelectionManual,
            _ => NetworkSelectionMode::NetworkSelectionUnknown,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkSelectionModeOptionsInner")]
#[derive(Debug, Clone)]
pub struct NetworkSelectionModeOptions {
    pub slot_id: i32,
    pub select_mode: NetworkSelectionMode,
    pub network_information: NetworkInformation,
    pub resume_selection: bool,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.CdmaCellInformationInner")]
#[derive(Debug, Clone)]
pub struct CdmaCellInformation {
    pub base_id: i32,
    pub latitude: i32,
    pub longitude: i32,
    pub nid: i32,
    pub sid: i32,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.GsmCellInformationInner")]
#[derive(Debug, Clone)]
pub struct GsmCellInformation {
    pub lac: i32,
    pub cell_id: i32,
    pub arfcn: i32,
    pub bsic: i32,
    pub mcc: String,
    pub mnc: String,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.LteCellInformationInner")]
#[derive(Debug, Clone)]
pub struct LteCellInformation {
    pub cgi: i64,
    pub pci: i32,
    pub tac: i32,
    pub earfcn: i32,
    pub bandwidth: i32,
    pub mcc: String,
    pub mnc: String,
    pub is_support_endc: bool,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NrCellInformationInner")]
#[derive(Debug, Clone)]
pub struct NrCellInformation {
    pub nr_arfcn: i32,
    pub pci: i32,
    pub tac: i32,
    pub nci: i32,
    pub mcc: String,
    pub mnc: String,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.TdscdmaCellInformationInner")]
#[derive(Debug, Clone)]
pub struct TdscdmaCellInformation {
    pub lac: i32,
    pub cell_id: i32,
    pub cpid: i32,
    pub uarfcn: i32,
    pub mcc: String,
    pub mnc: String,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.WcdmaCellInformationInner")]
#[derive(Debug, Clone)]
pub struct WcdmaCellInformation {
    pub lac: i32,
    pub cell_id: i32,
    pub psc: i32,
    pub uarfcn: i32,
    pub mcc: String,
    pub mnc: String,
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkCapabilityType")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NetworkCapabilityType {
    ServiceTypeLte,
    ServiceTypeNr,
}

impl From<NetworkCapabilityType> for i32 {
    fn from(value: NetworkCapabilityType) -> Self {
        value as i32
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NetworkCapabilityState")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NetworkCapabilityState {
    ServiceCapabilityOff,
    ServiceCapabilityOn,
}

impl From<NetworkCapabilityState> for i32 {
    fn from(value: NetworkCapabilityState) -> Self {
        value as i32
    }
}

impl From<i32> for NetworkCapabilityState {
    fn from(value: i32) -> Self {
        match value {
            0 => NetworkCapabilityState::ServiceCapabilityOff,
            1 => NetworkCapabilityState::ServiceCapabilityOn,
            _ => NetworkCapabilityState::ServiceCapabilityOff,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.radio.radio.NROptionMode")]
#[repr(i32)]
#[derive(Debug, Clone)]
pub enum NROptionMode {
    NrOptionUnknown,
    NrOptionNsaOnly,
    NrOptionSaOnly,
    NrOptionNsaAndSa,
}

impl From<NROptionMode> for i32 {
    fn from(value: NROptionMode) -> Self {
        value as i32
    }
}

impl From<i32> for NROptionMode {
    fn from(value: i32) -> Self {
        match value {
            0 => NROptionMode::NrOptionUnknown,
            1 => NROptionMode::NrOptionNsaOnly,
            2 => NROptionMode::NrOptionSaOnly,
            3 => NROptionMode::NrOptionNsaAndSa,
            _ => NROptionMode::NrOptionUnknown,
        }
    }
}
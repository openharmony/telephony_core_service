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

use ani_rs::business_error::BusinessError;
use ffi::{ArktsError, NetworkStateAni, NetworkInformationAni, CellInformationAni};

use crate::bridge;
use crate::bridge::{
    ims_reg_info_conversion, signal_information_push_data, ImsRegInfoAni, SignalInformationAni, NetworkInformationState,
    NetworkInformation, NetworkType, CellInformationData
};
use crate::register::on_ims_reg_info_change;

pub const TELEPHONY_SUCCESS: i32 = 8300000;

impl From<ffi::NetworkStateAni> for bridge::NetworkState {
    fn from(value: ffi::NetworkStateAni) -> Self {
        Self {
            is_ca_active: value.is_ca_active,
            long_operator_name: value.long_operator_name,
            short_operator_name: value.short_operator_name,
            plmn_numeric: value.plmn_numeric,
            is_roaming: value.is_roaming,
            reg_state: bridge::RegState::from(value.reg_state),
            cfg_tech: bridge::RadioTechnology::from(value.cfg_tech),
            nsa_state: bridge::NsaState::from(value.nsa_state),
            is_emergency: value.is_emergency,
        }
    }
}

impl NetworkStateAni {
    pub fn new() -> Self {
        Self {
            is_ca_active: false,
            long_operator_name: String::from(""),
            short_operator_name: String::from(""),
            plmn_numeric: String::from(""),
            is_roaming: false,
            reg_state: 0,
            cfg_tech: 0,
            nsa_state: 1,
            is_emergency: false,
        }
    }
}

#[cxx::bridge(namespace = "OHOS::Telephony::RadioAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    struct NetworkStateAni {
        pub is_ca_active: bool,
        pub long_operator_name: String,
        pub short_operator_name: String,
        pub plmn_numeric: String,
        pub is_roaming: bool,
        pub reg_state: i32,
        pub cfg_tech: i32,
        pub nsa_state: i32,
        pub is_emergency: bool,
    }

    struct NetworkInformationAni {
        pub operator_name: String,
        pub operator_numeric: String,
        pub state: i32,
        pub radio_tech: String,
    }

    // All fields of CellInformation
    struct CellInformationAni {
        pub network_type: i32,
        pub is_camped: bool,
        pub time_stamp: i64,
        pub signal_type: i32,
        pub signal_level: i32,
        pub dbm: i32,
        pub cell_id: i32,
        pub mcc: String,
        pub mnc: String,
        pub base_id: i32,
        pub latitude: i32,
        pub longitude: i32,
        pub nid: i32,
        pub sid: i32,
        pub lac: i32,
        pub arfcn: i32,
        pub bsic: i32,
        pub cgi: i64,
        pub pci: i32,
        pub tac: i32,
        pub earfcn: i32,
        pub bandwidth: i32,
        pub is_support_endc: bool,
        pub nr_arfcn: i32,
        pub nci: i32,
        pub cpid: i32,
        pub uarfcn: i32,
        pub psc: i32,
    }

    unsafe extern "C++" {
        include!("ani_radio.h");

        fn GetBasebandVersion(slotId: i32, basebandVersion: &mut String) -> ArktsError;
        fn SetNrOptionMode(slotId: i32, nrMode: i32) -> ArktsError;
        fn GetNrOptionMode(slotId: i32, nrMode: &mut i32) -> ArktsError;
        fn SetNetworkCapability(slotId: i32, cap_type: i32, cap_state: i32) -> ArktsError;
        fn GetNetworkCapability(slotId: i32, cap_type: i32, cap_state: &mut i32) -> ArktsError;
        fn FactoryReset(slotId: i32) -> ArktsError;
        fn GetRadioTech(slotId: i32, ps_radio_tech: &mut i32, cs_radio_tech: &mut i32) -> ArktsError;
        fn SendUpdateCellLocationRequest(slotId: i32) -> ArktsError;
        fn GetCellInformation(slotId: i32, cellInfoVec: &mut Vec<CellInformationAni>) -> ArktsError;
        fn GetNetworkSelectionMode(slotId: i32, network_selection_mode: &mut i32) -> ArktsError;
        fn SetNetworkSelectionMode(slotId: i32, mode: i32, info: &NetworkInformationAni, selection: bool) -> ArktsError;
        fn GetNetworkSearchInformation(slotId: i32, networkInfoVec: &mut Vec<NetworkInformationAni>) -> ArktsError;
        fn GetIsoCountryCodeForNetwork(slotId: i32, countryCode: &mut String) -> ArktsError;
        fn GetImeiSv(slotId: i32, imeiSv: &mut String) -> ArktsError;
        fn GetImei(slotId: i32, imei: &mut String) -> ArktsError;
        fn GetMeid(slotId: i32, meid: &mut String) -> ArktsError;
        fn GetUniqueDeviceId(slotId: i32, operatorName: &mut String) -> ArktsError;
        fn SetPrimarySlotId(slotId: i32) -> ArktsError;
        fn IsRadioOn(slotId: i32, isRadioOn: &mut bool) -> ArktsError;
        fn TurnOnRadio(slotId: i32) -> ArktsError;
        fn TurnOffRadio(slotId: i32) -> ArktsError;
        fn GetOperatorName(slotId: i32, operatorName: &mut String) -> ArktsError;
        fn SetPreferredNetwork(slotId: i32, preferredNetworkMode: i32) -> ArktsError;
        fn GetPreferredNetwork(slotId: i32, preferredNetworkMode: &mut i32) -> ArktsError;
        fn GetImsRegInfo(
            slotId: i32,
            imsSrvType: i32,
            imsRegInfo: &mut ImsRegInfoAni,
        ) -> ArktsError;
        fn GetSignalInformation(
            slotId: i32,
            signalInfoList: &mut Vec<SignalInformationAni>,
        ) -> ArktsError;
        fn GetPrimarySlotId(slotId: &mut i32) -> ArktsError;
        fn GetNetworkState(slotId: i32, networkState: &mut NetworkStateAni) -> ArktsError;
        fn IsNrSupported() -> bool;
        fn EventListenerRegister(slotId: i32, imsSrvType: i32) -> ArktsError;
        fn EventListenerUnRegister(slotId: i32, imsSrvType: i32) -> ArktsError;
    }

    extern "Rust" {
        type ImsRegInfoAni;
        fn ims_reg_info_conversion(info: &mut ImsRegInfoAni, ims_reg_state: i32, ims_reg_tech: i32);
        type SignalInformationAni;
        fn signal_information_push_data(
            signal_info: &mut Vec<SignalInformationAni>,
            signal_type: i32,
            signal_level: i32,
            d_bm: i32,
        );
        fn on_ims_reg_info_change(
            slot_id: i32,
            ims_srv_type: i32,
            ims_reg_state: i32,
            ims_reg_tech: i32,
        );
    }
}

impl ArktsError {
    pub fn is_error(&self) -> bool {
        if self.errorCode != TELEPHONY_SUCCESS {
            return true;
        }
        false
    }
}

impl From<ArktsError> for BusinessError {
    fn from(value: ArktsError) -> Self {
        BusinessError::new(value.errorCode, value.errorMessage)
    }
}

impl NetworkInformationAni {
    pub fn new() -> Self {
        Self {
            operator_name: "".to_string(),
            operator_numeric: "".to_string(),
            state: 0,
            radio_tech: "".to_string(),
        }
    }
}

impl From<NetworkInformationAni> for NetworkInformation {
    fn from(value: NetworkInformationAni) -> Self {
        Self {
            operator_name: value.operator_name,
            operator_numeric: value.operator_numeric,
            state: NetworkInformationState::from(value.state),
            radio_tech: value.radio_tech,
        }
    }
}

impl From<NetworkInformation> for NetworkInformationAni {
    fn from(value: NetworkInformation) -> Self {
        Self {
            operator_name: value.operator_name,
            operator_numeric: value.operator_numeric,
            state: value.state.into(),
            radio_tech: value.radio_tech,
        }
    }
}

impl CellInformationAni {
    pub fn new() -> Self {
        Self {
            network_type: 0,
            is_camped: false,
            time_stamp: 0,
            signal_type: 0,
            signal_level: 0,
            dbm: 0,
            cell_id: 0,
            mcc: "".to_string(),
            mnc: "".to_string(),
            base_id: 0,
            latitude: 0,
            longitude: 0,
            nid: 0,
            sid: 0,
            lac: 0,
            arfcn: 0,
            bsic: 0,
            cgi: 0,
            pci: 0,
            tac: 0,
            earfcn: 0,
            bandwidth: 0,
            is_support_endc: false,
            nr_arfcn: 0,
            nci: 0,
            cpid: 0,
            uarfcn: 0,
            psc: 0,
        }
    }
}

impl From<CellInformationAni> for bridge::CellInformation {
    fn from(value: CellInformationAni) -> Self {
        Self {
            network_type: NetworkType::from(value.network_type),
            is_camped: value.is_camped,
            time_stamp: value.time_stamp,
            signal_information: SignalInformationAni::new(
                value.signal_type, value.signal_level, value.dbm,
            ),
            data: match NetworkType::from(value.network_type) {
                NetworkType::NetworkTypeGsm => CellInformationData::Gsm(bridge::GsmCellInformation { 
                    lac: value.lac,
                    cell_id: value.cell_id,
                    arfcn: value.arfcn,
                    bsic: value.bsic,
                    mcc: value.mcc,
                    mnc: value.mnc,
                }),
                NetworkType::NetworkTypeCdma => CellInformationData::Cdma(bridge::CdmaCellInformation {
                    base_id: value.base_id,
                    latitude: value.latitude,
                    longitude: value.longitude,
                    nid: value.nid,
                    sid: value.sid,
                }),
                NetworkType::NetworkTypeWcdma => CellInformationData::Wcdma(bridge::WcdmaCellInformation {
                    lac: value.lac,
                    cell_id: value.cell_id,
                    psc: value.psc,
                    uarfcn: value.uarfcn,
                    mcc: value.mcc,
                    mnc: value.mnc,
                }),
                NetworkType::NetworkTypeTdscdma => CellInformationData::Tdscdma(bridge::TdscdmaCellInformation {
                    lac: value.lac,
                    cell_id: value.cell_id,
                    cpid: value.cpid,
                    uarfcn: value.uarfcn,
                    mcc: value.mcc,
                    mnc: value.mnc,
                }),
                NetworkType::NetworkTypeLte => CellInformationData::Lte(bridge::LteCellInformation {
                    cgi: value.cgi,
                    pci: value.pci,
                    tac: value.tac,
                    earfcn: value.earfcn,
                    bandwidth: value.bandwidth,
                    mcc: value.mcc,
                    mnc: value.mnc,
                    is_support_endc: value.is_support_endc,
                }),
                NetworkType::NetworkTypeNr => CellInformationData::Nr(bridge::NrCellInformation {
                    nr_arfcn: value.nr_arfcn,
                    pci: value.pci,
                    tac: value.tac,
                    nci: value.nci,
                    mcc: value.mcc,
                    mnc: value.mnc,
                }),
                _ => CellInformationData::Gsm(bridge::GsmCellInformation {
                    lac: value.lac,
                    cell_id: value.cell_id,
                    arfcn: value.arfcn,
                    bsic: value.bsic,
                    mcc: value.mcc,
                    mnc: value.mnc,
                }),
            }
        }
    }
}
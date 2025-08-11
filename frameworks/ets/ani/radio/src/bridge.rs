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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/ImsServiceType")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/ImsRegState")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/ImsRegTech")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/NetworkType")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/RegState")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/RadioTechnology")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/NsaState")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/ImsRegInfoInner")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/SignalInformationInner")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/CellInformationInner")]
#[derive(Debug, Clone)]
pub struct CellInformation {
    network_type: NetworkType,
    signal_information: SignalInformationAni,
}

impl CellInformation {
    pub fn new(network_type: i32, signal_information: SignalInformationAni) -> Self {
        Self {
            network_type: NetworkType::from(network_type),
            signal_information,
        }
    }
}

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/NetworkStateInner")]
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

#[ani_rs::ani(path = "L@ohos/telephony/radio/radio/NetworkRadioTechInner")]
#[derive(Debug, Clone)]
pub struct NetworkRadioTech {
    ps_radio_tech: RadioTechnology,
}

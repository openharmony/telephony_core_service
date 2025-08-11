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
use ffi::{ArktsError, NetworkStateAni};

use crate::bridge;
use crate::bridge::{
    ims_reg_info_conversion, signal_information_push_data, ImsRegInfoAni, SignalInformationAni,
};
use crate::register::on_ims_reg_info_change;

pub const TELEPHONY_SUCCESS: i32 = 8300000;

impl From<ffi::NetworkStateAni> for bridge::NetworkState {
    fn from(value: ffi::NetworkStateAni) -> Self {
        Self {
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

#[cxx::bridge(namespace = "OHOS::RadioAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    struct NetworkStateAni {
        pub long_operator_name: String,
        pub short_operator_name: String,
        pub plmn_numeric: String,
        pub is_roaming: bool,
        pub reg_state: i32,
        pub cfg_tech: i32,
        pub nsa_state: i32,
        pub is_emergency: bool,
    }

    unsafe extern "C++" {
        include!("ani_radio.h");
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

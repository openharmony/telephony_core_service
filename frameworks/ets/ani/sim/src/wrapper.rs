// Copyright (c) 2025 Huawei Device Co., Ltd.
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

use crate::bridge::{
    icc_account_info_conversion, icc_account_info_push_data, lock_status_response_conversion,
    operator_config_push_kv, AniIccAccountInfo, AniLockStatusResponse, AniOperatorConfig,
};
use ani_rs::business_error::BusinessError;
use ffi::ArktsError;

pub const TELEPHONY_SUCCESS: i32 = 8300000;

#[cxx::bridge(namespace = "OHOS::SimAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    unsafe extern "C++" {
        include!("ani_sim.h");

        fn getLockState(slotId: i32, lockType: i32, lockState: &mut i32) -> ArktsError;
        fn unlockPuk(
            slotId: i32,
            newPin: String,
            puk: String,
            lockStatusResponse: &mut AniLockStatusResponse,
        ) -> ArktsError;
        fn unlockPin(
            slotId: i32,
            pin: String,
            lockStatusResponse: &mut AniLockStatusResponse,
        ) -> ArktsError;

        fn hasSimCard(slotId: i32, hasCard: &mut bool) -> ArktsError;

        fn isSimActive(slotId: i32, isActive: &mut bool) -> ArktsError;

        fn getDefaultVoiceSlotId(slotId: &mut i32) -> ArktsError;

        fn getOperatorConfigs(slotId: i32, configValues: &mut Vec<AniOperatorConfig>)
            -> ArktsError;

        fn getActiveSimAccountInfoList(
            accountInfoValues: &mut Vec<AniIccAccountInfo>,
        ) -> ArktsError;

        fn getSimAccountInfo(slotId: i32, accountInfo: &mut AniIccAccountInfo) -> ArktsError;

        fn getSimState(slotId: i32, simState: &mut i32) -> ArktsError;

        fn getISOCountryCodeForSim(slotId: i32, countryCode: &mut String) -> ArktsError;

        fn getMaxSimCount() -> i32;
    }

    extern "Rust" {
        type AniLockStatusResponse;
        fn lock_status_response_conversion(
            lock_status: &mut AniLockStatusResponse,
            result: i32,
            remain: i32,
        );

        type AniOperatorConfig;
        fn operator_config_push_kv(
            config_value: &mut Vec<AniOperatorConfig>,
            key: String,
            value: String,
        );

        type AniIccAccountInfo;
        fn icc_account_info_push_data(
            account_info_values: &mut Vec<AniIccAccountInfo>,
            sim_id: i32,
            slot_index: i32,
            is_esim: bool,
            is_active: bool,
            icc_id: String,
            show_name: String,
            show_number: String,
        );

        fn icc_account_info_conversion(
            account_info: &mut AniIccAccountInfo,
            sim_id: i32,
            slot_index: i32,
            is_esim: bool,
            is_active: bool,
            icc_id: String,
            show_name: String,
            show_number: String,
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

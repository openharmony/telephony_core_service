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
    sim_authentication_response_conversion, operator_config_push_kv, AniIccAccountInfo, AniLockStatusResponse,
    AniOperatorConfig, AniDiallingNumbersInfo, AniSimAuthenticationResponse,
};
use ani_rs::business_error::BusinessError;
use ffi::ArktsError;
use ffi::ArktsDiallingNumbersInfo;

pub const TELEPHONY_SUCCESS: i32 = 8300000;

#[cxx::bridge(namespace = "OHOS::Telephony::SimAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    struct ArktsDiallingNumbersInfo {
        recordNumber: i32,
        alphaTag: String,
        teleNumber: String,
        pin2: String,
    }

    unsafe extern "C++" {
        include!("ani_sim.h");

        fn GetLockState(slotId: i32, lockType: i32, lockState: &mut i32) -> ArktsError;
        fn UnlockPuk(
            slotId: i32,
            newPin: String,
            puk: String,
            lockStatusResponse: &mut AniLockStatusResponse,
        ) -> ArktsError;
        fn UnlockPin(
            slotId: i32,
            pin: String,
            lockStatusResponse: &mut AniLockStatusResponse,
        ) -> ArktsError;

        fn HasSimCard(slotId: i32, hasCard: &mut bool) -> ArktsError;

        fn IsSimActive(slotId: i32, isActive: &mut bool) -> ArktsError;

        fn GetDefaultVoiceSlotId(slotId: &mut i32) -> ArktsError;

        fn GetOperatorConfigs(slotId: i32, configValues: &mut Vec<AniOperatorConfig>)
            -> ArktsError;

        fn GetActiveSimAccountInfoList(
            accountInfoValues: &mut Vec<AniIccAccountInfo>,
        ) -> ArktsError;

        fn GetSimAccountInfo(slotId: i32, accountInfo: &mut AniIccAccountInfo) -> ArktsError;

        fn GetSimState(slotId: i32, simState: &mut i32) -> ArktsError;

        fn GetISOCountryCodeForSim(slotId: i32, countryCode: &mut String) -> ArktsError;

        fn GetMaxSimCount() -> i32;

        fn GetSimAuthentication(slotId: i32, authType: i32, authData: String,
            simAuthenticationResponse: &mut AniSimAuthenticationResponse) -> ArktsError;

        fn GetDsdsMode(dsdsMode: &mut i32) -> ArktsError;

        fn GetDefaultVoiceSimId(simId: &mut i32) -> ArktsError;

        fn GetOpName(slotId: i32, opName: &mut String) -> ArktsError;

        fn GetOpKey(slotId: i32, opKey: &mut String) -> ArktsError;

        fn UnlockSimLock(
            slotId: i32,
            persoLockType: i32,
            password: String,
            lockStatus: &mut AniLockStatusResponse,
        ) -> ArktsError;

        fn SendTerminalResponseCmd(slotId: i32, cmd: String) -> ArktsError;

        fn SendEnvelopeCmd(slotId: i32, cmd: String) -> ArktsError;

        fn UpdateIccDiallingNumbers(slotId: i32, contactType: i32, diallingNumbers: &ArktsDiallingNumbersInfo) -> ArktsError;

        fn DelIccDiallingNumbers(slotId: i32, contactType: i32, diallingNumbers: &ArktsDiallingNumbersInfo) -> ArktsError;

        fn AddIccDiallingNumbers(slotId: i32, contactType: i32, diallingNumbers: &ArktsDiallingNumbersInfo) -> ArktsError;

        fn QueryIccDiallingNumbers(slotId: i32, contactType: i32, diallingNumbers: &mut Vec<ArktsDiallingNumbersInfo>) -> ArktsError;

        fn AlterPin2(slotId: i32, newPin2: String, oldPin2: String, lockStatusResponse: &mut AniLockStatusResponse) -> ArktsError;

        fn UnlockPuk2(slotId: i32, newPin2: String, puk2: String, lockStatusResponse: &mut AniLockStatusResponse) -> ArktsError;

        fn UnlockPin2(slotId: i32, pin2: String, lockStatusResponse: &mut AniLockStatusResponse) -> ArktsError;

        fn SetLockState(
            slotId: i32,
            lockType: i32,
            password: String,
            state: i32,
            lockStatusResponse: &mut AniLockStatusResponse
        ) -> ArktsError;

        fn AlterPin(slotId: i32, newPin: String, oldPin: String, lockStatusResponse: &mut AniLockStatusResponse) -> ArktsError;

        fn GetShowNumber(slotId: i32, showNumber: &mut String) -> ArktsError;

        fn SetShowNumber(slotId: i32, showNumber: String) -> ArktsError;

        fn GetShowName(slotId: i32, showName: &mut String) -> ArktsError;

        fn SetShowName(slotId: i32, showName: String) -> ArktsError;

        fn DeactivateSim(slotId: i32) -> ArktsError;

        fn ActivateSim(slotId: i32) -> ArktsError;

        fn SetDefaultVoiceSlotId(slotId: i32) -> ArktsError;

        fn GetImsi(slotId: i32, imsi: &mut String) -> ArktsError;

        fn IsOperatorSimCard(slotId: i32, operatorName: String, isOperatorCard: &mut bool) -> ArktsError;

        fn GetSimGid1(slotId: i32, simGid1: &mut String) -> ArktsError;

        fn GetSimTelephoneNumber(slotId: i32, simTelephoneNumber: &mut String) -> ArktsError;

        fn SetVoiceMailInfo(slotId: i32, mailName: String, mailNumber: String) -> ArktsError;

        fn GetVoiceMailNumber(slotId: i32, voiceMailNumber: &mut String) -> ArktsError;

        fn GetVoiceMailIdentifier(slotId: i32, voiceMailIdentifier: &mut String) -> ArktsError;

        fn GetSimIccId(slotId: i32, simIccId: &mut String) -> ArktsError;

        fn GetCardType(slotId: i32, cardType: &mut i32) -> ArktsError;

        fn GetSimSpn(slotId: i32, simSpn: &mut String) -> ArktsError;

        fn GetSimOperatorNumeric(slotId: i32, simOperatorNumeric: &mut String) -> ArktsError;

        fn HasOperatorPrivileges(slotId: i32, hasPrivileges: &mut bool) -> ArktsError;
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

        type AniSimAuthenticationResponse;
        fn sim_authentication_response_conversion(
            sim_authentication_response: &mut AniSimAuthenticationResponse,
            status_word1: i32,
            status_word2: i32,
            response: String,
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

impl From<AniDiallingNumbersInfo> for ArktsDiallingNumbersInfo {
    fn from(value: AniDiallingNumbersInfo) -> Self {
        Self {
            recordNumber: value.record_number.unwrap_or(0),
            alphaTag: value.alpha_tag,
            teleNumber: value.tele_number,
            pin2: value.pin2.unwrap_or_default(),
        }
    }
}

impl From<ArktsDiallingNumbersInfo> for AniDiallingNumbersInfo {
    fn from(value: ArktsDiallingNumbersInfo) -> Self {
        Self {
            record_number:(value.recordNumber != 0).then_some(value.recordNumber),
            alpha_tag: value.alphaTag,
            tele_number: value.teleNumber,
            pin2: (!value.pin2.is_empty()).then_some(value.pin2),
        }
    }
}

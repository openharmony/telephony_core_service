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

use crate::{
    bridge::{
        AniDiallingNumbersInfo, AniIccAccountInfo, AniLockInfo, AniLockStatusResponse, AniOperatorConfig, AniPersoLockInfo,
        AniSimAuthenticationResponse, CardType, ContactType, DsdsMode, LockState, LockType, OperatorSimCard, SimState, AuthType,
    },
    wrapper,
};
use ani_rs::business_error::BusinessError;

#[ani_rs::native]
pub fn get_lock_state(slot_id: i32, lock_type: LockType) -> Result<LockState, BusinessError> {
    let mut lock_state = 0;

    let arkts_error = wrapper::ffi::GetLockState(slot_id, lock_type.into(), &mut lock_state);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(LockState::from(lock_state))
}

#[ani_rs::native]
pub fn unlock_puk(
    slot_id: i32,
    new_pin: String,
    puk: String,
) -> Result<AniLockStatusResponse, BusinessError> {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::UnlockPuk(slot_id, new_pin, puk, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
}

#[ani_rs::native]
pub fn unlock_pin(slot_id: i32, pin: String) -> Result<AniLockStatusResponse, BusinessError> {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::UnlockPin(slot_id, pin, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
}

#[ani_rs::native]
pub fn has_sim_card(slot_id: i32) -> Result<bool, BusinessError> {
    let mut has_card = false;

    let arkts_error = wrapper::ffi::HasSimCard(slot_id, &mut has_card);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(has_card)
}

#[ani_rs::native]
pub fn is_sim_active(slot_id: i32) -> Result<bool, BusinessError> {
    let mut is_active = false;

    let arkts_error = wrapper::ffi::IsSimActive(slot_id, &mut is_active);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(is_active)
}

#[ani_rs::native]
pub fn get_default_voice_slot_id() -> Result<i32, BusinessError> {
    let mut slot_id = -2;

    let arkts_error = wrapper::ffi::GetDefaultVoiceSlotId(&mut slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(slot_id)
}

#[ani_rs::native]
pub fn get_operator_configs(slot_id: i32) -> Result<Vec<AniOperatorConfig>, BusinessError> {
    let mut config_value = Vec::new();

    let arkts_error = wrapper::ffi::GetOperatorConfigs(slot_id, &mut config_value);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(config_value)
}

#[ani_rs::native]
pub fn get_active_sim_account_info_list() -> Result<Vec<AniIccAccountInfo>, BusinessError> {
    let mut account_info = Vec::new();

    let arkts_error = wrapper::ffi::GetActiveSimAccountInfoList(&mut account_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(account_info)
}

#[ani_rs::native]
pub fn get_sim_account_info(slot_id: i32) -> Result<AniIccAccountInfo, BusinessError> {
    let mut info = AniIccAccountInfo::new();

    let arkts_error = wrapper::ffi::GetSimAccountInfo(slot_id, &mut info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(info)
}

#[ani_rs::native]
pub fn get_sim_state(slot_id: i32) -> Result<SimState, BusinessError> {
    let mut sim_state = 0;

    let arkts_error = wrapper::ffi::GetSimState(slot_id, &mut sim_state);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(SimState::from(sim_state))
}

#[ani_rs::native]
pub fn get_iso_country_code_for_sim(slot_id: i32) -> Result<String, BusinessError> {
    let mut country_code = String::from("");
    let arkts_error = wrapper::ffi::GetISOCountryCodeForSim(slot_id, &mut country_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(country_code)
}

#[ani_rs::native]
pub fn get_max_sim_count() -> Result<i32, BusinessError> {
    let count = wrapper::ffi::GetMaxSimCount();
    Ok(count)
}

#[ani_rs::native]
pub fn get_sim_authentication(
        slot_id: i32,
        auth_type: AuthType,
        auth_data: String
    ) -> Result<AniSimAuthenticationResponse, BusinessError> {
    let mut response = AniSimAuthenticationResponse::new();
    let arkts_error = wrapper::ffi::GetSimAuthentication(slot_id, auth_type.into(), auth_data, &mut response);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(response)
}

#[ani_rs::native]
pub fn get_dsds_mode() -> Result<DsdsMode, BusinessError> {
    let mut dsds_mode = 0;

    let arkts_error = wrapper::ffi::GetDsdsMode(&mut dsds_mode);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(DsdsMode::from(dsds_mode))
}

#[ani_rs::native]
pub fn get_default_voice_sim_id() -> Result<i32, BusinessError> {
    let mut sim_id = 0;

    let arkts_error = wrapper::ffi::GetDefaultVoiceSimId(&mut sim_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(sim_id)
}

#[ani_rs::native]
pub fn get_op_name(slot_id: i32) -> Result<String, BusinessError> {
    let mut op_name = String::new();
    let arkts_error = wrapper::ffi::GetOpName(slot_id, &mut op_name);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(op_name)
}

#[ani_rs::native]
pub fn get_op_key(slot_id: i32) -> Result<String, BusinessError> {
    let mut op_key = String::new();
    let arkts_error = wrapper::ffi::GetOpKey(slot_id, &mut op_key);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(op_key)
}

#[ani_rs::native]
pub fn unlock_sim_lock(slot_id: i32, lock_info: AniPersoLockInfo) -> Result<AniLockStatusResponse, BusinessError> {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::UnlockSimLock(
        slot_id, lock_info.lock_type.into(), lock_info.password, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
}

#[ani_rs::native]
pub fn send_terminal_response_cmd(slot_id: i32, cmd: String) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SendTerminalResponseCmd(slot_id, cmd);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn send_envelope_cmd(slot_id: i32, cmd: String) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SendEnvelopeCmd(slot_id, cmd);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn update_icc_dialling_numbers(
        slot_id: i32,
        contact_type: ContactType,
        dialling_numbers: AniDiallingNumbersInfo
    ) -> Result<(), BusinessError> {
    let dialling_number_info = wrapper::ffi::ArktsDiallingNumbersInfo::from(dialling_numbers);
    let arkts_error = wrapper::ffi::UpdateIccDiallingNumbers(slot_id, contact_type.into(), &dialling_number_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn del_icc_dialling_numbers(
        slot_id: i32,
        contact_type: ContactType,
        dialling_numbers: AniDiallingNumbersInfo
    ) -> Result<(), BusinessError> {
    let dialling_number_info = wrapper::ffi::ArktsDiallingNumbersInfo::from(dialling_numbers);
    let arkts_error = wrapper::ffi::DelIccDiallingNumbers(slot_id, contact_type.into(), &dialling_number_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
 }

 #[ani_rs::native]
 pub fn add_icc_dialling_numbers(
        slot_id: i32,
        contact_type: ContactType,
        dialling_numbers: AniDiallingNumbersInfo
    ) -> Result<(), BusinessError> {
    let dialling_number_info = wrapper::ffi::ArktsDiallingNumbersInfo::from(dialling_numbers);
    let arkts_error = wrapper::ffi::AddIccDiallingNumbers(slot_id, contact_type.into(), &dialling_number_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn query_icc_dialling_numbers(slot_id: i32, contact_type: ContactType) -> Result<Vec<AniDiallingNumbersInfo>, BusinessError> {
    let mut dialling_numbers: Vec<wrapper::ffi::ArktsDiallingNumbersInfo> = Vec::new();
    let arkts_error = wrapper::ffi::QueryIccDiallingNumbers(slot_id, contact_type.into(), &mut dialling_numbers);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    let dialling_numbers_info: Vec<AniDiallingNumbersInfo> = dialling_numbers
        .into_iter()
        .map(|dialling_number| dialling_number.into())
        .collect();
    Ok(dialling_numbers_info)
 }

 #[ani_rs::native]
 pub fn alter_pin2(slot_id: i32, new_pin2: String, old_pin2: String) -> Result<AniLockStatusResponse, BusinessError>
 {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::AlterPin2(slot_id, new_pin2, old_pin2, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)   
 }

 #[ani_rs::native]
 pub fn unlock_puk2(slot_id: i32, new_pin2: String, puk2: String) -> Result<AniLockStatusResponse, BusinessError>
 {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::UnlockPuk2(slot_id, new_pin2, puk2, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
 }

 #[ani_rs::native]
 pub fn unlock_pin2(slot_id: i32, pin2: String) -> Result<AniLockStatusResponse, BusinessError>
 {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::UnlockPin2(slot_id, pin2, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
 }

 #[ani_rs::native]
 pub fn set_lock_state(slot_id: i32, options: AniLockInfo) -> Result<AniLockStatusResponse, BusinessError>
 {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::SetLockState(slot_id, options.lock_type.into(),
            options.password, options.state.into(), &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
 }

 #[ani_rs::native]
 pub fn alter_pin(slot_id: i32, new_pin: String, old_pin: String) -> Result<AniLockStatusResponse, BusinessError>
 {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::AlterPin(slot_id, new_pin, old_pin, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
 }

 #[ani_rs::native]
pub fn get_show_number(slot_id: i32) -> Result<String, BusinessError> {
    let mut show_number = String::new();
    let arkts_error = wrapper::ffi::GetShowNumber(slot_id, &mut show_number);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(show_number)
}

#[ani_rs::native]
pub fn set_show_number(slot_id: i32, show_number: String) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetShowNumber(slot_id, show_number);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_show_name(slot_id: i32) -> Result<String, BusinessError> {
    let mut show_name = String::new();
    let arkts_error = wrapper::ffi::GetShowName(slot_id, &mut show_name);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(show_name)
}

#[ani_rs::native]
pub fn set_show_name(slot_id: i32, show_name: String) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetShowName(slot_id, show_name);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn deactivate_sim(slot_id: i32) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::DeactivateSim(slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn activate_sim(slot_id: i32) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::ActivateSim(slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn set_default_voice_slot_id(slot_id: i32) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetDefaultVoiceSlotId(slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_imsi(slot_id: i32) -> Result<String, BusinessError> {
    let mut imsi = String::new();
    let arkts_error = wrapper::ffi::GetImsi(slot_id, &mut imsi);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(imsi)
}

#[ani_rs::native]
pub fn is_operator_sim_card(slot_id: i32, operator_name: OperatorSimCard) -> Result<bool, BusinessError> {
    let mut is_operator_card = false;

    let arkts_error = wrapper::ffi::IsOperatorSimCard(slot_id, operator_name.as_str().to_string(), &mut is_operator_card);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(is_operator_card)
}

#[ani_rs::native]
pub fn get_sim_gid1(slot_id: i32) -> Result<String, BusinessError> {
    let mut sim_gid1 = String::new();
    let arkts_error = wrapper::ffi::GetSimGid1(slot_id, &mut sim_gid1);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(sim_gid1)
}

#[ani_rs::native]
pub fn get_sim_telephone_number(slot_id: i32) -> Result<String, BusinessError> {
    let mut sim_telephone_number = String::new();
    let arkts_error = wrapper::ffi::GetSimTelephoneNumber(slot_id, &mut sim_telephone_number);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(sim_telephone_number)
}

#[ani_rs::native]
pub fn set_voice_mail_info(slot_id: i32, mail_name: String, mail_number: String) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetVoiceMailInfo(slot_id, mail_name, mail_number);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_voice_mail_number(slot_id: i32) -> Result<String, BusinessError> {
    let mut voice_mail_number = String::new();
    let arkts_error = wrapper::ffi::GetVoiceMailNumber(slot_id, &mut voice_mail_number);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(voice_mail_number)
}

#[ani_rs::native]
pub fn get_voice_mail_identifier(slot_id: i32) -> Result<String, BusinessError> {
    let mut voice_mail_identifier = String::new();
    let arkts_error = wrapper::ffi::GetVoiceMailIdentifier(slot_id, &mut voice_mail_identifier);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(voice_mail_identifier)
}

#[ani_rs::native]
pub fn get_sim_icc_id(slot_id: i32) -> Result<String, BusinessError> {
    let mut sim_icc_id = String::new();
    let arkts_error = wrapper::ffi::GetSimIccId(slot_id, &mut sim_icc_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(sim_icc_id)
}

#[ani_rs::native]
pub fn get_card_type(slot_id: i32) -> Result<CardType, BusinessError> {
    let mut card_type = -1;
    let arkts_error = wrapper::ffi::GetCardType(slot_id, &mut card_type);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(CardType::from(card_type))
}

#[ani_rs::native]
pub fn get_sim_spn(slot_id: i32) -> Result<String, BusinessError> {
    let mut sim_spn = String::new();
    let arkts_error = wrapper::ffi::GetSimSpn(slot_id, &mut sim_spn);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(sim_spn)
}

#[ani_rs::native]
pub fn get_sim_operator_numeric(slot_id: i32) -> Result<String, BusinessError> {
    let mut sim_operator_numeric = String::new();
    let arkts_error = wrapper::ffi::GetSimOperatorNumeric(slot_id, &mut sim_operator_numeric);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(sim_operator_numeric)
}

#[ani_rs::native]
pub fn has_operator_privileges(slot_id: i32) -> Result<bool, BusinessError> {
    let mut has_privileges = false;

    let arkts_error = wrapper::ffi::HasOperatorPrivileges(slot_id, &mut has_privileges);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(has_privileges)
}
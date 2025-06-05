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
        AniIccAccountInfo, AniLockStatusResponse, AniOperatorConfig, LockState, LockType, SimState,
    },
    wrapper,
};
use ani_rs::business_error::BusinessError;

#[ani_rs::native]
pub fn get_lock_state(slot_id: i32, lock_type: LockType) -> Result<LockState, BusinessError> {
    let mut lock_state = 0;

    let arkts_error = wrapper::ffi::getLockState(slot_id, lock_type.into(), &mut lock_state);
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
    let arkts_error = wrapper::ffi::unlockPuk(slot_id, new_pin, puk, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
}

#[ani_rs::native]
pub fn unlock_pin(slot_id: i32, pin: String) -> Result<AniLockStatusResponse, BusinessError> {
    let mut lock_status = AniLockStatusResponse::new();
    let arkts_error = wrapper::ffi::unlockPin(slot_id, pin, &mut lock_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(lock_status)
}

#[ani_rs::native]
pub fn has_sim_card(slot_id: i32) -> Result<bool, BusinessError> {
    let mut has_card = false;

    let arkts_error = wrapper::ffi::hasSimCard(slot_id, &mut has_card);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(has_card)
}

#[ani_rs::native]
pub fn is_sim_active(slot_id: i32) -> Result<bool, BusinessError> {
    let mut is_active = false;

    let arkts_error = wrapper::ffi::isSimActive(slot_id, &mut is_active);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(is_active)
}

#[ani_rs::native]
pub fn get_default_voice_slot_id() -> Result<i32, BusinessError> {
    let mut slot_id = -2;

    let arkts_error = wrapper::ffi::getDefaultVoiceSlotId(&mut slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(slot_id)
}

#[ani_rs::native]
pub fn get_operator_configs(slot_id: i32) -> Result<Vec<AniOperatorConfig>, BusinessError> {
    let mut config_value = Vec::new();

    let arkts_error = wrapper::ffi::getOperatorConfigs(slot_id, &mut config_value);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(config_value)
}

#[ani_rs::native]
pub fn get_active_sim_account_info_list() -> Result<Vec<AniIccAccountInfo>, BusinessError> {
    let mut account_info = Vec::new();

    let arkts_error = wrapper::ffi::getActiveSimAccountInfoList(&mut account_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(account_info)
}

#[ani_rs::native]
pub fn get_sim_account_info(slot_id: i32) -> Result<AniIccAccountInfo, BusinessError> {
    let mut info = AniIccAccountInfo::new();

    let arkts_error = wrapper::ffi::getSimAccountInfo(slot_id, &mut info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(info)
}

#[ani_rs::native]
pub fn get_sim_state(slot_id: i32) -> Result<SimState, BusinessError> {
    let mut sim_state = 0;

    let arkts_error = wrapper::ffi::getSimState(slot_id, &mut sim_state);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(SimState::from(sim_state))
}

#[ani_rs::native]
pub fn get_iso_country_code_for_sim(slot_id: i32) -> Result<String, BusinessError> {
    let mut country_code = String::from("");
    let arkts_error = wrapper::ffi::getISOCountryCodeForSim(slot_id, &mut country_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(country_code)
}

#[ani_rs::native]
pub fn get_max_sim_count() -> Result<i32, BusinessError> {
    let count = wrapper::ffi::getMaxSimCount();
    Ok(count)
}

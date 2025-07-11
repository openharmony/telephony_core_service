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

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.LockState")]
#[repr(i32)]
pub enum LockState {
    LockOff = 0,
    LockOn = 1,
}

impl From<i32> for LockState {
    fn from(value: i32) -> Self {
        match value {
            0 => LockState::LockOff,
            1 => LockState::LockOn,
            _ => LockState::LockOff,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.LockType")]
#[repr(i32)]
pub enum LockType {
    PinLock = 1,
    FdnLock = 2,
}

impl From<LockType> for i32 {
    fn from(value: LockType) -> Self {
        match value {
            LockType::PinLock => 1,
            LockType::FdnLock => 2,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.LockStatusResponseInner")]
pub struct AniLockStatusResponse {
    result: i32,
    remain: Option<i32>,
}

impl AniLockStatusResponse {
    pub fn new() -> Self {
        Self {
            result: 0,
            remain: None,
        }
    }
}

pub fn lock_status_response_conversion(
    lock_status: &mut AniLockStatusResponse,
    result: i32,
    remain: i32,
) {
    const PASS_WORD_ERR: i32 = -1;
    lock_status.result = result;

    if result == PASS_WORD_ERR {
        lock_status.remain = Some(remain);
    } else {
        lock_status.remain = None;
    }
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.OperatorConfigInner")]
pub struct AniOperatorConfig {
    field: String,
    value: String,
}
impl AniOperatorConfig {
    pub fn new(field: String, value: String) -> Self {
        Self { field, value }
    }
}

pub fn operator_config_push_kv(
    config_values: &mut Vec<AniOperatorConfig>,
    key: String,
    value: String,
) {
    let config = AniOperatorConfig::new(key, value);
    config_values.push(config);
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.IccAccountInfoInner")]
pub struct AniIccAccountInfo {
    sim_id: i32,
    slot_index: i32,
    is_esim: bool,
    is_active: bool,
    icc_id: String,
    show_name: String,
    show_number: String,
}

impl AniIccAccountInfo {
    pub fn new() -> Self {
        Self {
            sim_id: 0,
            slot_index: 0,
            is_esim: false,
            is_active: false,
            icc_id: "".to_string(),
            show_name: "".to_string(),
            show_number: "".to_string(),
        }
    }
}

pub fn icc_account_info_push_data(
    account_info_values: &mut Vec<AniIccAccountInfo>,
    sim_id: i32,
    slot_index: i32,
    is_esim: bool,
    is_active: bool,
    icc_id: String,
    show_name: String,
    show_number: String,
) {
    let account_info = AniIccAccountInfo {
        sim_id,
        slot_index,
        is_esim,
        is_active,
        icc_id,
        show_name,
        show_number,
    };
    account_info_values.push(account_info);
}

pub fn icc_account_info_conversion(
    account_info: &mut AniIccAccountInfo,
    sim_id: i32,
    slot_index: i32,
    is_esim: bool,
    is_active: bool,
    icc_id: String,
    show_name: String,
    show_number: String,
) {
    account_info.sim_id = sim_id;
    account_info.slot_index = slot_index;
    account_info.is_esim = is_esim;
    account_info.is_active = is_active;
    account_info.icc_id = icc_id;
    account_info.show_name = show_name;
    account_info.show_number = show_number;
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.SimState")]
#[repr(i32)]
pub enum SimState {
    SimStateUnknown = 0,
    SimStateNotPresent = 1,
    SimStateLocked = 2,
    SimStateNotReady = 3,
    SimStateReady = 4,
    SimStateLoaded = 5,
}

impl From<i32> for SimState {
    fn from(value: i32) -> Self {
        match value {
            0 => SimState::SimStateUnknown,
            1 => SimState::SimStateNotPresent,
            2 => SimState::SimStateLocked,
            3 => SimState::SimStateNotReady,
            4 => SimState::SimStateReady,
            5 => SimState::SimStateLoaded,
            _ => SimState::SimStateUnknown,
        }
    }
}

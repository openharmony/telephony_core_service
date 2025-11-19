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

impl From<LockState> for i32 {
    fn from(value: LockState) -> Self {
        match value {
            LockState::LockOff => 0,
            LockState::LockOn => 1,
            _ => 0,
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

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.PersoLockType")]
#[repr(i32)]
pub enum PersoLockType {
    PnPinLock = 0,
    PnPukLock = 1,
    PuPinLock = 2,
    PuPukLock = 3,
    PpPinLock = 4,
    PpPukLock = 5,
    PcPinLock = 6,
    PcPukLock = 7,
    SimPinLock = 8,
    SimPukLock = 9,
}

impl From<PersoLockType> for i32 {
    fn from(value: PersoLockType) -> Self {
        match value {
            PersoLockType::PnPinLock => 0,
            PersoLockType::PnPukLock => 1,
            PersoLockType::PuPinLock => 2,
            PersoLockType::PuPukLock => 3,
            PersoLockType::PpPinLock => 4,
            PersoLockType::PpPukLock => 5,
            PersoLockType::PcPinLock => 6,
            PersoLockType::PcPukLock => 7,
            PersoLockType::SimPinLock => 8,
            PersoLockType::SimPukLock => 9,
            _ => 0,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.PersoLockInfoInner")]
pub struct AniPersoLockInfo {
    pub lock_type: PersoLockType,
    pub password: String,
}

impl AniPersoLockInfo {
    pub fn new() -> Self {
        Self {
            lock_type: PersoLockType::PnPinLock,
            password: String::new(),
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.ContactType")]
#[repr(i32)]
pub enum ContactType {
    GeneralContact = 1,
    FixedDialing = 2,
}

impl From<ContactType> for i32 {
    fn from(value: ContactType) -> Self {
        match value {
            ContactType::GeneralContact => 1,
            ContactType::FixedDialing => 2,
            _ => 1,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.sim.sim.DiallingNumbersInfoInner")]
pub struct AniDiallingNumbersInfo {
    pub alpha_tag: String,
    pub tele_number: String,
    pub record_number: Option<i32>,
    pub pin2: Option<String>,
}

impl AniDiallingNumbersInfo {
    pub fn new() -> Self {
        Self {
            alpha_tag: String::new(),
            tele_number: String::new(),
            record_number: None,
            pin2: None,
        }
    }
}

#[ani_rs::ani(path="@ohos.telephony.sim.sim.LockInfoInner")]
pub struct AniLockInfo {
    pub lock_type: LockType,
    pub password: String,
    pub state: LockState,
}

impl AniLockInfo {
    pub fn new() -> Self {
        Self {
            lock_type: LockType::PinLock,
            password: String::new(),
            state: LockState::LockOff,
        }
    }
}

#[ani_rs::ani(path="@ohos.telephony.sim.sim.CardType")]
#[repr(i32)]
pub enum CardType {
    UnknownCard = -1,

    SingleModeSimCard = 10,

    SingleModeUsimCard = 20,

    SingleModeRuimCard = 30,

    DualModeCgCard = 40,

    CtNationalRoamingCard = 41,

    CuDualModeCard = 42,

    DualModeTelecomLteCard = 43,

    DualModeUgCard = 50,

    SingleModeIsimCard = 60,
}

impl From<i32> for CardType {
    fn from(value: i32) -> Self {
        match value {
            -1 => CardType::UnknownCard,
            10 => CardType::SingleModeSimCard,
            20 => CardType::SingleModeUsimCard,
            30 => CardType::SingleModeRuimCard,
            40 => CardType::DualModeCgCard,
            41 => CardType::CtNationalRoamingCard,
            42 => CardType::CuDualModeCard,
            43 => CardType::DualModeTelecomLteCard,
            50 => CardType::DualModeUgCard,
            60 => CardType::SingleModeIsimCard,
            _ => CardType::UnknownCard,
        }
    }
}

#[ani_rs::ani(path="@ohos.telephony.sim.sim.OperatorSimCard")]
#[repr(i32)]
pub enum OperatorSimCard {
    ChinaTelecomCard = 0,
}

impl OperatorSimCard {
    pub const fn as_str(&self) -> &'static str {
        match self {
            OperatorSimCard::ChinaTelecomCard => "china_telecom_card",
        }
    }
}

#[ani_rs::ani(path="@ohos.telephony.sim.sim.DsdsMode")]
#[repr(i32)]
pub enum DsdsMode {
    DsdsModeV2 = 0,

    DsdsModeV3 = 1,

    DsdsModeV5Tdm = 2,

    DsdsModeV5Dsda = 3,
}

impl From<i32> for DsdsMode {
    fn from(value: i32) -> Self {
        match value {
            0 => DsdsMode::DsdsModeV2,
            1 => DsdsMode::DsdsModeV3,
            2 => DsdsMode::DsdsModeV5Tdm,
            3 => DsdsMode::DsdsModeV5Dsda,
            _ => DsdsMode::DsdsModeV2,
        }
    }
}

#[ani_rs::ani(path="@ohos.telephony.sim.sim.AuthType")]
#[repr(i32)]
pub enum AuthType {
    SimAuthEapSimType = 128,

    SimAuthEapAkaType = 129,
}

impl From<AuthType> for i32 {
    fn from(value: AuthType) -> Self {
        match value {
            AuthType::SimAuthEapSimType => 128,
            AuthType::SimAuthEapAkaType => 129,
            _ => 128,
        }
    }
}

#[ani_rs::ani(path="@ohos.telephony.sim.sim.SimAuthenticationResponseInner")]
pub struct AniSimAuthenticationResponse {
    pub sim_status_word1: i32,

    pub sim_status_word2: i32,
  
    pub response: String,
}

impl AniSimAuthenticationResponse {
    pub fn new() -> Self {
        Self {
            sim_status_word1: 0,
            sim_status_word2: 0,
            response: String::new(),
        }
    }
}

pub fn sim_authentication_response_conversion(
    sim_authentication_response: &mut AniSimAuthenticationResponse,
    status_word1: i32,
    status_word2: i32,
    response: String) {
    sim_authentication_response.sim_status_word1 = status_word1;
    sim_authentication_response.sim_status_word2 = status_word2;
    sim_authentication_response.response = response;
}
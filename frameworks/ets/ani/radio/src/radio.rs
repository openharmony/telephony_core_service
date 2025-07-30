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

use ani_rs::{business_error::BusinessError, objects::AniFnObject, AniEnv};

use crate::{
    bridge::{ImsRegInfoAni, ImsServiceType, NetworkState, SignalInformationAni},
    register::{EventListener, Register},
    telephony_error,
    wrapper::{self, ffi::NetworkStateAni},
};

const DEFAULT_SIM_SLOT_ID: i32 = 0;

#[ani_rs::native]
pub fn get_ims_reg_info(
    slot_id: i32,
    ims_type: ImsServiceType,
) -> Result<ImsRegInfoAni, BusinessError> {
    let mut ims_reg_info = ImsRegInfoAni::new(0, 0);
    let arkts_error = wrapper::ffi::GetImsRegInfo(slot_id, ims_type as i32, &mut ims_reg_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ims_reg_info)
}

#[ani_rs::native]
pub fn get_signal_information(slot_id: i32) -> Result<Vec<SignalInformationAni>, BusinessError> {
    let mut signal_info_list = Vec::new();

    let arkts_error = wrapper::ffi::GetSignalInformation(slot_id, &mut signal_info_list);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(signal_info_list)
}

#[ani_rs::native]
pub fn get_network_state(slot_id: Option<i32>) -> Result<NetworkState, BusinessError> {
    let mut network_state = NetworkStateAni::new();

    let slot_id = slot_id.unwrap_or_else(|| DEFAULT_SIM_SLOT_ID);
    let arkts_error = wrapper::ffi::GetNetworkState(slot_id, &mut network_state);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    let res = NetworkState::from(network_state);
    Ok(res)
}

#[ani_rs::native]
pub fn is_nr_supported() -> Result<bool, BusinessError> {
    let res = wrapper::ffi::IsNrSupported();
    Ok(res)
}

#[ani_rs::native]
pub fn get_primary_slot_id() -> Result<i32, BusinessError> {
    let mut slot_id = DEFAULT_SIM_SLOT_ID;
    let arkts_error = wrapper::ffi::GetPrimarySlotId(&mut slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(slot_id)
}

#[ani_rs::native]
pub fn on_ims_reg_state_change(
    env: &AniEnv,
    on_type: String,
    slot_id: i32,
    ims_srv_type: ImsServiceType,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    if on_type != "imsRegStateChange" {
        telephony_error!("callbackType is not imsRegStateChange and is {}", on_type);
        return Err(BusinessError::PARAMETER);
    }

    let callback_global = callback.into_global_callback(env).unwrap();
    let listener = EventListener::new(slot_id, ims_srv_type, callback_global);
    Register::get_instance().register(listener)?;
    Ok(())
}

#[ani_rs::native]
pub fn off_ims_reg_state_change(
    off_type: String,
    slot_id: i32,
    ims_srv_type: ImsServiceType,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    if off_type != "imsRegStateChange" {
        telephony_error!("callbackType is not imsRegStateChange and is {}", off_type);
        return Err(BusinessError::PARAMETER);
    }
    Register::get_instance().unregister(slot_id, ims_srv_type)?;
    Ok(())
}

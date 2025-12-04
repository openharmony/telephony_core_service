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
    bridge::{ImsRegInfoAni, ImsServiceType, NetworkState, SignalInformationAni, PreferredNetworkMode, NetworkInformationState,
        NetworkInformation, NetworkSearchResult, NetworkSelectionModeOptions, NetworkSelectionMode, CellInformation, NetworkRadioTech,
        NetworkCapabilityType, NetworkCapabilityState, NROptionMode},
    register::{EventListener, Register},
    telephony_error,
    wrapper::{self, ffi::NetworkStateAni, ffi::NetworkInformationAni, ffi::CellInformationAni},
};

const DEFAULT_SIM_SLOT_ID: i32 = 0;

#[ani_rs::native]
pub fn get_baseband_version(slot_id: i32) -> Result<String, BusinessError> {
    let mut baseband_version = String::from("");
    let arkts_error = wrapper::ffi::GetBasebandVersion(slot_id, &mut baseband_version);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(baseband_version)
}

#[ani_rs::native]
pub fn set_nr_option_mode(slot_id: i32, nr_mode: NROptionMode) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetNrOptionMode(slot_id, nr_mode.into());
    if (arkts_error.is_error()) {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_nr_option_mode(slot_id: i32) -> Result<NROptionMode, BusinessError> {
    let mut nr_mode = 0;
    let arkts_error = wrapper::ffi::GetNrOptionMode(slot_id, &mut nr_mode);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(NROptionMode::from(nr_mode))
}

#[ani_rs::native]
pub fn set_network_capability(slot_id: i32, cap_type: NetworkCapabilityType,
        cap_state: NetworkCapabilityState) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetNetworkCapability(slot_id, cap_type.into(), cap_state.into());
    if (arkts_error.is_error()) {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_network_capability(slot_id: i32, cap_type: NetworkCapabilityType) -> Result<NetworkCapabilityState, BusinessError> {
    let mut cap_state = 0;
    let arkts_error = wrapper::ffi::GetNetworkCapability(slot_id, cap_type.into(), &mut cap_state);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(NetworkCapabilityState::from(cap_state))
}

#[ani_rs::native]
pub fn factory_reset(slot_id: i32) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::FactoryReset(slot_id);
    if (arkts_error.is_error()) {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_radio_tech(slot_id: i32) -> Result<NetworkRadioTech, BusinessError> {
    let mut ps_radio_tech = 0;
    let mut cs_radio_tech = 0;
    let arkts_error = wrapper::ffi::GetRadioTech(slot_id, &mut ps_radio_tech, &mut cs_radio_tech);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(NetworkRadioTech::new(ps_radio_tech, cs_radio_tech))
}

#[ani_rs::native]
pub fn send_update_cell_location_request(slot_id: Option<i32>) -> Result<(), BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let arkts_error = wrapper::ffi::SendUpdateCellLocationRequest(id);
    if (arkts_error.is_error()) {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_cell_information(slot_id: Option<i32>) -> Result<Vec<CellInformation>, BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let mut cell_info: Vec<CellInformationAni> = Vec::new();
    let arkts_error = wrapper::ffi::GetCellInformation(id, &mut cell_info);
    if (arkts_error.is_error()) {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(cell_info.into_iter().map(|info| info.into()).collect())
}

#[ani_rs::native]
pub fn get_network_selection_mode(slot_id: i32) -> Result<NetworkSelectionMode, BusinessError> {
    let mut network_selection_mode = 0;
    let arkts_error = wrapper::ffi::GetNetworkSelectionMode(slot_id, &mut network_selection_mode);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(NetworkSelectionMode::from(network_selection_mode))
}

#[ani_rs::native]
pub fn set_network_selection_mode(options: NetworkSelectionModeOptions) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetNetworkSelectionMode(options.slot_id, options.select_mode.into(),
        &(options.network_information.into()), options.resume_selection);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(())
}

#[ani_rs::native]
pub fn get_network_search_information(slot_id: i32) -> Result<NetworkSearchResult, BusinessError> {
    let mut search_result = NetworkSearchResult::new();
    let mut network_information_vec: Vec<NetworkInformationAni> = Vec::new();
    let arkts_error = wrapper::ffi::GetNetworkSearchInformation(slot_id, &mut network_information_vec);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    if (!network_information_vec.is_empty()) {
        search_result.is_network_search_success = true;
        search_result.network_search_result = network_information_vec.into_iter().map(
            |info|NetworkInformation::from(info)).collect();
    }

    Ok(search_result)
}

#[ani_rs::native]
pub fn get_iso_country_code_for_network(slot_id: i32) -> Result<String, BusinessError> {
    let mut country_code = String::from("");
    let arkts_error = wrapper::ffi::GetIsoCountryCodeForNetwork(slot_id, &mut country_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(country_code)
}

#[ani_rs::native]
pub fn get_imeisv(slot_id: i32) -> Result<String, BusinessError> {
    let mut imeisv = String::from("");
    let arkts_error = wrapper::ffi::GetImeiSv(slot_id, &mut imeisv);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(imeisv)
}

#[ani_rs::native]
pub fn get_imei(slot_id: Option<i32>) -> Result<String, BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let mut imei = String::from("");
    let arkts_error = wrapper::ffi::GetImei(id, &mut imei);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(imei)
}

#[ani_rs::native]
pub fn get_meid(slot_id: Option<i32>) -> Result<String, BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let mut meid = String::from("");
    let arkts_error = wrapper::ffi::GetMeid(id, &mut meid);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(meid)
}

#[ani_rs::native]
pub fn get_unique_device_id(slot_id: Option<i32>) -> Result<String, BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let mut unique_device_id = String::from("");
    let arkts_error = wrapper::ffi::GetUniqueDeviceId(id, &mut unique_device_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(unique_device_id)
}

#[ani_rs::native]
pub fn set_primary_slot_id(slot_id: i32) -> Result<(), BusinessError> {
    let arkts_error = wrapper::ffi::SetPrimarySlotId(slot_id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}


#[ani_rs::native]
pub fn is_radio_on(slot_id: Option<i32>) -> Result<bool, BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let mut res = false;
    let arkts_error = wrapper::ffi::IsRadioOn(id, &mut res);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(res)
}

#[ani_rs::native]
pub fn turn_on_radio(slot_id: Option<i32>) -> Result<(), BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let arkts_error = wrapper::ffi::TurnOnRadio(id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn turn_off_radio(slot_id: Option<i32>) -> Result<(), BusinessError> {
    let id = slot_id.unwrap_or(DEFAULT_SIM_SLOT_ID);
    let arkts_error = wrapper::ffi::TurnOffRadio(id);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn get_operator_name(slot_id: i32) -> Result<String, BusinessError> {
    let mut operator_name = String::from("");
    let arkts_error = wrapper::ffi::GetOperatorName(slot_id, &mut operator_name);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(operator_name)
}

#[ani_rs::native]
pub fn set_preferred_network(slot_id: i32, preferred_network_mode: PreferredNetworkMode) -> Result<(), BusinessError> {
    let mode = preferred_network_mode.into();
    let arkts_error = wrapper::ffi::SetPreferredNetwork(slot_id, mode);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn get_preferred_network(slot_id: i32) -> Result<PreferredNetworkMode, BusinessError> {
    let mut preferred_network_mode = 0;
    let arkts_error = wrapper::ffi::GetPreferredNetwork(slot_id, &mut preferred_network_mode);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    let res = PreferredNetworkMode::from(preferred_network_mode);
    Ok(res)
}

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

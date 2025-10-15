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

use ani_rs::business_error::BusinessError;

use crate::{bridge::{CancelReason, DownloadConfiguration, DownloadProfileResult, DownloadableProfile, EuiccInfo,
    GetDownloadableProfileMetadataResult, GetDownloadableProfilesResult, GetEuiccProfileInfoListResult, OsuStatus,
    ResetOption, ResultCode}, wrapper};


#[ani_rs::native]
pub fn reset_memory(slot_id: i32, options: Option<ResetOption>) -> Result<ResultCode, BusinessError> {
    let mut result_code = 0;

    let opts = options.unwrap_or(ResetOption::DeleteOperationalProfiles);
    let arkts_error = wrapper::ffi::ResetMemory(slot_id, opts.into(), &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

#[ani_rs::native]
pub fn is_supported(slot_id: i32) -> Result<bool, BusinessError> {
    let mut is_supported_result = false;
    let arkts_error = wrapper::ffi::IsSupported(slot_id, &mut is_supported_result);
    if arkts_error.is_error() {
        return Ok(false);
    }

    Ok(is_supported_result)
}

#[ani_rs::native]
pub fn add_profile(profile: DownloadableProfile) -> Result<bool, BusinessError> {
    let profile_ani = profile.into();
    let mut add_profile_result = false;
    let arkts_error = wrapper::ffi::AddProfile(&profile_ani, &mut add_profile_result);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(add_profile_result)
}

#[ani_rs::native]
pub fn get_eid(slot_id: i32) -> Result<String, BusinessError> {
    let mut eid = "".to_string();
    let arkts_error = wrapper::ffi::GetEid(slot_id, &mut eid);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(eid)
}

#[ani_rs::native]
pub fn get_osu_status(slot_id: i32) -> Result<OsuStatus, BusinessError> {
    let mut osu_status = 0;
    let arkts_error = wrapper::ffi::GetOsuStatus(slot_id, &mut osu_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(OsuStatus::from(osu_status))
}

#[ani_rs::native]
pub fn start_osu(slot_id: i32) -> Result<OsuStatus, BusinessError> {
    let mut osu_status = 0;
    let arkts_error = wrapper::ffi::StartOsu(slot_id, &mut osu_status);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(OsuStatus::from(osu_status))
}

#[ani_rs::native]
pub fn get_downloadable_profile_metadata(slot_id: i32, port_index: i32, profile: DownloadableProfile,
    force_disable_profile: bool) -> Result<GetDownloadableProfileMetadataResult, BusinessError> {
    let profile_ani = profile.into();
    let mut result_ani = wrapper::ffi::GetDownloadableProfileMetadataResultAni::new();
    let arkts_error = wrapper::ffi::GetDownloadableProfileMetadata(slot_id, port_index, &profile_ani,
        force_disable_profile, &mut result_ani);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(result_ani.into())
}

#[ani_rs::native]
pub fn get_downloadable_profiles(slot_id: i32, port_index: i32, force_disable_profile: bool) ->
    Result<GetDownloadableProfilesResult, BusinessError> {
    let mut result = 0;
    let mut profiles_ani: Vec<wrapper::ffi::DownloadableProfileAni> = Vec::new();
    let arkts_error = wrapper::ffi::GetDownloadableProfiles(slot_id, port_index, force_disable_profile, &mut result,
        &mut profiles_ani);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(GetDownloadableProfilesResult::new(result, profiles_ani.into_iter().
        map(|profile_ani: wrapper::ffi::DownloadableProfileAni| profile_ani.into()).collect()))
}

#[ani_rs::native]
pub fn download_profile(slot_id: i32, port_index: i32, profile: DownloadableProfile,
    configuration: DownloadConfiguration) -> Result<DownloadProfileResult, BusinessError> {
    let mut result_ani = wrapper::ffi::DownloadProfileResultAni::new();
    let profile_ani: wrapper::ffi::DownloadableProfileAni = profile.into();
    let config_ani: wrapper::ffi::DownloadConfigurationAni = configuration.into();
    let arkts_error = wrapper::ffi::DownloadProfile(slot_id, port_index, &profile_ani, &config_ani, &mut result_ani);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(DownloadProfileResult::from(result_ani))
}

#[ani_rs::native]
pub fn get_euicc_profile_info_list(slot_id: i32) -> Result<GetEuiccProfileInfoListResult, BusinessError> {
    let mut info_list = wrapper::ffi::GetEuiccProfileInfoListResultAni::new();
    let arkts_error = wrapper::ffi::GetEuiccProfileInfoList(slot_id, &mut info_list);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(GetEuiccProfileInfoListResult::from(info_list))
}

#[ani_rs::native]
pub fn get_euicc_info(slot_id: i32) -> Result<EuiccInfo, BusinessError> {
    let mut euicc_info = "".to_string();
    let arkts_error = wrapper::ffi::GetEuiccInfo(slot_id, &mut euicc_info);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(EuiccInfo::new(euicc_info))
}

#[ani_rs::native]
pub fn delete_profile(slot_id: i32, iccid: String) -> Result<ResultCode, BusinessError> {
    let mut result_code = 0;
    let arkts_error = wrapper::ffi::DeleteProfile(slot_id, iccid, &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

#[ani_rs::native]
pub fn switch_to_profile(slot_id: i32, port_index: i32, iccid: String, force_disable_profile: bool) ->
    Result<ResultCode, BusinessError> {
    let mut result_code = 0;
    let arkts_error = wrapper::ffi::SwitchToProfile(slot_id, port_index, iccid, force_disable_profile, &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

#[ani_rs::native]
pub fn set_profile_nickname(slot_id: i32, iccid: String, nickname: String) -> Result<ResultCode, BusinessError> {
    let mut result_code = 0;
    let arkts_error = wrapper::ffi::SetProfileNickname(slot_id, iccid, nickname, &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

#[ani_rs::native]
pub fn reserve_profiles_for_factory_restore(slot_id: i32) -> Result<ResultCode, BusinessError> {
    let mut result_code = 0;
    let arkts_error = wrapper::ffi::ReserveProfilesForFactoryRestore(slot_id, &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

#[ani_rs::native]
pub fn set_default_smdp_address(slot_id: i32, address: String) -> Result<ResultCode, BusinessError> {
    let mut result_code = 0;
    let arkts_error = wrapper::ffi::SetDefaultSmdpAddress(slot_id, address, &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

#[ani_rs::native]
pub fn get_default_smdp_address(slot_id: i32) -> Result<String, BusinessError> {
    let mut address = String::from("");
    let arkts_error = wrapper::ffi::GetDefaultSmdpAddress(slot_id, &mut address);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(address)
}

#[ani_rs::native]
pub fn cancel_session(slot_id: i32, transaction_id: String, cancel_reason: CancelReason) ->
    Result<ResultCode, BusinessError> {
    let mut result_code = 0;
    let arkts_error = wrapper::ffi::CancelSession(slot_id, transaction_id, cancel_reason.into(), &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}

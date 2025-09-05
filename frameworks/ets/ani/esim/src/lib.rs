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

use ani_rs::ani_constructor;

mod bridge;
mod wrapper;
mod esim;


ani_constructor!(
    namespace "L@ohos/telephony/esim/eSIM"
    [
        "nativeResetMemory": esim::reset_memory,
        "nativeIsSupported": esim::is_supported,
        "nativeAddProfile": esim::add_profile,
        "nativeGetEid": esim::get_eid,
        "nativeGetOsuStatus": esim::get_osu_status,
        "nativeStartOsu": esim::start_osu,
        "nativeGetDownloadableProfileMetadata": esim::get_downloadable_profile_metadata,
        "nativeGetDownloadableProfiles": esim::get_downloadable_profiles,
        "nativeDownloadProfile": esim::download_profile,
        "nativeGetEuiccProfileInfoList": esim::get_euicc_profile_info_list,
        "nativeGetEuiccInfo": esim::get_euicc_info,
        "nativeDeleteProfile": esim::delete_profile,
        "nativeSwitchToProfile": esim::switch_to_profile,
        "nativeSetProfileNickname": esim::set_profile_nickname,
        "nativeReserveProfilesForFactoryRestore": esim::reserve_profiles_for_factory_restore,
        "nativeSetDefaultSmdpAddress": esim::set_default_smdp_address,
        "nativeGetDefaultSmdpAddress": esim::get_default_smdp_address,
        "nativeCancelSession": esim::cancel_session,
    ]
);
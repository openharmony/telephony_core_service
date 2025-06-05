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
mod sim;
mod wrapper;

ani_constructor!(
    namespace "L@ohos/telephony/sim/sim"
    [
        "nativeGetLockState": sim::get_lock_state,
        "nativeUnlockPuk": sim::unlock_puk,
        "nativeunlockPin": sim::unlock_pin,
        "nativeGetOperatorConfigs": sim::get_operator_configs,
        "nativeGetActiveSimAccountInfoList": sim::get_active_sim_account_info_list,
        "nativeGetSimAccountInfo": sim::get_sim_account_info,
        "nativeHasSimCard":  sim::has_sim_card,
        "nativeGetSimState": sim::get_sim_state,
        "nativeGetISOCountryCodeForSim": sim::get_iso_country_code_for_sim,
        "nativeGetMaxSimCount": sim::get_max_sim_count,
        "nativeGetDefaultVoiceSlotId": sim::get_default_voice_slot_id,
        "nativeIsSimActive": sim::is_sim_active,
    ]
);

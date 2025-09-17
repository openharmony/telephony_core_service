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
    namespace "@ohos.telephony.sim.sim"
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
        "nativeGetSimAuthentication": sim::get_sim_authentication,
        "nativeGetDsdsMode": sim::get_dsds_mode,
        "nativeGetDefaultVoiceSimId": sim::get_default_voice_sim_id,
        "nativeGetOpName": sim::get_op_name,
        "nativeGetOpKey": sim::get_op_key,
        "nativeUnlockSimLock": sim::unlock_sim_lock,
        "nativeSendTerminalResponseCmd": sim::send_terminal_response_cmd,
        "nativeSendEnvelopeCmd": sim::send_envelope_cmd,
        "nativeAlterPin2": sim::alter_pin2,
        "nativeUnlockPuk2": sim::unlock_puk2,
        "nativeUnlockPin2": sim::unlock_pin2,
        "nativeSetLockState": sim::set_lock_state,
        "nativeAlterPin": sim::alter_pin,
        "nativeGetShowNumber": sim::get_show_number,
        "nativeSetShowNumber": sim::set_show_number,
        "nativeGetShowName": sim::get_show_name,
        "nativeSetShowName": sim::set_show_name,
        "nativeDeactivateSim": sim::deactivate_sim,
        "nativeActivateSim": sim::activate_sim,
        "nativeSetDefaultVoiceSlotId": sim::set_default_voice_slot_id,
        "nativeGetIMSI": sim::get_imsi,
        "nativeGetSimGid1": sim::get_sim_gid1,
        "nativeGetSimTelephoneNumber": sim::get_sim_telephone_number,
        "nativeSetVoiceMailInfo": sim::set_voice_mail_info,
        "nativeGetVoiceMailNumber": sim::get_voice_mail_number,
        "nativeGetVoiceMailIdentifier": sim::get_voice_mail_identifier,
        "nativeGetSimIccId": sim::get_sim_icc_id,
        "nativeGetCardType": sim::get_card_type,
        "nativeGetSimSpn": sim::get_sim_spn,
        "nativeGetSimOperatorNumeric": sim::get_sim_operator_numeric,
        "nativeHasOperatorPrivileges": sim::has_operator_privileges,
        "nativeIsOperatorSimCard": sim::is_operator_sim_card,
    ]
);

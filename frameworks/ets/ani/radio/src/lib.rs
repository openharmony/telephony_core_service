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

mod bridge;
mod radio;
mod wrapper;
mod register;
mod log;

ani_rs::ani_constructor! {
    namespace "L@ohos/telephony/radio/radio"
    [
        "nativeGetImsRegInfo": radio::get_ims_reg_info,
        "nativeGetSignalInformation": radio::get_signal_information,
        "nativeGetPrimarySlotId": radio::get_primary_slot_id,
        "nativeGetNetworkState": radio::get_network_state,
        "nativeIsNRSupported": radio::is_nr_supported,
        "onImsRegStateChange": radio::on_ims_reg_state_change,
        "offImsRegStateChange": radio::off_ims_reg_state_change,
    ]
}

const LOG_LABEL: hilog_rust::HiLogLabel = hilog_rust::HiLogLabel {
    log_type: hilog_rust::LogType::LogCore,
    domain: 0xD001F04,
    tag: "CoreServiceRadioJsApi",
};

#[used]
#[link_section = ".init_array"]
static G_TELEPHONY_PANIC_HOOK: extern "C" fn() = {
    #[link_section = ".text.startup"]
    extern "C" fn init() {
        std::panic::set_hook(Box::new(|info| {
            telephony_error!("Panic occurred: {:?}", info);
        }));
    }
    init
};

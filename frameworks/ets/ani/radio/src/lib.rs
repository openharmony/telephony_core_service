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
    namespace "@ohos.telephony.radio.radio"
    [
        "nativeGetBasebandVersion": radio::get_baseband_version,
        "nativeSetNROptionMode": radio::set_nr_option_mode,
        "nativeGetNROptionMode": radio::get_nr_option_mode,
        "nativeSetNetworkCapability": radio::set_network_capability,
        "nativeGetNetworkCapability": radio::get_network_capability,
        "nativeFactoryReset": radio::factory_reset,
        "nativeGetRadioTech": radio::get_radio_tech,
        "nativeSendUpdateCellLocationRequest": radio::send_update_cell_location_request,
        "nativeGetCellInformation": radio::get_cell_information,
        "nativeGetNetworkSelectionMode": radio::get_network_selection_mode,
        "nativeSetNetworkSelectionMode": radio::set_network_selection_mode,
        "nativeGetNetworkSearchInformation": radio::get_network_search_information,
        "nativeGetISOCountryCodeForNetwork": radio::get_iso_country_code_for_network,
        "nativeGetIMEISV": radio::get_imeisv,
        "nativeGetIMEI": radio::get_imei,
        "nativeGetMEID": radio::get_meid,
        "nativeGetUniqueDeviceId": radio::get_unique_device_id,
        "nativeSetPrimarySlotId": radio::set_primary_slot_id,
        "nativeIsRadioOn": radio::is_radio_on,
        "nativeTurnOnRadio": radio::turn_on_radio,
        "nativeTurnOffRadio": radio::turn_off_radio,
        "nativeGetOperatorName": radio::get_operator_name,
        "nativeSetPreferredNetwork": radio::set_preferred_network,
        "nativeGetPreferredNetwork": radio::get_preferred_network,
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

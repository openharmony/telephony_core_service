// Copyright (c) 2026 Huawei Device Co., Ltd.
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

use std::ffi::CStr;
use ani_rs::{ani_constructor, objects::AniObject, AniEnv};

mod bridge;
mod vcard;
mod wrapper;
mod context;
mod log;

pub fn get_native_ptr<'local>(env: &AniEnv<'local>, obj: &AniObject) -> i64 {
    let native_str = unsafe { CStr::from_bytes_with_nul_unchecked(b"nativePtr\0") };
    env.get_field::<i64>(obj, native_str).unwrap_or(0)
}

ani_constructor!(
    namespace "@ohos.telephony.vcard.vcard"
    [
        "nativeImportVCard": vcard::import_vcard,
        "nativeExportVCard": vcard::export_vcard,
    ]
);

const LOG_LABEL: hilog_rust::HiLogLabel = hilog_rust::HiLogLabel {
    log_type: hilog_rust::LogType::LogCore,
    domain: 0xD001F04,
    tag: "CoreServiceVcardJsApi",
};
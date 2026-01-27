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

#[ani_rs::ani(path = "@ohos.telephony.vcard.vcard.VCardType")]
#[repr(i32)]
pub enum VCardType {
    VERSION_21 = 0,
	VERSION_30 = 1,
	VERSION_40 = 2,
}

impl From<i32> for VCardType {
    fn from(value: i32) -> Self {
        match value {
            0 => VCardType::VERSION_21,
            1 => VCardType::VERSION_30,
            2 => VCardType::VERSION_40,
            _ => VCardType::VERSION_21,
        }
    }
}

impl From<VCardType> for i32 {
    fn from(value: VCardType) -> Self {
        match value {
            VCardType::VERSION_21 => 0,
            VCardType::VERSION_30 => 1,
            VCardType::VERSION_40 => 2,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.vcard.vcard.VCardBuilderOptionsInner")]
pub struct AniVCardBuilderOptions {
    pub cardType: Option<VCardType>,
    pub charset: Option<String>,
}

impl Default for AniVCardBuilderOptions {
    fn default() -> Self {
        Self {
            cardType: Some(VCardType::VERSION_21),
            charset: Some("UTF-8".to_string()),
        }
    }
}

impl AniVCardBuilderOptions {
    pub fn new() -> Self {
        Self::default()
    }
}

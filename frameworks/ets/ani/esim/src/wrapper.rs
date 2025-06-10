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
use ffi::ArktsError;

pub const TELEPHONY_SUCCESS: i32 = 3120000;

#[cxx::bridge(namespace = "OHOS::EsimAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    unsafe extern "C++" {
        include!("ani_esim.h");

        fn resetMemory(slotId: i32, options: i32, resultCode: &mut i32) -> ArktsError;
    }
}

impl ArktsError {
    pub fn is_error(&self) -> bool {
        if self.errorCode != TELEPHONY_SUCCESS {
            return true;
        }
        false
    }
}

impl From<ArktsError> for BusinessError {
    fn from(value: ArktsError) -> Self {
        BusinessError::new(value.errorCode, value.errorMessage)
    }
}
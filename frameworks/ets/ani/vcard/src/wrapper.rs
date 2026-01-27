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

use ani_rs::business_error::BusinessError;
use ffi::ArktsError;

pub const TELEPHONY_SUCCESS: i32 = 8300000;

#[repr(transparent)]
pub struct AniEnv {
    pub inner: ani_rs::AniEnv<'static>,
}

#[repr(transparent)]
pub struct AniObject {
    pub inner: ani_rs::objects::AniObject<'static>,
}

#[cxx::bridge(namespace = "OHOS::Telephony::VcardAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    unsafe extern "C++" {
        include!("ani_vcard.h");

        unsafe fn IsStageContext(env: *mut AniEnv, ani_object: *mut AniObject) -> bool;
        unsafe fn GetStageModeContext(
            env: *mut *mut AniEnv,
            ani_object: *mut AniObject,
        ) -> SharedPtr<Context>;

        #[namespace = "OHOS::AbilityRuntime"]
        type Context;

        fn ImportVcard(context: SharedPtr<Context>, filePath: String, accountId: i32) -> ArktsError;
        fn ExportVcard(
            context: SharedPtr<Context>,
            predicates: i64,
            cardType: i32,
            charset: String,
            address: &mut String,
        ) -> ArktsError;

    }

    extern "Rust" {
        type AniEnv;

        type AniObject;
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

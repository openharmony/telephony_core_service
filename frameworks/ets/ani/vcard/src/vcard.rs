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

use crate::{
    get_native_ptr,
    bridge::{
        AniVCardBuilderOptions, VCardType
    },
    telephony_debug,
    wrapper,
    context::{is_stage_context, Context},
};
use ani_rs::{
    business_error::BusinessError,
    objects::{AniObject, AniRef},
    AniEnv,
};
use std::ffi::CStr;

#[ani_rs::native]
pub fn import_vcard(
    env: &AniEnv,
    context: AniRef,
    filePath: String,
    accountId: Option<i32>,
) -> Result<(), BusinessError> {
    let context = AniObject::from(context);
    telephony_debug!("is {}", is_stage_context(env, &context));
    let context = Context::new(env, &context);
    let account = accountId.unwrap_or(0);
    let arkts_error = wrapper::ffi::ImportVcard(context.inner, filePath, account);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }
    Ok(())
}

#[ani_rs::native]
pub fn export_vcard(
    env: &AniEnv,
    context: AniRef,
    predicates: AniRef,
    options: Option<AniVCardBuilderOptions>,
) -> Result<String, BusinessError> {
    let mut filePath = String::new();
    let context = AniObject::from(context);
    telephony_debug!("is {}", is_stage_context(env, &context));
    let context = Context::new(env, &context);
    let predicates = AniObject::from(predicates);
    let predicates_ptr = get_native_ptr(&env, &predicates);
    let options = options.unwrap_or_default();
    let card_type = options.cardType.unwrap_or(VCardType::VERSION_21);
    let charset = options.charset.unwrap_or_else(|| "UTF-8".to_string());
    let arkts_error = wrapper::ffi::ExportVcard(
        context.inner,
        predicates_ptr,
        card_type as i32,
        charset,
        &mut filePath,
    );
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(filePath)
}

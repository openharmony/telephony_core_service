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

use crate::{bridge::{ResetOption, ResultCode}, wrapper};


#[ani_rs::native]
pub fn reset_memory(slot_id: i32, options: Option<ResetOption>) -> Result<ResultCode, BusinessError> {
    let mut result_code = 0;

    let opts = options.unwrap_or(ResetOption::DeleteOperationalProfiles);
    let arkts_error = wrapper::ffi::resetMemory(slot_id, opts.into(), &mut result_code);
    if arkts_error.is_error() {
        return Err(BusinessError::from(arkts_error));
    }

    Ok(ResultCode::from(result_code))
}
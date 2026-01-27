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

use ani_rs::objects::AniObject;
use ani_rs::AniEnv;
use cxx::SharedPtr;

use crate::wrapper;

#[inline]
pub fn is_stage_context(env: &AniEnv, ani_object: &AniObject) -> bool {
    let env = env as *const AniEnv as *mut AniEnv as *mut wrapper::AniEnv;
    let ani_object = ani_object as *const AniObject as *mut AniObject as *mut wrapper::AniObject;
    unsafe { wrapper::ffi::IsStageContext(env, ani_object) }
}

pub struct Context {
    pub inner: SharedPtr<wrapper::ffi::Context>,
}

impl Context {
    pub fn new(env: &AniEnv, ani_object: &AniObject) -> Self {
        let env = env as *const AniEnv as *mut AniEnv as *mut *mut wrapper::AniEnv;
        let ani_object =
            ani_object as *const AniObject as *mut AniObject as *mut wrapper::AniObject;
        let inner = unsafe { wrapper::ffi::GetStageModeContext(env, ani_object) };
        Self { inner }
    }
}

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

use ani_rs::{business_error::BusinessError, objects::GlobalRefCallback};

use crate::{
    bridge::{ImsRegInfoAni, ImsServiceType},
    telephony_error, wrapper,
};
use std::{
    ops::Deref,
    sync::{Mutex, OnceLock},
};

#[derive(Clone)]
pub struct EventListener {
    slot_id: i32,
    ims_srv_type: ImsServiceType,
    callback_ref: GlobalRefCallback<(ImsRegInfoAni,)>,
}

impl EventListener {
    pub fn new(
        slot_id: i32,
        ims_srv_type: ImsServiceType,
        callback_ref: GlobalRefCallback<(ImsRegInfoAni,)>,
    ) -> Self {
        Self {
            ims_srv_type,
            slot_id,
            callback_ref,
        }
    }
}

pub struct Register {
    inner: Mutex<Vec<EventListener>>,
}

impl Register {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }

    pub fn get_instance() -> &'static Self {
        static INSTANCE: OnceLock<Register> = OnceLock::new();
        INSTANCE.get_or_init(Register::new)
    }

    pub fn insert_ims_reg_callback(
        &self,
        listener_list: &mut Vec<EventListener>,
        listener: EventListener,
    ) {
        for item in listener_list.iter() {
            if item.slot_id == listener.slot_id && item.ims_srv_type == listener.ims_srv_type {
                telephony_error!("[slot {}] callback is existent", listener.slot_id);
                return;
            }
        }
        listener_list.push(listener);
    }

    pub fn remove_ims_reg_callback(
        &self,
        listener_list: &mut Vec<EventListener>,
        slot_id: i32,
        ims_srv_type: ImsServiceType,
    ) {
        listener_list.retain(|listener| {
            if listener.slot_id == slot_id && listener.ims_srv_type == ims_srv_type {
                false
            } else {
                true
            }
        });
    }

    pub fn register(&self, listener: EventListener) -> Result<(), BusinessError> {
        let mut inner = self.inner.lock().unwrap();
        self.insert_ims_reg_callback(&mut inner, listener.clone());

        let arkts_error = wrapper::ffi::EventListenerRegister(
            listener.slot_id,
            listener.ims_srv_type.clone() as i32,
        );
        if arkts_error.is_error() {
            self.remove_ims_reg_callback(
                &mut inner,
                listener.slot_id,
                listener.ims_srv_type.clone(),
            );
            telephony_error!(
                "[slot{}] Register imsRegState callback failed, type {:?}",
                listener.slot_id,
                listener.ims_srv_type
            );
            return Err(BusinessError::from(arkts_error));
        }
        Ok(())
    }

    pub fn unregister(
        &self,
        slot_id: i32,
        ims_srv_type: ImsServiceType,
    ) -> Result<(), BusinessError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.is_empty() {
            telephony_error!("UnregisterEventListener listener Vec is empty.");
            return Ok(());
        }
        self.remove_ims_reg_callback(&mut inner, slot_id, ims_srv_type.clone());
        let arkts_error = wrapper::ffi::EventListenerUnRegister(slot_id, ims_srv_type as i32);
        if arkts_error.is_error() {
            return Err(BusinessError::from(arkts_error));
        }

        Ok(())
    }

    pub fn execute_on_ims_reg_state_change(
        &self,
        slot_id: i32,
        ims_srv_type: ImsServiceType,
        ims_reg_state: i32,
        ims_reg_tech: i32,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if inner.is_empty() {
            telephony_error!("Callback vec is empty");
            return;
        }
        let argv = ImsRegInfoAni::new(ims_reg_state, ims_reg_tech);

        for item in inner.deref() {
            if item.slot_id == slot_id && item.ims_srv_type == ims_srv_type {
                item.callback_ref.execute((argv,));
                break;
            }
        }
    }
}

pub fn on_ims_reg_info_change(
    slot_id: i32,
    ims_srv_type: i32,
    ims_reg_state: i32,
    ims_reg_tech: i32,
) {
    let ims_srv_type = ImsServiceType::from(ims_srv_type);
    Register::get_instance().execute_on_ims_reg_state_change(
        slot_id,
        ims_srv_type,
        ims_reg_state,
        ims_reg_tech,
    );
}

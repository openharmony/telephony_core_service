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
use ffi:: {ArktsError, OperatorIdAni, AccessRuleAni, EuiccProfileAni, GetEuiccProfileInfoListResultAni,
    DownloadProfileResultAni, DownloadConfigurationAni, DownloadableProfileAni, GetDownloadableProfileMetadataResultAni };
use crate::bridge::{ AccessRule, EuiccProfile, GetEuiccProfileInfoListResult, OperatorId, PolicyRules, ProfileClass,
    ProfileState, ResultCode, DownloadProfileResult, SolvableErrors, DownloadConfiguration, DownloadableProfile,
    GetDownloadableProfileMetadataResult };

pub const TELEPHONY_SUCCESS: i32 = 3120000;

#[cxx::bridge(namespace = "OHOS::Telephony::EsimAni")]
pub mod ffi {
    struct ArktsError {
        errorCode: i32,
        errorMessage: String,
    }

    struct OperatorIdAni {
        mcc: String,
        mnc: String,
        gid1: String,
        gid2: String,
    }

    struct AccessRuleAni {
        certificateHashHexStr: String,
        packageName: String,
        accessType: i32,
    }

    struct EuiccProfileAni {
        iccid: String,
        nickName: String,
        serviceProviderName: String,
        profileName: String,
        state: i32,
        profileClass: i32,
        operatorId: OperatorIdAni,
        policyRules: i32,
        accessRules: Vec<AccessRuleAni>,
    }
    struct GetEuiccProfileInfoListResultAni {
        responseResult: i32,
        profiles: Vec<EuiccProfileAni>,
        isRemovable: bool,
    }

    struct DownloadProfileResultAni {
        responseResult: i32,
        solvableErrors: i32,
        cardId: i32,
    }

    struct DownloadConfigurationAni {
        pub switchAfterDownload: bool,
        pub forceDisableProfile: bool,
        pub isPprAllowed: bool,
    }

    struct DownloadableProfileAni {
        pub activationCode: String,
        pub confirmationCode: String,
        pub carrierName: String,
        pub accessRules: Vec<AccessRuleAni>,
    }

    struct GetDownloadableProfileMetadataResultAni {
        pub downloadableProfile: DownloadableProfileAni,
        pub pprType: i32,
        pub pprFlag: bool,
        pub iccid: String,
        pub serviceProviderName: String,
        pub profileName: String,
        pub profileClass: i32,
        pub solvableErrors: i32,
        pub responseResult: i32,
    }

    unsafe extern "C++" {
        include!("ani_esim.h");

        fn IsSupported(slotId: i32, isSupportedResult: &mut bool) -> ArktsError;
        fn AddProfile(profileAni: &DownloadableProfileAni, addProfileResult: &mut bool) -> ArktsError;
        fn GetEid(slotId: i32, eid: &mut String) -> ArktsError;
        fn GetOsuStatus(slotId: i32, osu_status: &mut i32) -> ArktsError;
        fn StartOsu(slotId: i32, osu_status: &mut i32) -> ArktsError;
        fn GetDownloadableProfileMetadata(slotId: i32, portIndex: i32, profile: &DownloadableProfileAni,
            force_disable_profile: bool, metadataResult: &mut GetDownloadableProfileMetadataResultAni) -> ArktsError;
        fn GetDownloadableProfiles(slotId: i32, portIndex: i32, force_disable_profile: bool, resultCode: &mut i32,
            profiles: &mut Vec<DownloadableProfileAni>) -> ArktsError;
        fn DownloadProfile(slotId: i32, portIndex: i32, profile: &DownloadableProfileAni,
            config: &DownloadConfigurationAni, profileResult: &mut DownloadProfileResultAni) -> ArktsError;
        fn GetEuiccProfileInfoList(slotId: i32, infoListResult: &mut GetEuiccProfileInfoListResultAni) -> ArktsError;
        fn ResetMemory(slotId: i32, options: i32, resultCode: &mut i32) -> ArktsError;
        fn GetEuiccInfo(slotId: i32, euiccInfo: &mut String) -> ArktsError;
        fn DeleteProfile(slotId: i32, iccid: String, resultCode: &mut i32) -> ArktsError;
        fn SwitchToProfile(slotId: i32, port_index: i32, iccid: String, force_disable_profile: bool,
                resultCode: &mut i32) -> ArktsError;
        fn SetProfileNickname(slotId: i32, iccid: String, nickname: String, resultCode: &mut i32) -> ArktsError;
        fn ReserveProfilesForFactoryRestore(slotId: i32, resultCode: &mut i32) -> ArktsError;
        fn SetDefaultSmdpAddress(slotId: i32, address: String, resultCode: &mut i32) -> ArktsError;
        fn GetDefaultSmdpAddress(slotId: i32, address: &mut String) -> ArktsError;
        fn CancelSession(slotId: i32, transactionId: String, cancelReason: i32, resultCode: &mut i32) -> ArktsError;
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

impl From<OperatorIdAni> for OperatorId {
    fn from(value: OperatorIdAni) -> Self {
        Self {
            mcc: value.mcc,
            mnc: value.mnc,
            gid1: value.gid1,
            gid2: value.gid2,
        }
    }
}

impl From<AccessRuleAni> for AccessRule {
    fn from(value: AccessRuleAni) -> Self {
        Self {
            certificate_hash_hex_str: value.certificateHashHexStr,
            package_name: value.packageName,
            access_type: value.accessType,
        }
    }
}

impl From<AccessRule> for AccessRuleAni {
    fn from(value: AccessRule) -> Self {
        Self {
            certificateHashHexStr: value.certificate_hash_hex_str,
            packageName: value.package_name,
            accessType: value.access_type,
        }
    }
}

impl From<EuiccProfileAni> for EuiccProfile {
    fn from(value: EuiccProfileAni) -> Self {
        Self {
            iccid: value.iccid,
            nick_name: value.nickName,
            service_provider_name: value.serviceProviderName,
            profile_name: value.profileName,
            state: ProfileState::from(value.state),
            profile_class: ProfileClass::from(value.profileClass),
            operator_id: OperatorId::from(value.operatorId),
            policy_rules: PolicyRules::from(value.policyRules),
            access_rules: value.accessRules.into_iter().map(|rule| AccessRule::from(rule)).collect(),
        }
    }
}

impl GetEuiccProfileInfoListResultAni {
    pub fn new() -> Self {
        Self {
            responseResult: 0,
            profiles: vec![],
            isRemovable: false,
        }
    }
}

impl From<GetEuiccProfileInfoListResultAni> for GetEuiccProfileInfoListResult {
    fn from(value: GetEuiccProfileInfoListResultAni) -> Self {
        Self {
            response_result: ResultCode::from(value.responseResult),
            profiles: value.profiles.into_iter().map(|profile| EuiccProfile::from(profile)).collect(),
            is_removable: value.isRemovable,
        }
    }
}

impl DownloadProfileResultAni {
    pub fn new() -> Self {
        Self {
            responseResult: 0,
            solvableErrors: 0,
            cardId: 0,
        }
    }
}

impl From<DownloadProfileResultAni> for DownloadProfileResult {
    fn from(value: DownloadProfileResultAni) -> Self {
        Self {
            response_result: ResultCode::from(value.responseResult),
            solvable_errors: SolvableErrors::from(value.solvableErrors),
            card_id: value.cardId,
        }
    }
}

impl From<DownloadConfiguration> for DownloadConfigurationAni {
    fn from(value: DownloadConfiguration) -> Self {
        Self {
            switchAfterDownload: value.switch_after_download,
            forceDisableProfile: value.force_disable_profile,
            isPprAllowed: value.is_ppr_allowed,
        }
    }
 }

 impl DownloadableProfileAni {
    pub fn new() -> Self {
        Self {
            activationCode: "".to_string(),
            confirmationCode: "".to_string(),
            carrierName: "".to_string(),
            accessRules: vec![],
        }
    }
 }

 impl From<DownloadableProfile> for DownloadableProfileAni {
    fn from(value: DownloadableProfile) -> Self {
        Self {
            activationCode: value.activation_code,
            confirmationCode: value.confirmation_code.unwrap_or_default(),
            carrierName: value.carrier_name.unwrap_or_default(),
            accessRules: value.access_rules.unwrap_or_default().into_iter().map(|rule: AccessRule| rule.into()).collect(),
        }
    }
 }

 impl From<DownloadableProfileAni> for DownloadableProfile { 
    fn from(value: DownloadableProfileAni) -> Self {
        Self {
            activation_code: value.activationCode,
            confirmation_code: Some(value.confirmationCode),
            carrier_name: Some(value.carrierName),
            access_rules: Some(value.accessRules.into_iter().map(|rule: AccessRuleAni| rule.into()).collect()),
        }
    }
 }

 impl GetDownloadableProfileMetadataResultAni {
    pub fn new() -> Self {
        Self {
            downloadableProfile: DownloadableProfileAni::new(),
            pprType: 0,
            pprFlag: false,
            iccid: "".to_string(),
            serviceProviderName: "".to_string(),
            profileName: "".to_string(),
            profileClass: 0,
            solvableErrors: 0,
            responseResult: 0,
        }
    }
 }

 impl From<GetDownloadableProfileMetadataResultAni> for GetDownloadableProfileMetadataResult {
    fn from(value: GetDownloadableProfileMetadataResultAni) -> Self {
        Self {
            downloadable_profile: value.downloadableProfile.into(),
            ppr_type: value.pprType,
            ppr_flag: value.pprFlag,
            iccid: value.iccid,
            service_provider_name: value.serviceProviderName,
            profile_name: value.profileName,
            profile_class: value.profileClass.into(),
            solvable_errors: value.solvableErrors.into(),
            response_result: value.responseResult.into(),
        }
    }
 }
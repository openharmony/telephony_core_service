/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sim_file.h"

#include "common_event_manager.h"
#include "radio_event.h"

using namespace std;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Telephony {
void SimFile::InitMemberFunc()
{
    InitBaseMemberFunc();
    InitObtainMemberFunc();
    InitPlmnMemberFunc();
}

void SimFile::InitBaseMemberFunc()
{
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_READY] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessIccReady(event); };
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_LOCKED] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessIccLocked(event); };
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_SIMLOCK] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessIccLocked(event); };
    memberFuncMap_[SimFile::RELOAD_ICCID_EVENT] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessReloadIccid(event); };
    memberFuncMap_[SimFile::RELOAD_IMSI_EVENT] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessReloadImsi(event); };
    memberFuncMap_[MSG_SIM_SET_MSISDN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSetMsisdnDone(event); };
    memberFuncMap_[MSG_SIM_UPDATE_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessUpdateDone(event); };
    memberFuncMap_[MSG_SIM_MARK_SMS_READ_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessMarkSms(event); };
    memberFuncMap_[MSG_SIM_SMS_ON_SIM] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSmsOnSim(event); };
    memberFuncMap_[MSG_SIM_SET_MBDN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSetMbdn(event); };
    memberFuncMap_[MSG_SIM_SET_CPHS_MAILBOX_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSetCphsMailbox(event); };
}

void SimFile::InitObtainMemberFunc()
{
    memberFuncMap_[MSG_SIM_OBTAIN_IMSI_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainIMSIDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_ICCID_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetIccIdDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_MBI_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetMbiDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_CPHS_MAILBOX_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetCphsMailBoxDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_MBDN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetMbdnDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_MSISDN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetMsisdnDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_MWIS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetMwisDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_VOICE_MAIL_INDICATOR_CPHS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessVoiceMailCphs(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_AD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetAdDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_LI_LANGUAGE_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainLiLanguage(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_PL_LANGUAGE_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainPlLanguage(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_CFF_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetCffDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_SPDI_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetSpdiDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_PNN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetPnnDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_OPL_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetOplDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_OPL5G_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetOpl5gDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_ALL_SMS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetAllSmsDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_SMS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetSmsDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_SST_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetSstDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_INFO_CPHS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetInfoCphs(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_CFIS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetCfisDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_CSP_CPHS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetCspCphs(event); };
}

void SimFile::InitPlmnMemberFunc()
{
    memberFuncMap_[MSG_SIM_OBTAIN_SPN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainSpnPhase(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_GID1_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainGid1Done(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_GID2_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainGid2Done(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_PLMN_W_ACT_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetPlmnActDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_OPLMN_W_ACT_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetOplmnActDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_HPLMN_W_ACT_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetHplmActDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_EHPLMN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetEhplmnDone(event); };
    memberFuncMap_[MSG_SIM_OBTAIN_FPLMN_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetFplmnDone(event); };
}
} // namespace telephony
} // namespace OHOS
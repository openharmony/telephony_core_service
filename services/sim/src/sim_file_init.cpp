/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use & file except in compliance with the License.
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

#include "sim_file_init.h"

#include <unistd.h>

#include "radio_event.h"

namespace OHOS {
namespace Telephony {
void SimFileInit::InitMemberFunc(SimFile &simFile)
{
    InitBaseMemberFunc(simFile);
    InitObtainMemberFunc(simFile);
    InitPlmnMemberFunc(simFile);
}

void SimFileInit::InitBaseMemberFunc(SimFile &simFile)
{
    simFile.memberFuncMap_[RadioEvent::RADIO_SIM_STATE_READY] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessIccReady(event); };
    simFile.memberFuncMap_[RadioEvent::RADIO_SIM_STATE_LOCKED] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessIccLocked(event); };
    simFile.memberFuncMap_[RadioEvent::RADIO_SIM_STATE_SIMLOCK] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessIccLocked(event); };
    simFile.memberFuncMap_[SimFile::RELOAD_ICCID_EVENT] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessReloadIccid(event); };
    simFile.memberFuncMap_[SimFile::RELOAD_IMSI_EVENT] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessReloadImsi(event); };
    simFile.memberFuncMap_[MSG_SIM_SET_MSISDN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessSetMsisdnDone(event); };
    simFile.memberFuncMap_[MSG_SIM_UPDATE_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessUpdateDone(event); };
    simFile.memberFuncMap_[MSG_SIM_MARK_SMS_READ_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessMarkSms(event); };
    simFile.memberFuncMap_[MSG_SIM_SMS_ON_SIM] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessSmsOnSim(event); };
    simFile.memberFuncMap_[MSG_SIM_SET_MBDN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessSetMbdn(event); };
    simFile.memberFuncMap_[MSG_SIM_SET_CPHS_MAILBOX_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessSetCphsMailbox(event); };
}

void SimFileInit::InitObtainMemberFunc(SimFile &simFile)
{
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_IMSI_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessObtainIMSIDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_ICCID_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetIccIdDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_MBI_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetMbiDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_CPHS_MAILBOX_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetCphsMailBoxDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_MBDN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetMbdnDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_MSISDN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetMsisdnDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_MWIS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetMwisDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_VOICE_MAIL_INDICATOR_CPHS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessVoiceMailCphs(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_AD_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetAdDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_LI_LANGUAGE_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessObtainLiLanguage(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_PL_LANGUAGE_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessObtainPlLanguage(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_CFF_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetCffDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_SPDI_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetSpdiDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_PNN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetPnnDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_OPL_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetOplDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_OPL5G_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetOpl5gDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_ALL_SMS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetAllSmsDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_SMS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetSmsDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_SST_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetSstDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_INFO_CPHS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetInfoCphs(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_CFIS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetCfisDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_CSP_CPHS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetCspCphs(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_SPN_CPHS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetSpnCphsDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_SPN_SHORT_CPHS_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetSpnShortCphsDone(event); };
}

void SimFileInit::InitPlmnMemberFunc(SimFile &simFile)
{
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_SPN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessObtainSpnPhase(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_GID1_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessObtainGid1Done(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_GID2_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessObtainGid2Done(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_PLMN_W_ACT_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetPlmnActDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_OPLMN_W_ACT_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetOplmnActDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_HPLMN_W_ACT_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetHplmActDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_EHPLMN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetEhplmnDone(event); };
    simFile.memberFuncMap_[MSG_SIM_OBTAIN_FPLMN_DONE] =
        [&](const AppExecFwk::InnerEvent::Pointer &event) { return simFile.ProcessGetFplmnDone(event); };
}
}  // namespace Telephony
}  // namespace OHOS
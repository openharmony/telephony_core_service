/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "usim_file_controller.h"

namespace OHOS {
namespace Telephony {
UsimFileController::UsimFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : IccFileController(runner)
{}

std::string UsimFileController::ObtainElementFilePath(int efId)
{
    std::string path = ObtainUsimElementFilePath(efId);
    if (!path.empty()) {
        return path;
    }
    std::string mf = MASTER_FILE_SIM;
    path = ObtainElementFileForPublic(efId);
    if (path.empty()) {
        mf.append(DEDICATED_FILE_TELECOM);
        mf.append(DEDICATED_FILE_DIALLING_NUMBERS);
        return mf;
    }
    return path;
}

std::string UsimFileController::ObtainUsimElementFilePath(int efId)
{
    std::string mf = MASTER_FILE_SIM;
    switch (efId) {
        case ELEMENTARY_FILE_SMS:
        case ELEMENTARY_FILE_EXT5:
        case ELEMENTARY_FILE_EXT6:
        case ELEMENTARY_FILE_MWIS:
        case ELEMENTARY_FILE_MBI:
        case ELEMENTARY_FILE_SPN:
        case ELEMENTARY_FILE_AD:
        case ELEMENTARY_FILE_MBDN:
        case ELEMENTARY_FILE_PNN:
        case ELEMENTARY_FILE_OPL:
        case ELEMENTARY_FILE_SPDI:
        case ELEMENTARY_FILE_SST:
        case ELEMENTARY_FILE_CFIS:
        case ELEMENTARY_FILE_MAILBOX_CPHS:
        case ELEMENTARY_FILE_VOICE_MAIL_INDICATOR_CPHS:
        case ELEMENTARY_FILE_CFF_CPHS:
        case ELEMENTARY_FILE_SPN_CPHS:
        case ELEMENTARY_FILE_SPN_SHORT_CPHS:
        case ELEMENTARY_FILE_FDN:
        case ELEMENTARY_FILE_SDN:
        case ELEMENTARY_FILE_EXT3:
        case ELEMENTARY_FILE_MSISDN:
        case ELEMENTARY_FILE_EXT2:
        case ELEMENTARY_FILE_INFO_CPHS:
        case ELEMENTARY_FILE_CSP_CPHS:
        case ELEMENTARY_FILE_GID1:
        case ELEMENTARY_FILE_GID2:
        case ELEMENTARY_FILE_LI:
        case ELEMENTARY_FILE_PLMN_W_ACT:
        case ELEMENTARY_FILE_OPLMN_W_ACT:
        case ELEMENTARY_FILE_HPLMN_W_ACT:
        case ELEMENTARY_FILE_EHPLMN:
        case ELEMENTARY_FILE_FPLMN:
        case ELEMENTARY_FILE_LRPLMNSI:
        case ELEMENTARY_FILE_HPPLMN:
            mf.append(DEDICATED_FILE_ADF);
            return mf;
        case ELEMENTARY_FILE_PBR:
            mf.append(DEDICATED_FILE_TELECOM);
            mf.append(DEDICATED_FILE_DIALLING_NUMBERS);
            return mf;
        default:
            return "";
    }
}

UsimFileController::~UsimFileController() {}
} // namespace Telephony
} // namespace OHOS

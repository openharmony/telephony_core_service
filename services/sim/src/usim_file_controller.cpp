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
UsimFileController::UsimFileController(int slotId) : IccFileController("UsimFileController", slotId) {}

const std::string DEDICATED_FILE_TELE = "7F10";

const std::map<int, std::string> usimElementFilePathMap = {
    {ELEMENTARY_FILE_SMS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_EXT5, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_EXT6, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_MWIS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_MBI, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_SPN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_AD, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_MBDN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_PNN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_OPL, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_SPDI, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_SST, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_CFIS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_MAILBOX_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_VOICE_MAIL_INDICATOR_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_CFF_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_SPN_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_SPN_SHORT_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_FDN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_SDN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_EXT3, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_MSISDN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_EXT2, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_INFO_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_CSP_CPHS, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_GID1, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_GID2, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_LI, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_PLMN_W_ACT, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_OPLMN_W_ACT, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_HPLMN_W_ACT, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_EHPLMN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_FPLMN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_LRPLMNSI, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_HPPLMN, DEDICATED_FILE_ADF},
    {ELEMENTARY_FILE_PBR, DEDICATED_FILE_TELE + DEDICATED_FILE_DIALLING_NUMBERS},
    {ELEMENTARY_FILE_OPL5G, DEDICATED_FILE_ADF + DEDICATED_FILE_DF5GS}
};

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
    auto it = usimElementFilePathMap.find(efId);
    if (it != usimElementFilePathMap.end()) {
        return mf.append(it->second);
    } else {
        return "";
    }
}

UsimFileController::~UsimFileController() {}
} // namespace Telephony
} // namespace OHOS

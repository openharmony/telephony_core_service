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

#include "csim_file_controller.h"

namespace OHOS {
namespace Telephony {
CsimFileController::CsimFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : IccFileController(runner)
{}

std::string CsimFileController::ObtainElementFilePath(int efId)
{
    std::string mf = MASTER_FILE_SIM;
    if (efId == ELEMENTARY_FILE_SMS || efId == ELEMENTARY_FILE_CST || efId == ELEMENTARY_FILE_FDN ||
        efId == ELEMENTARY_FILE_MSISDN || efId == ELEMENTARY_FILE_RUIM_SPN || efId == ELEMENTARY_FILE_CSIM_LI ||
        efId == ELEMENTARY_FILE_CSIM_MDN || efId == ELEMENTARY_FILE_CSIM_IMSIM ||
        efId == ELEMENTARY_FILE_CSIM_CDMAHOME || efId == ELEMENTARY_FILE_CSIM_EPRL ||
        efId == ELEMENTARY_FILE_CSIM_MIPUPP) {
        mf.append(DEDICATED_FILE_ADF);
        return mf;
    }
    std::string path = ObtainElementFileForPublic(efId);
    if (!path.empty()) {
        return path;
    }
    mf.append(DEDICATED_FILE_TELECOM);
    mf.append(DEDICATED_FILE_DIALLING_NUMBERS);
    return mf;
}

CsimFileController::~CsimFileController() {}
} // namespace Telephony
} // namespace OHOS

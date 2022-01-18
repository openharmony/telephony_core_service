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

#include "ruim_file_controller.h"

namespace OHOS {
namespace Telephony {
RuimFileController::RuimFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner, int slotId)
    : IccFileController(runner, slotId)
{}

std::string RuimFileController::ObtainElementFilePath(int efId)
{
    if (efId == ELEMENTARY_FILE_SMS || efId == ELEMENTARY_FILE_CST || efId == ELEMENTARY_FILE_RUIM_SPN ||
        efId == ELEMENTARY_FILE_CSIM_LI || efId == ELEMENTARY_FILE_CSIM_MDN || efId == ELEMENTARY_FILE_CSIM_IMSIM ||
        efId == ELEMENTARY_FILE_CSIM_CDMAHOME || efId == ELEMENTARY_FILE_CSIM_EPRL) {
        return MASTER_FILE_SIM + DEDICATED_FILE_CDMA;
    }
    std::string path = ObtainElementFileForPublic(efId);
    if (path.empty()) {
        TELEPHONY_LOGE("Error: RuimFileController ElementFile Path get null string");
    }
    return path;
}

void RuimFileController::ObtainTransparentImg(
    int fileId, int highOffset, int lowOffset, int length, AppExecFwk::InnerEvent::Pointer &onLoaded)
{
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_SIM_OBTAIN_ICON_DONE, fileId, 0, onLoaded);
    if (telRilManager_ != nullptr) {
        SimIoRequestInfo msg;
        msg.command = CONTROLLER_REQ_GET_RESPONSE;
        msg.fileId = fileId;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = GET_RESPONSE_ELEMENTARY_FILE_IMG_SIZE_BYTES;
        msg.data = "";
        msg.path = ObtainElementFilePath(ELEMENTARY_FILE_IMG);
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId_, msg, response);
    }
}

RuimFileController::~RuimFileController() {}
} // namespace Telephony
} // namespace OHOS

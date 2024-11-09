/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "esim_controller.h"

#include <algorithm>
#include <dlfcn.h>
#include <thread>

#include "ffrt.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

static const std::string CHECK_CMD_HEAD = "D0";
static const std::string CHECK_CMD_TAG = "81";
static const std::string CHECK_GET_INPUT_TAG = "23";
static const std::string VERIFY_BIND_START_DATA = "0456657269667942696E645374617274";
static const std::string VERIFY_BIND_END_DATA = "0456657269667942696E64456E64";
static const std::string ESIM_CA_LIBPATH = "libesim_ca.z.so";

constexpr size_t CHECK_CMD_HEAD_START = 0;
constexpr size_t CHECK_CMD_TAG_START = 4;
constexpr size_t CHECK_GET_INPUT_TAG_START = 10;
constexpr size_t GET_INPUT_DATA_START = 26;
constexpr size_t COMPARE_EQUAL_VALUE = 0;

EsimController::EsimController() {}

EsimController::~EsimController() {}

bool EsimController::ChecIsVerifyBindCommand(const std::string &cmdData)
{
    std::string checkCmdData = cmdData;
    std::transform(checkCmdData.begin(), checkCmdData.end(), checkCmdData.begin(), ::toupper);
    if (checkCmdData.compare(CHECK_CMD_HEAD_START, CHECK_CMD_HEAD.length(),
        CHECK_CMD_HEAD) != COMPARE_EQUAL_VALUE) {
        return false;
    }
    if (checkCmdData.compare(CHECK_CMD_TAG_START, CHECK_CMD_TAG.length(),
        CHECK_CMD_TAG) != COMPARE_EQUAL_VALUE) {
        return false;
    }
    if (checkCmdData.compare(CHECK_GET_INPUT_TAG_START, CHECK_GET_INPUT_TAG.length(),
        CHECK_GET_INPUT_TAG) != COMPARE_EQUAL_VALUE) {
        return false;
    }
    if (checkCmdData.compare(GET_INPUT_DATA_START, VERIFY_BIND_START_DATA.length(),
        VERIFY_BIND_START_DATA) == COMPARE_EQUAL_VALUE) {
        return true;
    }
    return (checkCmdData.compare(GET_INPUT_DATA_START, VERIFY_BIND_END_DATA.length(),
        VERIFY_BIND_END_DATA) == COMPARE_EQUAL_VALUE);
}

void EsimController::ProcessCommandMessage(int slotId, const std::string &cmdData)
{
    TELEPHONY_LOGI("EsimController:Start process verify bind message.");
    ffrt::submit([=]() {
        this->ProcessCommandByCa(slotId, cmdData);
    });
}

void EsimController::ProcessCommandByCa(int slotId, const std::string &cmdData)
{
    std::lock_guard<std::mutex> locker(caMutex_);
    void *handler = dlopen(ESIM_CA_LIBPATH.c_str(), RTLD_LAZY);
    if (handler == NULL) {
        TELEPHONY_LOGE("open lib: %{public}s failed", ESIM_CA_LIBPATH.c_str());
        return;
    }

    VerifyBind func = (VerifyBind)dlsym(handler, "CAEsimStartEuiccCheckBinding");
    if (func == NULL) {
        TELEPHONY_LOGE("dlsym CAEsimStartEuiccCheckBinding failed, error:%{public}s", dlerror());
    } else {
        func(slotId, cmdData.c_str(), cmdData.length());
    }
    dlclose(handler);
}
} // namespace Telephony
} // namespace OHOS

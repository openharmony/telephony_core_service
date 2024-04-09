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

#ifndef CORE_SERVICE_TEST_CODE_H
#define CORE_SERVICE_TEST_CODE_H

namespace OHOS {
namespace Telephony {
extern "C" {
enum CoreServiceTestCode {
    REGISTER_SIM_ACCOUNT_CODE = 1,
    UNREGISTER_SIM_ACCOUNT_CODE,
    REGISTER_IMS_REG_CODE,
    UNREGISTER_IMS_REG_CODE,
    ADD_STATE_OBSERVER,
    REMOVE_STATE_OBSERVER,
};
} // end extern
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_TEST_CODE_H

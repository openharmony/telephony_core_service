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

#ifndef OHOS_I_SIM_SMS_MANAGER_H
#define OHOS_I_SIM_SMS_MANAGER_H

namespace OHOS {
namespace Telephony {
class ISimSmsManager {
public:
    virtual void Init() {}
    virtual bool AddSmsToIcc(int status, std::string &pdu, std::string &smsc) = 0;
    virtual bool RenewSmsIcc(int index, int status, std::string &pduData, std::string &smsc) = 0;
    virtual bool DelSmsIcc(int index) = 0;
    virtual std::vector<std::string> ObtainAllSmsOfIcc() = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif

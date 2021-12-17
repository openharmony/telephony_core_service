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

#ifndef OHOS_I_SIM_FILE_MANAGER_H
#define OHOS_I_SIM_FILE_MANAGER_H

namespace OHOS {
namespace Telephony {
class ISimFileManager {
public:
    using HANDLE = std::shared_ptr<AppExecFwk::EventHandler>;
    virtual void Init() {}
    virtual std::u16string GetSimOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetISOCountryCodeForSim(int32_t slotId) = 0;
    virtual std::u16string GetSimSpn(int32_t slotId) = 0;
    virtual std::u16string GetSimIccId(int32_t slotId) = 0;
    virtual std::u16string GetIMSI(int32_t slotId) = 0;
    virtual std::u16string GetLocaleFromDefaultSim() = 0;
    virtual std::u16string GetSimGid1(int32_t slotId) = 0;
    virtual std::u16string GetSimTelephoneNumber(int32_t slotId) = 0;
    virtual std::u16string GetVoiceMailIdentifier(int32_t slotId) = 0;
    virtual std::u16string GetVoiceMailNumber(int32_t slotId) = 0;
    virtual int ObtainSpnCondition(bool roaming, std::string operatorNum) = 0;
    virtual void RegisterCoreNotify(const HANDLE &handler, int what) = 0;
    virtual void UnRegisterCoreNotify(const HANDLE &observerCallBack, int what) = 0;
    virtual void SetImsi(std::string imsi) = 0;
    virtual bool SetVoiceMailInfo(
        int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif

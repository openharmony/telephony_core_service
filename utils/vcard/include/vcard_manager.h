/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_VCARD_MANAGER_H
#define OHOS_VCARD_MANAGER_H

#include "mutex"
#include "vcard_configuration.h"
#include "vcard_contact.h"
#include "vcard_decoder.h"

namespace OHOS {
namespace Telephony {
class VCardManager {
public:
    int32_t Import(const std::string &path, int32_t accountId);
    int32_t ImportLock(
        const std::string &path, std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, int32_t accountId);
    int32_t Export(std::string &path, const DataShare::DataSharePredicates &predicates,
        int32_t cardType = VCardConfiguration::VER_21, const std::string &charset = "UTF-8");
    int32_t ExportLock(std::string &path, std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const DataShare::DataSharePredicates &predicates, int32_t cardType = VCardConfiguration::VER_21,
        const std::string &charset = "UTF-8");
    int32_t ExportToStr(std::string &str, const DataShare::DataSharePredicates &predicates,
        int32_t cardType = VCardConfiguration::VER_21, const std::string &charset = "UTF-8");
    void SetDataHelper(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper);
    void OnStarted();
    void OnEnded();
    void OnOneContactStarted();
    void OnOneContactEnded();
    void OnRawDataCreated(std::shared_ptr<VCardRawData> rawData);
    static VCardManager &GetInstance();
    void Release();

private:
    class DecodeListener : public VCardDecodeListener {
    public:
        virtual void OnStarted();
        virtual void OnEnded();
        virtual void OnOneContactStarted();
        virtual void OnOneContactEnded();
        virtual void OnRawDataCreated(std::shared_ptr<VCardRawData> rawData);
        std::vector<std::shared_ptr<VCardContact>> &GetContacts();

    private:
        std::vector<std::shared_ptr<VCardContact>> contacts_;
        std::shared_ptr<VCardContact> currentContact_;
    };

private:
    VCardManager();
    void Decode(const std::string &path, int32_t &errorCode);
    void InsertContactDbAbility(int32_t accountId, int32_t &errorCode);
    int32_t InsertRawContact(int32_t accountId, std::shared_ptr<VCardContact> contact);
    bool IsAccountIdExit(int32_t accountId);
    int32_t InsertContactData(int32_t rawId, std::shared_ptr<VCardContact> contact);
    bool IsContactsIdExit(int32_t accountId);
    int32_t GetAccountId();
    bool ParameterTypeAndCharsetCheck(int32_t cardType, std::string charset, int32_t &errorCode);
    std::vector<std::vector<std::shared_ptr<VCardContact>>> SplitContactsVector(
        std::vector<std::shared_ptr<VCardContact>> list, size_t step);
    void BatchInsertContactDbAbility(int32_t accountId, int32_t &errorCode);
    void BatchInsertRawContact(int32_t accountId, uint32_t size, std::vector<int32_t> &rawIds, int32_t &errorCode,
        const std::vector<std::shared_ptr<VCardContact>> &contactList);
    void BatchInsertContactData(std::vector<int32_t> &rawIds,
        const std::vector<std::shared_ptr<VCardContact>> &contactList, int32_t &errorCode);

private:
    std::shared_ptr<VCardManager::DecodeListener> listener_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_MANAGER_H

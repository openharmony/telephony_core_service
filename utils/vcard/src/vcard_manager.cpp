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

#include "vcard_manager.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_constant.h"
#include "vcard_encoder.h"
#include "vcard_file_utils.h"
#include "vcard_rdb_helper.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {
VCardManager::VCardManager()
{
    listener_ = std::make_shared<VCardManager::DecodeListener>();
}

std::vector<std::shared_ptr<VCardContact>> &VCardManager::DecodeListener::GetContacts()
{
    return contacts_;
}

void VCardManager::DecodeListener::OnStarted()
{
    contacts_.clear();
}

void VCardManager::DecodeListener::OnEnded()
{
    TELEPHONY_LOGI("OnEnded contact size %{public}d", static_cast<int32_t>(contacts_.size()));
    VCardDecoder::Close();
}

void VCardManager::DecodeListener::OnOneContactStarted()
{
    TELEPHONY_LOGI("OnOneContactStarted index %{public}d", static_cast<int32_t>(contacts_.size()));
    currentContact_ = std::make_shared<VCardContact>();
}

void VCardManager::DecodeListener::OnOneContactEnded()
{
    TELEPHONY_LOGI("OnOneContactEnded index %{public}d", static_cast<int32_t>(contacts_.size()));
    contacts_.push_back(currentContact_);
    currentContact_ = nullptr;
}

void VCardManager::DecodeListener::OnRawDataCreated(std::shared_ptr<VCardRawData> rawData)
{
    if (rawData == nullptr || currentContact_ == nullptr) {
        return;
    }
    int32_t errorCode = TELEPHONY_SUCCESS;
    currentContact_->AddRawData(rawData, errorCode);
}

int32_t VCardManager::ImportLock(
    const std::string &path, std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, int32_t accountId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("DataShareHelper is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    SetDataHelper(dataShareHelper);
    int32_t errorCode = Import(path, accountId);
    Release();
    TELEPHONY_LOGI("ImportLock errorCode : %{public}d finish", errorCode);
    return errorCode;
}

int32_t VCardManager::Import(const std::string &path, int32_t accountId)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    Decode(path, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Failed to decode");
        return errorCode;
    }
    BatchInsertContactDbAbility(accountId, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Failed to insert ability");
        return errorCode;
    }
    TELEPHONY_LOGI("Import size %{public}d success", static_cast<int32_t>(listener_->GetContacts().size()));
    return errorCode;
}

void VCardManager::Decode(const std::string &path, int32_t &errorCode)
{
    std::shared_ptr<VCardDecoder> decoder = VCardDecoder::Create(path, errorCode);
    if (decoder == nullptr || errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Failed to get decoder");
        return;
    }
    decoder->AddVCardDecodeListener(listener_);
    decoder->Decode(errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Failed to decode");
    }
}

void VCardManager::InsertContactDbAbility(int32_t accountId, int32_t &errorCode)
{
    if (listener_ == nullptr) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return;
    }
    if (listener_->GetContacts().size() == 0) {
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    for (std::shared_ptr<VCardContact> contact : listener_->GetContacts()) {
        auto rawId = InsertRawContact(accountId);
        if (rawId <= 0) {
            TELEPHONY_LOGE("Failed to insert raw contact");
            errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
            continue;
        }
        if (InsertContactData(rawId, contact) == TELEPHONY_ERROR) {
            TELEPHONY_LOGE("Insert contactData failed");
            errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
    }
}

void VCardManager::BatchInsertContactDbAbility(int32_t accountId, int32_t &errorCode)
{
    if (listener_ == nullptr) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return;
    }
    if (listener_->GetContacts().size() < BATCH_INSERT_MAX_SIZE) {
        TELEPHONY_LOGI("contactData < BATCH_INSERT_MAX_SIZE");
        InsertContactDbAbility(accountId, errorCode);
        return;
    }
    if (listener_->GetContacts().size() == 0) {
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    std::vector<std::vector<std::shared_ptr<VCardContact>>> splitList =
        SplitContactsVector(listener_->GetContacts(), BATCH_INSERT_MAX_SIZE);
    TELEPHONY_LOGI(
        "contactData > BATCH_INSERT_MAX_SIZE, split List size %{public}d", static_cast<int32_t>(splitList.size()));
    for (std::vector<std::shared_ptr<VCardContact>> list : splitList) {
        TELEPHONY_LOGI("List size %{public}d", static_cast<int32_t>(list.size()));
        std::vector<int32_t> rawIds;
        BatchInsertRawContact(accountId, list.size(), rawIds, errorCode);
        if (errorCode == TELEPHONY_ERROR) {
            TELEPHONY_LOGE("Failed to batch insert raw contact");
            continue;
        }
        BatchInsertContactData(rawIds, list, errorCode);
        if (errorCode == TELEPHONY_ERROR) {
            TELEPHONY_LOGE("Failed to batch insert contactData");
            continue;
        }
    }
}

void VCardManager::BatchInsertRawContact(
    int32_t accountId, uint32_t size, std::vector<int32_t> &rawIds, int32_t &errorCode)
{
    int32_t rawContactMaxId = VCardRdbHelper::GetInstance().QueryRawContactMaxId();
    std::vector<DataShare::DataShareValuesBucket> rawContactValues;
    for (uint32_t i = 0; i < size; i++) {
        OHOS::DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(RawContact::ACCOUNT_ID, GetAccountId());
        if (IsContactsIdExit(accountId)) {
            valuesBucket.Put(RawContact::CONTACT_ID, accountId);
        }
        rawContactValues.push_back(valuesBucket);
        rawIds.push_back(rawContactMaxId + i + 1);
    }
    VCardRdbHelper::GetInstance().BatchInsertRawContact(rawContactValues);
}

void VCardManager::BatchInsertContactData(
    std::vector<int32_t> &rawIds, const std::vector<std::shared_ptr<VCardContact>> &contactList, int32_t &errorCode)
{
    std::vector<DataShare::DataShareValuesBucket> contactDataValues;
    for (size_t i = 0; i < rawIds.size(); i++) {
        int32_t rawId = rawIds[i];
        TELEPHONY_LOGI("rawId %{public}d", rawId);
        std::shared_ptr<VCardContact> contact = contactList[i];
        if (contact == nullptr) {
            errorCode = TELEPHONY_ERROR;
            TELEPHONY_LOGE("contact is nullptr");
            continue;
        }
        contact->BuildContactData(rawId, contactDataValues);
        if (contactDataValues.empty()) {
            TELEPHONY_LOGE("no contactData insert");
            errorCode = TELEPHONY_ERROR;
        }
    }
    int ret = VCardRdbHelper::GetInstance().BatchInsertContactData(contactDataValues);
    if (ret == TELEPHONY_ERROR) {
        TELEPHONY_LOGE("batch insert contactDatat failed");
        errorCode = TELEPHONY_ERROR;
    }
}

std::vector<std::vector<std::shared_ptr<VCardContact>>> VCardManager::SplitContactsVector(
    std::vector<std::shared_ptr<VCardContact>> list, size_t step)
{
    std::vector<std::vector<std::shared_ptr<VCardContact>>> result;
    if (step >= list.size()) {
        result.push_back(list);
    } else {
        std::vector<std::shared_ptr<VCardContact>>::iterator curPtr = list.begin();
        std::vector<std::shared_ptr<VCardContact>>::iterator endPtr = list.end();
        std::vector<std::shared_ptr<VCardContact>>::iterator end;
        while (curPtr < endPtr) {
            end = static_cast<size_t>(endPtr - curPtr) > step ? (step + curPtr) : endPtr;
            step = static_cast<size_t>(endPtr - curPtr) > step ? step : (endPtr - curPtr);
            result.push_back(std::vector<std::shared_ptr<VCardContact>>(curPtr, end));
            curPtr += step;
        }
    }
    return result;
}

int32_t VCardManager::InsertRawContact(int32_t accountId)
{
    OHOS::DataShare::DataShareValuesBucket ValuesBucket;
    ValuesBucket.Put(RawContact::ACCOUNT_ID, GetAccountId());
    if (IsContactsIdExit(accountId)) {
        ValuesBucket.Put(RawContact::CONTACT_ID, accountId);
    }
    return VCardRdbHelper::GetInstance().InsertRawContact(ValuesBucket);
}

bool VCardManager::IsContactsIdExit(int32_t accountId)
{
    std::vector<std::string> columns;
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Contact::ID, std::to_string(accountId));
    auto resultSet = VCardRdbHelper::GetInstance().QueryContact(columns, predicates);
    if (resultSet == nullptr) {
        return false;
    }
    bool result = (resultSet->GoToFirstRow() == DataShare::E_OK);
    resultSet->Close();
    return result;
}

int32_t VCardManager::GetAccountId()
{
    std::vector<std::string> columns;
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Account::ACCOUNT_TYPE, "com.ohos.contacts");
    auto resultSet = VCardRdbHelper::GetInstance().QueryAccount(columns, predicates);
    if (resultSet == nullptr) {
        return -1;
    }
    resultSet->GoToFirstRow();
    int32_t index = 0;
    int32_t id = 0;
    resultSet->GetColumnIndex(Account::ID, index);
    resultSet->GetInt(index, id);
    resultSet->Close();
    return id;
}

bool VCardManager::IsAccountIdExit(int32_t accountId)
{
    std::vector<std::string> columns;
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Account::ID, std::to_string(accountId));
    auto resultSet = VCardRdbHelper::GetInstance().QueryAccount(columns, predicates);
    if (resultSet == nullptr) {
        return false;
    }
    bool result = (resultSet->GoToFirstRow() == DataShare::E_OK);
    resultSet->Close();
    return result;
}

int32_t VCardManager::InsertContactData(int32_t rawId, std::shared_ptr<VCardContact> contact)
{
    if (contact == nullptr) {
        return TELEPHONY_ERROR;
    }
    std::vector<DataShare::DataShareValuesBucket> contactDataValues;
    contact->BuildContactData(rawId, contactDataValues);
    if (contactDataValues.empty()) {
        TELEPHONY_LOGI("no data insert");
        return TELEPHONY_ERROR;
    }
    int ret = VCardRdbHelper::GetInstance().InsertContactData(contactDataValues);
    if (ret == TELEPHONY_ERROR) {
        TELEPHONY_LOGE("insert failed");
        return TELEPHONY_ERROR;
    }
    return TELEPHONY_SUCCESS;
}

bool VCardManager::ParameterTypeAndCharsetCheck(int32_t cardType, std::string charset, int32_t &errorCode)
{
    if (cardType < VERSION_21_NUM || cardType > VERSION_40_NUM) {
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return false;
    }
    if (!charset.empty() && !VCardUtils::EqualsIgnoreCase(DEFAULT_CHARSET, charset)) {
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return false;
    }
    errorCode = TELEPHONY_SUCCESS;
    return true;
}

int32_t VCardManager::ExportLock(std::string &path, std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const DataShare::DataSharePredicates &predicates, int32_t cardType, const std::string &charset)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("DataShareHelper is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    SetDataHelper(dataShareHelper);
    int32_t errorCode = Export(path, predicates, cardType, charset);
    Release();
    TELEPHONY_LOGI("ExportLock errorCode : %{public}d finish", errorCode);
    return errorCode;
}

int32_t VCardManager::Export(
    std::string &path, const DataShare::DataSharePredicates &predicates, int32_t cardType, const std::string &charset)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    if (!ParameterTypeAndCharsetCheck(cardType, charset, errorCode)) {
        return errorCode;
    }
    std::vector<std::string> columns;
    auto resultSet = VCardRdbHelper::GetInstance().QueryContact(columns, predicates);
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("QueryContact failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    std::string result = "";
    VCardEncoder encoder { cardType, charset };
    while (resultSetNum == 0 && errorCode == TELEPHONY_SUCCESS) {
        result += encoder.ContructVCard(resultSet, errorCode);
        resultSetNum = resultSet->GoToNextRow();
    }
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Export data failed");
        resultSet->Close();
        return errorCode;
    }
    if (path.empty()) {
        std::string fileName = VCardUtils::CreateFileName();
        path = VCARD_EXPORT_FILE_PATH + fileName;
    } else {
        path = path + VCardUtils::CreateFileName();
    }
    if (!result.empty()) {
        VCardUtils::SaveFile(result, path);
        resultSet->Close();
    } else {
        resultSet->Close();
        return TELEPHONY_ERROR;
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardManager::ExportToStr(
    std::string &str, const DataShare::DataSharePredicates &predicates, int32_t cardType, const std::string &charset)
{
    std::vector<std::string> columns;
    auto resultSet = VCardRdbHelper::GetInstance().QueryContact(columns, predicates);
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("QueryContact failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    VCardEncoder encoder { cardType, charset };
    int32_t errorCode = TELEPHONY_SUCCESS;
    str = "";
    while (resultSetNum == 0 && errorCode == TELEPHONY_SUCCESS) {
        str += encoder.ContructVCard(resultSet, errorCode);
        resultSetNum = resultSet->GoToNextRow();
    }
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Export data failed");
        resultSet->Close();
        return errorCode;
    }
    resultSet->Close();
    return TELEPHONY_SUCCESS;
}

void VCardManager::SetDataHelper(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper)
{
    VCardRdbHelper::GetInstance().SetDataHelper(dataShareHelper);
}

VCardManager &VCardManager::GetInstance()
{
    static VCardManager instance;
    return instance;
}

void VCardManager::Release()
{
    VCardRdbHelper::GetInstance().Release();
    if (listener_ != nullptr) {
        listener_->GetContacts().clear();
    }
}
} // namespace Telephony
} // namespace OHOS

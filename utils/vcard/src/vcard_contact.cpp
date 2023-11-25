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
#include "vcard_contact.h"

#include <numeric>

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_configuration.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {
std::mutex mutex_;
void VCardContact::Init() {}

void VCardContact::AddRawData(std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    if (rawData == nullptr) {
        return;
    }
    std::string name;
    std::string rawValue;
    std::string byte;
    std::vector<std::string> values;
    std::vector<std::string> groups;
    std::map<std::string, std::vector<std::string>> parasMap;
    name = rawData->GetName();
    rawValue = rawData->GetRawValue();
    byte = rawData->GetByte();
    values = rawData->GetValue();
    groups = rawData->GetGroup();
    parasMap = rawData->GetParasMap();
    if (values.size() == 0 && byte.empty()) {
        return;
    }
    std::string propValue = (values.size() != 0) ? VCardUtils::TrimListToString(values) : "";
    AddDatas(name, rawValue, byte, values, propValue, groups, parasMap);
}

void VCardContact::AddDatas(std::string name, std::string rawValue, std::string byte, std::vector<std::string> values,
    std::string propValue, std::vector<std::string> groups, std::map<std::string, std::vector<std::string>> parasMap)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (name == VCARD_TYPE_VERSION) {
        vCardType_ = rawValue;
    } else if (name == VCARD_TYPE_FN || name == VCARD_TYPE_NAME || name == VCARD_TYPE_N ||
               name == VCARD_TYPE_SORT_STRING || name == VCARD_TYPE_X_PHONETIC_FIRST_NAME ||
               name == VCARD_TYPE_X_PHONETIC_LAST_NAME || name == VCARD_TYPE_X_PHONETIC_MIDDLE_NAME) {
        AddNameData(name, rawValue, values, parasMap, propValue);
    } else if (name == VCARD_TYPE_NICKNAME) {
        HandleNickName(propValue);
    } else if (name == VCARD_TYPE_SOUND) {
        AddSoundDatas(rawValue, propValue, values, parasMap);
    } else if (name == VCARD_TYPE_ADR) {
        AddPostalDatas(rawValue, propValue, values, parasMap);
    } else if (name == VCARD_TYPE_EMAIL) {
        AddEmailsData(rawValue, propValue, values, parasMap);
    } else if (name == VCARD_TYPE_ORG) {
        AddOrganizationsData(rawValue, propValue, values, parasMap);
    } else if (name == VCARD_TYPE_TITLE) {
        HandleTitleValue((parasMap.size() != 0) ? propValue : rawValue);
    } else if (name == VCARD_TYPE_PHOTO || name == VCARD_TYPE_LOGO) {
        AddPhotoDatas(byte, rawValue, propValue, values, parasMap);
    } else if (name == VCARD_TYPE_TEL) {
        AddPhonesData(rawValue, propValue, values, parasMap);
    }
    AddOtherDatas(name, rawValue, byte, values, propValue, groups, parasMap);
}

void VCardContact::AddOtherDatas(std::string name, std::string rawValue, std::string byte,
    std::vector<std::string> values, std::string propValue, std::vector<std::string> groups,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    if (name == VCARD_TYPE_X_SKYPE_PSTNNUMBER) {
        AddSkypePstnNumDatas(propValue, parasMap);
    } else if (name == VCARD_TYPE_NOTE) {
        AddNote((parasMap.size() != 0) ? propValue : rawValue);
    } else if (name == VCARD_TYPE_URL) {
        AddWebSiteDatas(rawValue, propValue, values, parasMap);
    } else if (name == VCARD_TYPE_BDAY) {
        AddBirthdayDatas(rawValue);
    } else if (name == VCARD_TYPE_ANNIVERSARY) {
        AddAnniversaryDatas(propValue);
    } else if (name == VCARD_TYPE_IMPP) {
        AddImppDatas(propValue, parasMap);
    } else if (name == VCARD_TYPE_X_SIP) {
        AddSipData(rawValue, parasMap, propValue);
    } else if (name == VCARD_TYPE_X_OHOS_CUSTOM) {
        AddCustom(rawValue, parasMap, propValue);
    } else if (name == VCARD_TYPE_X_AIM || name == VCARD_TYPE_X_MSN || name == VCARD_TYPE_X_YAHOO ||
               name == VCARD_TYPE_X_ICQ || name == VCARD_TYPE_X_JABBER || name == VCARD_TYPE_X_QQ) {
        AddIms(name, rawValue, propValue, values, parasMap);
    } else {
        TELEPHONY_LOGI("No need to do anything");
    }
}

int32_t VCardContact::BuildContactData(int32_t rawId, std::vector<DataShare::DataShareValuesBucket> &contactDataValues)
{
    BuildValuesBucket(rawId, contactDataValues, nameData_);
    if (!birthday_->GetBirthday().empty()) {
        BuildValuesBucket(rawId, contactDataValues, birthday_);
    }
    if (!anniversary_->GetAnniversary().empty()) {
        BuildValuesBucket(rawId, contactDataValues, anniversary_);
    }
    BuildValuesBuckets(rawId, contactDataValues, phones_);
    BuildValuesBuckets(rawId, contactDataValues, emails_);
    BuildValuesBuckets(rawId, contactDataValues, postals_);
    BuildValuesBuckets(rawId, contactDataValues, organizations_);
    BuildValuesBuckets(rawId, contactDataValues, ims_);
    BuildValuesBuckets(rawId, contactDataValues, photos_);
    BuildValuesBuckets(rawId, contactDataValues, websites_);
    BuildValuesBuckets(rawId, contactDataValues, sips_);
    BuildValuesBuckets(rawId, contactDataValues, nicknames_);
    BuildValuesBuckets(rawId, contactDataValues, notes_);
    BuildValuesBuckets(rawId, contactDataValues, relations_);
    BuildValuesBuckets(rawId, contactDataValues, events_);
    return TELEPHONY_SUCCESS;
}

void VCardContact::BuildValuesBucket(int32_t rawId, std::vector<DataShare::DataShareValuesBucket> &contactDataValues,
    std::shared_ptr<VCardContactData> contactData)
{
    if (contactData == nullptr) {
        return;
    }
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ContactData::RAW_CONTACT_ID, std::to_string(rawId));
    contactData->BuildValuesBucket(valuesBucket);
    contactDataValues.push_back(valuesBucket);
}

template<typename T>
void VCardContact::BuildValuesBuckets(int32_t rawId, std::vector<DataShare::DataShareValuesBucket> &contactDataValues,
    std::vector<std::shared_ptr<T>> &contactDatas)
{
    for (auto data : contactDatas) {
        BuildValuesBucket(rawId, contactDataValues, data);
    }
}

int32_t VCardContact::BuildContact(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    while (resultSetNum == 0) {
        BuildOneData(resultSet);
        resultSetNum = resultSet->GoToNextRow();
    }
    return TELEPHONY_SUCCESS;
}

int32_t VCardContact::BuildOneData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int typeId = 0;
    int columnIndexType = 0;
    resultSet->GetColumnIndex(ContactData::TYPE_ID, columnIndexType);
    resultSet->GetInt(columnIndexType, typeId);
    switch (typeId) {
        case TypeId::NAME: {
            BuildData(resultSet, names_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::PHONE: {
            BuildData(resultSet, phones_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::RELATION: {
            BuildData(resultSet, relations_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::IM: {
            BuildData(resultSet, ims_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::SIP_ADDRESS: {
            BuildData(resultSet, sips_);
            return TELEPHONY_SUCCESS;
        }
        default:
            break;
    }
    return BuildOtherData(typeId, resultSet);
}

int32_t VCardContact::BuildOtherData(int32_t typeId, std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    switch (typeId) {
        case TypeId::NICKNAME: {
            BuildData(resultSet, nicknames_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::EMAIL: {
            BuildData(resultSet, emails_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::POSTAL_ADDRESS: {
            BuildData(resultSet, postals_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::ORGANIZATION: {
            BuildData(resultSet, organizations_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::WEBSITE: {
            BuildData(resultSet, websites_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::PHOTO: {
            BuildData(resultSet, photos_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::NOTE: {
            BuildData(resultSet, notes_);
            return TELEPHONY_SUCCESS;
        }
        case TypeId::CONTACT_EVENT: {
            BuildData(resultSet, events_);
            return TELEPHONY_SUCCESS;
        }
        default:
            break;
    }
    return TELEPHONY_SUCCESS;
}

template<typename T>
void VCardContact::BuildData(
    std::shared_ptr<DataShare::DataShareResultSet> resultSet, std::vector<std::shared_ptr<T>> &contactDatas)
{
    auto data = std::make_shared<T>();
    data->BuildData(resultSet);
    contactDatas.push_back(data);
}

std::shared_ptr<VCardNameData> VCardContact::GetNameData()
{
    return nameData_;
}

std::vector<std::shared_ptr<VCardNameData>> VCardContact::GetNames()
{
    return names_;
}

std::vector<std::shared_ptr<VCardRelationData>> VCardContact::GetRelations()
{
    return relations_;
}

std::vector<std::shared_ptr<VCardImData>> VCardContact::GetIms()
{
    return ims_;
}

std::vector<std::shared_ptr<VCardSipData>> VCardContact::GetSips()
{
    return sips_;
}

std::vector<std::shared_ptr<VCardPhoneData>> VCardContact::GetPhones()
{
    return phones_;
}

std::vector<std::shared_ptr<VCardOrganizationData>> VCardContact::GetOrganizations()
{
    return organizations_;
}

std::vector<std::shared_ptr<VCardWebsiteData>> VCardContact::GetWebsites()
{
    return websites_;
}

std::vector<std::shared_ptr<VCardPhotoData>> VCardContact::GetPhotos()
{
    return photos_;
}

std::vector<std::shared_ptr<VCardEmailData>> VCardContact::GetEmails()
{
    return emails_;
}

std::vector<std::shared_ptr<VCardNicknameData>> VCardContact::GetNicknames()
{
    return nicknames_;
}

std::vector<std::shared_ptr<VCardPostalData>> VCardContact::GetPostalDatas()
{
    return postals_;
}

std::vector<std::shared_ptr<VCardEventData>> VCardContact::GetEventDatas()
{
    return events_;
}

std::vector<std::shared_ptr<VCardNoteData>> VCardContact::GetNotes()
{
    return notes_;
}

std::shared_ptr<VCardBirthdayData> VCardContact::GetBirthdays()
{
    return birthday_;
}

void VCardContact::HandleName(std::vector<std::string> values, std::map<std::string, std::vector<std::string>> parasMap)
{
    if (nameData_ == nullptr) {
        return;
    }
    int32_t size = 0;
    if (values.empty() || (size = values.size()) == 0) {
        return;
    }
    if (size > N_MAX_VALUE_SIZE) {
        size = N_MAX_VALUE_SIZE;
    }
    switch (size) {
        case SIZE_FIVE:
            nameData_->SetSuffix(values[N_SUFFIX_VALUE_INDEX]);
            // fall_through
        case SIZE_FOUR:
            nameData_->SetPrefix(values[N_PREFIX_VALUE_INDEX]);
            // fall_through
        case SIZE_THREE:
            nameData_->SetMiddle(values[N_MIDDLE_VALUE_INDEX]);
            // fall_through
        case SIZE_TWO:
            nameData_->SetGiven(values[N_GIVEN_VALUE_INDEX]);
            // fall_through
        default:
            nameData_->SetFamily(values[N_FAMILY_VALUE_INDEX]);
            break;
    }
}

void VCardContact::HandleSortAsName(std::map<std::string, std::vector<std::string>> parasMap)
{
    if (nameData_ == nullptr) {
        return;
    }
    if (vCardType_ == VERSION_30 &&
        !(nameData_->GetPhoneticFamily().empty() && nameData_->GetPhoneticMiddle().empty() &&
            nameData_->GetPhoneticGiven().empty())) {
        return;
    }
    std::vector<std::string> sortAsList;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_SORT_AS);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_SORT_AS);
        return;
    } else {
        sortAsList = it->second;
    }

    if (sortAsList.size() > 0) {
        std::vector<std::string> sortNames = VCardUtils::ConstructListFromValue(sortAsList[0], vCardType_);
        int32_t size = sortNames.size();
        if (size > SORT_NAME_MAX_VALUE_SIZE) {
            size = SORT_NAME_MAX_VALUE_SIZE;
        }
        switch (size) {
            case SIZE_THREE:
                nameData_->SetPhoneticMiddle(sortNames[PHONETIC_MIDDLE_VALUE_INDEX]);
                // fall_through
            case SIZE_TWO:
                nameData_->SetPhoneticGiven(sortNames[PHONETIC_GIVEN_VALUE_INDEX]);
                // fall_through
            default:
                nameData_->SetPhoneticFamily(sortNames[PHONETIC_FAMILY_VALUE_INDEX]);
                break;
        }
    }
}

void VCardContact::HandleNickName(std::string nickName)
{
    std::shared_ptr<VCardNicknameData> nn = std::make_shared<VCardNicknameData>();
    nn->SetNickName(nickName);
    nicknames_.push_back(nn);
}

void VCardContact::HandlePhoneticNameFromSound(std::vector<std::string> elems)
{
    if (nameData_ == nullptr) {
        return;
    }
    if (nameData_->GetPhoneticFamily().empty() && nameData_->GetPhoneticMiddle().empty() &&
        nameData_->GetPhoneticGiven().empty()) {
        return;
    }
    int32_t size = elems.size();
    if (elems.empty() || size == 0) {
        return;
    }
    size = (size > PHONE_NAME_SOUND_MAX_VALUE_SIZE) ? PHONE_NAME_SOUND_MAX_VALUE_SIZE : size;
    if (elems[0].length() > 0) {
        bool onlyFirstElemIsNonEmpty = true;
        for (int32_t i = 1; i < size; i++) {
            if (elems[i].length() > 0) {
                onlyFirstElemIsNonEmpty = false;
                break;
            }
        }
        if (onlyFirstElemIsNonEmpty) {
            std::vector<std::string> namesArray = VCardUtils::Split(elems[VALUE_INDEX_ZERO], " ");
            int32_t nameArrayLength = namesArray.size();
            if (nameArrayLength == VALUE_LEN_THREE) {
                nameData_->SetPhoneticFamily(namesArray[VALUE_INDEX_ZERO]);
                nameData_->SetPhoneticMiddle(namesArray[VALUE_INDEX_ONE]);
                nameData_->SetPhoneticGiven(namesArray[VALUE_INDEX_TWO]);
            } else if (nameArrayLength == VALUE_LEN_TWO) {
                nameData_->SetPhoneticFamily(namesArray[VALUE_INDEX_ZERO]);
                nameData_->SetPhoneticGiven(namesArray[VALUE_INDEX_ONE]);
            } else {
                nameData_->SetPhoneticGiven(elems[VALUE_INDEX_ZERO]);
            }
            return;
        }
    }
    switch (size) {
        case SIZE_THREE:
            nameData_->SetPhoneticMiddle(elems[VALUE_INDEX_TWO]);
            break;
        case SIZE_TWO:
            nameData_->SetPhoneticGiven(elems[VALUE_INDEX_ONE]);
            break;
        default:
            nameData_->SetPhoneticFamily(elems[VALUE_INDEX_ZERO]);
            break;
    }
}

void VCardContact::AddPostal(int32_t type, std::vector<std::string> propValueList, std::string label, bool isPrimary)
{
    std::shared_ptr<VCardPostalData> pd = std::make_shared<VCardPostalData>();
    pd->InitPostalData(propValueList, type, label);
    postals_.push_back(pd);
}

void VCardContact::AddEmail(int32_t type, std::string data, std::string label, std::string displayname, bool isPrimary)
{
    std::shared_ptr<VCardEmailData> ed = std::make_shared<VCardEmailData>();
    ed->InitEmailData(data, std::to_string(type), label, displayname);
    emails_.push_back(ed);
}

void VCardContact::HandleOrgValue(int32_t type, std::vector<std::string> orgList,
    std::map<std::string, std::vector<std::string>> paramMap, bool isPrimary)
{
    std::string phoneticName = BuildSinglePhoneticNameFromSortAsParam(paramMap);

    std::string organizationName;
    std::string departmentName;
    int32_t size = orgList.size();
    switch (size) {
        case SIZE_ZERO:
            organizationName = "";
            departmentName = "";
            break;
        case SIZE_ONE:
            organizationName = orgList[0];
            departmentName = "";
            break;
        default:
            organizationName = orgList[0];
            std::string builder;
            for (int32_t i = 1; i < size; i++) {
                if (i > 1) {
                    builder += " ";
                }
                builder += orgList[i];
            }
            departmentName = builder;
            break;
    }

    if (organizations_.empty()) {
        AddNewOrganization(organizationName, departmentName, "", "", phoneticName, type, isPrimary);
        return;
    }

    for (std::shared_ptr<VCardOrganizationData> organizationData : organizations_) {
        if (organizationData == nullptr) {
            return;
        }
        if (organizationData->GetOrganization().empty() && organizationData->GetDepartmentName().empty()) {
            organizationData->SetOrganization(organizationName);
            organizationData->SetDepartmentName(departmentName);
            return;
        }
    }

    AddNewOrganization(organizationName, departmentName, "", "", phoneticName, type, isPrimary);
}

std::string VCardContact::BuildSinglePhoneticNameFromSortAsParam(
    std::map<std::string, std::vector<std::string>> paramMap)
{
    std::vector<std::string> sortAsList;
    std::map<std::string, std::vector<std::string>>::iterator it = paramMap.find(VCARD_PARAM_SORT_AS);
    if (it == paramMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_SORT_AS);
        return "";
    } else {
        sortAsList = it->second;
    }
    if (!sortAsList.empty()) {
        std::vector<std::string> sortNames = VCardUtils::ConstructListFromValue(sortAsList.at(0), vCardType_);
        std::string init = "";
        std::string builder = std::accumulate(sortNames.begin(), sortNames.end(), init);
        return builder;
    } else {
        return "";
    }
}

void VCardContact::AddNewOrganization(std::string organizationName, std::string departmentName, std::string company,
    std::string titleName, std::string phoneticName, int32_t type, bool isPrimary)
{
    std::shared_ptr<VCardOrganizationData> od = std::make_shared<VCardOrganizationData>();
    od->InitOrganizationData(organizationName, departmentName, company, titleName, phoneticName, type);
    organizations_.push_back(od);
}

void VCardContact::HandleTitleValue(std::string title)
{
    if (organizations_.empty()) {
        AddNewOrganization("", "", "", title, "", VALUE_INDEX_ONE, false);
        return;
    }
    for (std::shared_ptr<VCardOrganizationData> organizationData : organizations_) {
        if (organizationData == nullptr) {
            return;
        }
        if (organizationData->GetTitle().empty()) {
            organizationData->SetTitle(title);
            return;
        }
    }
    AddNewOrganization("", "", "", title, "", VALUE_INDEX_ONE, false);
}

void VCardContact::AddPhotoBytes(std::string formatName, std::string photoBytes, bool isPrimary)
{
    std::shared_ptr<VCardPhotoData> pd = std::make_shared<VCardPhotoData>();
    pd->InitPhotoData(formatName, photoBytes);
    photos_.push_back(pd);
}

void VCardContact::HandleSipCase(std::string propValue, std::vector<std::string> typeCollection)
{
    if (propValue.empty()) {
        return;
    }
    if (VCardUtils::StartWith(propValue, "sip:")) {
        propValue = propValue.substr(VALUE_INDEX_FOUR);
        if (propValue.length() == 0) {
            return;
        }
    }
    int32_t type = -1;
    std::string label;
    bool isPrimary = false;
    if (!typeCollection.empty()) {
        for (std::string typeStringOrg : typeCollection) {
            std::string typeStringUpperCase = VCardUtils::ToUpper(typeStringOrg);
            if (typeStringUpperCase == VCARD_PARAM_TYPE_PREF) {
                isPrimary = true;
            } else if (typeStringUpperCase == VCARD_PARAM_TYPE_HOME) {
                type = static_cast<int32_t>(SipType::SIP_HOME);
            } else if (typeStringUpperCase == VCARD_PARAM_TYPE_WORK) {
                type = static_cast<int32_t>(SipType::SIP_WORK);
            } else if (type < 0) {
                label = (VCardUtils::StartWith(typeStringUpperCase, "X-")) ? typeStringOrg.substr(VALUE_INDEX_TWO)
                                                                           : typeStringOrg;
                type = static_cast<int32_t>(SipType::CUSTOM_LABEL);
            } else {
                TELEPHONY_LOGI("No need to do anything");
            }
        }
    }
    if (type < 0) {
        type = static_cast<int32_t>(SipType::SIP_OTHER);
    }
    AddSip(propValue, type, label, isPrimary);
}

void VCardContact::AddPhone(int32_t type, std::string data, std::string label, bool isPrimary)
{
    std::string builder;
    std::string trimmed = data;
    std::string formattedNumber;
    if (type == static_cast<int32_t>(PhoneVcType::NUM_PAGER) ||
        VCardConfiguration::RefrainPhoneNumberFormatting(VCardUtils::VcardtypeToInt(vCardType_))) {
        formattedNumber = trimmed;
    } else {
        bool hasPauseOrWait = false;
        std::size_t length = trimmed.length();
        for (std::size_t i = 0; i < length; i++) {
            char ch = trimmed[i];
            if (ch == 'p' || ch == 'P') {
                builder += ',';
                hasPauseOrWait = true;
            } else if (ch == 'w' || ch == 'W') {
                builder += ';';
                hasPauseOrWait = true;
            } else if (((ch >= '0' && ch <= '9') || ch == '*' || ch == '#') || (i == 0 && ch == '+')) {
                builder += ch;
            } else {
                TELEPHONY_LOGI("No need to do anything");
            }
        }
        if (!hasPauseOrWait) {
            formattedNumber = VCardUtils::FormatNumber(builder);
        } else {
            formattedNumber = builder;
        }
    }
    std::shared_ptr<VCardPhoneData> object = std::make_shared<VCardPhoneData>();
    object->InitPhoneData(formattedNumber, type, label, isPrimary);
    phones_.push_back(object);
}

void VCardContact::AddSip(std::string sipData, int32_t type, std::string label, bool isPrimary)
{
    std::shared_ptr<VCardSipData> object = std::make_shared<VCardSipData>();
    object->InitSipData(sipData, type, label);
    sips_.push_back(object);
}

void VCardContact::AddNote(const std::string note)
{
    std::shared_ptr<VCardNoteData> object = std::make_shared<VCardNoteData>();
    object->InitNoteData(note);
    notes_.push_back(object);
}

void VCardContact::AddIms(std::string name, std::string rawValue, std::string propValue,
    std::vector<std::string> values, std::map<std::string, std::vector<std::string>> parasMap)
{
    int32_t labeId = VCardUtils::GetLabelIdFromImType(name);
    std::shared_ptr<VCardImData> object = std::make_shared<VCardImData>();
    std::vector<std::string> valueList = GetValueListFromParasMap(rawValue, propValue, parasMap);
    for (std::string value : valueList) {
        object->SetAddress(value);
    }
    object->SetLabelId(std::to_string(labeId));
    ims_.push_back(object);
}

void VCardContact::AddNameData(std::string name, std::string rawValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap, std::string propValue)
{
    if (nameData_ == nullptr) {
        return;
    }
    if (name == VCARD_TYPE_FN) {
        nameData_->setDispalyName((values.size() != 0) ? values[0] : "");
    } else if (name == VCARD_TYPE_N) {
        HandleSortAsName(parasMap);
        HandleName(values, parasMap);
    } else if (name == VCARD_TYPE_NAME) {
        if (nameData_->GetFormatted().empty()) {
            nameData_->SetFormatted(propValue);
        }
    } else if (name == VCARD_TYPE_SORT_STRING) {
        nameData_->setSort(propValue);
    } else if (name == VCARD_TYPE_X_PHONETIC_FIRST_NAME) {
        std::vector<std::string> valueList = GetValueListFromParasMap(rawValue, propValue, parasMap);
        nameData_->SetPhoneticGiven((valueList.size() != 0) ? valueList[0] : "");
    } else if (name == VCARD_TYPE_X_PHONETIC_MIDDLE_NAME) {
        std::vector<std::string> valueList = GetValueListFromParasMap(rawValue, propValue, parasMap);
        nameData_->SetPhoneticMiddle((valueList.size() != 0) ? valueList[0] : "");
    } else if (name == VCARD_TYPE_X_PHONETIC_LAST_NAME) {
        std::vector<std::string> valueList = GetValueListFromParasMap(rawValue, propValue, parasMap);
        nameData_->SetPhoneticFamily((valueList.size() != 0) ? valueList[0] : "");
    } else {
        TELEPHONY_LOGI("No need to do anything");
    }
}

void VCardContact::AddCustom(
    std::string rawValue, std::map<std::string, std::vector<std::string>> parasMap, std::string propValue)
{
    std::vector<std::string> values = GetValueListFromParasMap(rawValue, propValue, parasMap);
    std::string type = (values.size() != 0) ? values[0] : "";
    if (type == TypeData::NICKNAME) {
        std::shared_ptr<VCardNicknameData> object = std::make_shared<VCardNicknameData>();
        int i = 0;
        for (std::string value : values) {
            if (i == SIZE_ONE) {
                object->SetNickName(value);
                break;
            }
            i++;
        }
        nicknames_.push_back(object);
    } else if (type == TypeData::RELATION) {
        std::shared_ptr<VCardRelationData> object = std::make_shared<VCardRelationData>();
        int i = 0;
        for (std::string value : values) {
            if (i == SIZE_ONE) {
                object->SetRelationName(value);
            } else if (i == SIZE_TWO) {
                object->SetLabelId(value);
            } else if (i == SIZE_THREE) {
                object->SetLabelName(value);
                break;
            }
            i++;
        }
        relations_.push_back(object);
    } else if (type == TypeData::CONTACT_EVENT) {
        std::shared_ptr<VCardEventData> object = std::make_shared<VCardEventData>();
        int i = 0;
        for (std::string value : values) {
            if (i == SIZE_ONE) {
                object->SetEventDate(value);
            } else if (i == SIZE_TWO) {
                object->SetLabelId(value);
            } else if (i == SIZE_THREE) {
                object->SetLabelName(value);
                break;
            }
            i++;
        }
        events_.push_back(object);
    }
}

void VCardContact::SetSip(
    std::string rawValue, std::map<std::string, std::vector<std::string>> parasMap, std::string propValue)
{
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        std::shared_ptr<VCardSipData> object = std::make_shared<VCardSipData>();
        std::vector<std::string> values = VCardUtils::Split(propValue, ";");
        for (size_t i = 0; i < values.size(); i++) {
            if (i == SIZE_ZERO) {
                std::vector<std::string> address = VCardUtils::Split(values[i], ":");
                object->SetAddress((address.size() >= SIZE_TWO) ? address[1] : "");
            } else if (i == SIZE_ONE) {
                object->SetLabelId(values[i]);
            } else if (i == SIZE_TWO) {
                object->SetLabelName(values[i]);
                break;
            }
        }
        sips_.push_back(object);
    } else {
        std::vector<std::string> typeCollection;
        typeCollection = it->second;
        HandleSipCase(propValue, typeCollection);
    }
}

void VCardContact::AddSipData(
    std::string rawValue, std::map<std::string, std::vector<std::string>> parasMap, std::string propValue)
{
    if (parasMap.size() != 0 && !propValue.empty()) {
        SetSip(rawValue, parasMap, propValue);
        return;
    }
    std::shared_ptr<VCardSipData> object = std::make_shared<VCardSipData>();
    std::vector<std::string> values = VCardUtils::Split(rawValue, ";");
    for (size_t i = 0; i < values.size(); i++) {
        if (i == SIZE_ZERO) {
            std::vector<std::string> address = VCardUtils::Split(values[i], ":");
            object->SetAddress((address.size() >= SIZE_TWO) ? address[1] : "");
        }
        if (i == SIZE_ONE) {
            object->SetLabelId(values[i]);
        }
        if (i == SIZE_TWO) {
            object->SetLabelName(values[i]);
        }
    }
    sips_.push_back(object);
}

void VCardContact::AddPhonesData(std::string rawValue, std::string propValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    std::string phoneNumber;
    bool isSip = false;
    if (vCardType_ == VERSION_40) {
        if (VCardUtils::StartWith(propValue, "sip:")) {
            isSip = true;
        } else if (VCardUtils::StartWith(propValue, "tel:")) {
            phoneNumber = propValue.substr(VALUE_INDEX_FOUR);
        } else {
            phoneNumber = propValue;
        }
    } else {
        phoneNumber = rawValue;
    }
    if (isSip) {
        std::vector<std::string> typeCollection;
        std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
        if (it == parasMap.end()) {
            TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
            return;
        } else {
            typeCollection = it->second;
        }
        HandleSipCase(propValue, typeCollection);
    } else {
        HandlePhoneCase(phoneNumber, rawValue, propValue, values, parasMap);
    }
}

void VCardContact::HandlePhoneCase(std::string phoneNumber, std::string rawValue, std::string propValue,
    std::vector<std::string> values, std::map<std::string, std::vector<std::string>> parasMap)
{
    std::vector<std::string> typeCollection;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        return;
    } else {
        typeCollection = it->second;
    }
    std::tuple<int32_t, std::string> result(NUM_MINUS_ONE, "-1");
    VCardUtils::GetPhoneTypeFromStrings(typeCollection, phoneNumber, result);
    int32_t type = NUM_MINUS_ONE;
    std::string label;
    if (std::get<0>(result) != NUM_MINUS_ONE && std::get<1>(result) == "-1") {
        type = std::get<0>(result);
        label = "";
    } else if (std::get<0>(result) == NUM_MINUS_ONE && std::get<1>(result) != "-1") {
        type = static_cast<int32_t>(PhoneVcType::CUSTOM_LABEL);
        label = std::get<1>(result);
    }
    bool isPrimary = false;
    bool contains = false;
    if (std::find(typeCollection.begin(), typeCollection.end(), VCARD_PARAM_TYPE_PREF) != typeCollection.end()) {
        contains = true;
    }
    if (!typeCollection.empty() && contains) {
        isPrimary = true;
    }
    AddPhone(type, phoneNumber, label, isPrimary);
}

void VCardContact::AddOrganizationsData(std::string rawValue, std::string propValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    int32_t type = SIZE_ONE;
    bool isPrimary = false;
    if (parasMap.size() != 0) {
        std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
        if (it == parasMap.end()) {
            TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
            AddNewOrganization("", "", propValue, "", "", type, isPrimary);
        } else {
            HandleOrgValue(type, values, parasMap, isPrimary);
        }
    } else {
        AddNewOrganization("", "", rawValue, "", "", type, isPrimary);
    }
}

void VCardContact::AddEmailsData(std::string rawValue, std::string propValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    int32_t type = NUM_MINUS_ONE;
    std::string label = "";
    bool isPrimary = false;
    std::vector<std::string> typeCollection;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        return;
    } else {
        typeCollection = it->second;
    }
    if (!typeCollection.empty()) {
        for (std::string typeStringOrg : typeCollection) {
            std::string typeStringUpperCase = VCardUtils::ToUpper(typeStringOrg);
            if (typeStringUpperCase == VCARD_PARAM_TYPE_PREF) {
                isPrimary = true;
            } else if (typeStringUpperCase == VCARD_PARAM_TYPE_HOME) {
                type = static_cast<int32_t>(EmailType::EMAIL_HOME);
            } else if (typeStringUpperCase == VCARD_PARAM_TYPE_WORK) {
                type = static_cast<int32_t>(EmailType::EMAIL_WORK);
            } else if (typeStringUpperCase == VCARD_PARAM_TYPE_CELL) {
                type = VALUE_INDEX_FOUR;
            } else if (type < 0) {
                label = (VCardUtils::StartWith(typeStringUpperCase, "X-")) ? typeStringOrg.substr(VALUE_INDEX_TWO)
                                                                           : typeStringOrg;
                type = static_cast<int32_t>(EmailType::CUSTOM_LABEL);
            } else {
                TELEPHONY_LOGI("No need to do anything");
            }
        }
    }
    if (type < 0) {
        type = static_cast<int32_t>(EmailType::EMAIL_OTHER);
    }
    std::map<std::string, std::vector<std::string>>::iterator itCharset = parasMap.find(VCARD_PARAM_CHARSET);
    std::map<std::string, std::vector<std::string>>::iterator itEncoding = parasMap.find(VCARD_PARAM_ENCODING);
    std::vector<std::string> valueList =
        VCardUtils::Split(((itCharset != parasMap.end() && itEncoding != parasMap.end()) ? propValue : rawValue), ";");
    std::string address = (valueList.size() != 0) ? valueList[0] : "";
    std::string displayname = (valueList.size() >= SIZE_TWO) ? valueList[1] : "";
    AddEmail(type, address, label, displayname, isPrimary);
}

void VCardContact::AddPostalDatas(std::string rawValue, std::string propValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    bool valueIsAllEmpty = true;
    for (std::string value : values) {
        if (!value.empty()) {
            valueIsAllEmpty = false;
            break;
        }
    }
    if (valueIsAllEmpty) {
        return;
    }
    int32_t type = -1;
    std::string label = "";
    bool isPrimary = false;
    std::vector<std::string> typeCollection;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        return;
    } else {
        typeCollection = it->second;
    }
    for (std::string typeStringOrg : typeCollection) {
        std::string typeStringUpperCase = VCardUtils::ToUpper(typeStringOrg);
        if (typeStringUpperCase == VCARD_PARAM_TYPE_PREF) {
            isPrimary = true;
        } else if (typeStringUpperCase == VCARD_PARAM_TYPE_HOME) {
            type = static_cast<int32_t>(PostalType::ADDR_HOME);
            label = "";
        } else if (typeStringUpperCase == VCARD_PARAM_TYPE_WORK ||
                   typeStringUpperCase == VCARD_PARAM_EXTRA_TYPE_COMPANY) {
            type = static_cast<int32_t>(PostalType::ADDR_WORK);
            label = "";
        } else if (typeStringUpperCase == VCARD_PARAM_ADR_TYPE_PARCEL ||
                   typeStringUpperCase == VCARD_PARAM_ADR_TYPE_DOM ||
                   typeStringUpperCase == VCARD_PARAM_ADR_TYPE_INTL) {
            // We do not have any appropriate way to store this information.
        } else if (type < 0) {
            type = static_cast<int32_t>(PostalType::CUSTOM_LABEL);
            label = (VCardUtils::StartWith(typeStringUpperCase, "X-")) ? typeStringOrg.substr(VALUE_INDEX_TWO)
                                                                       : typeStringOrg;
            if (VCardUtils::ToUpper(label) == VCARD_PARAM_ADR_EXTRA_TYPE_OTHER) {
                type = static_cast<int32_t>(PostalType::ADDR_OTHER);
                label = "";
            }
        } else {
            TELEPHONY_LOGI("No need to do anything");
        }
    }
    AddPostal(type < 0 ? static_cast<int32_t>(PostalType::ADDR_HOME) : type, values, label, isPrimary);
}

void VCardContact::AddSoundDatas(std::string rawValue, std::string propValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    std::vector<std::string> typeList;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        return;
    } else {
        typeList = it->second;
    }
    bool contains = false;
    if (std::find(typeList.begin(), typeList.end(), VCARD_PARAM_X_IRMC_N) != typeList.end()) {
        contains = true;
    }
    if (typeList.size() > 0 && contains) {
        std::vector<std::string> phoneticNameList = VCardUtils::ConstructListFromValue(propValue, vCardType_);
        HandlePhoneticNameFromSound(phoneticNameList);
    }
}

void VCardContact::AddPhotoDatas(std::string byte, std::string rawValue, std::string propValue,
    std::vector<std::string> values, std::map<std::string, std::vector<std::string>> parasMap)
{
    std::vector<std::string> typeList;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        return;
    } else {
        typeList = it->second;
    }
    std::string formatName;
    bool isPrimary = false;
    if (!typeList.empty()) {
        for (std::string typeValue : typeList) {
            if (typeValue == VCARD_PARAM_TYPE_PREF) {
                isPrimary = true;
            } else if (formatName.empty()) {
                formatName = typeValue;
            } else {
                TELEPHONY_LOGI("No need to do anything");
            }
        }
    }
    AddPhotoBytes(formatName, byte, isPrimary);
}

void VCardContact::AddSkypePstnNumDatas(std::string propValue, std::map<std::string, std::vector<std::string>> parasMap)
{
    std::vector<std::string> typeCollection;
    std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
    if (it == parasMap.end()) {
        TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
        return;
    } else {
        typeCollection = it->second;
    }
    int32_t type = static_cast<int32_t>(PhoneVcType::NUM_OTHER);
    bool isPrimary = false;
    if (std::find(typeCollection.begin(), typeCollection.end(), VCARD_PARAM_TYPE_PREF) != typeCollection.end()) {
        isPrimary = true;
    }
    AddPhone(type, propValue, "", isPrimary);
}

void VCardContact::AddWebSiteDatas(std::string rawValue, std::string propValue, std::vector<std::string> values,
    std::map<std::string, std::vector<std::string>> parasMap)
{
    std::shared_ptr<VCardWebsiteData> object = std::make_shared<VCardWebsiteData>();
    std::vector<std::string> valueList = VCardUtils::Split((parasMap.size() != 0) ? propValue : rawValue, ";");
    object->InitWebsite((valueList.size() > SIZE_ZERO) ? valueList[VALUE_INDEX_ZERO] : "");
    object->SetLabelId((valueList.size() > SIZE_ONE) ? valueList[VALUE_INDEX_ONE] : "");
    object->SetLabelName((valueList.size() > SIZE_TWO) ? valueList[VALUE_INDEX_TWO] : "");
    websites_.push_back(object);
}

void VCardContact::AddBirthdayDatas(std::string rawValue)
{
    std::shared_ptr<VCardBirthdayData> object = std::make_shared<VCardBirthdayData>();
    object->InitBirthdayData(rawValue);
    birthday_ = object;
}

void VCardContact::AddAnniversaryDatas(std::string propValue)
{
    std::shared_ptr<VCardAnniversaryData> object = std::make_shared<VCardAnniversaryData>();
    object->InitAnniversaryData(propValue);
    anniversary_ = object;
}

void VCardContact::AddImppDatas(std::string propValue, std::map<std::string, std::vector<std::string>> parasMap)
{
    if (VCardUtils::StartWith(propValue, "sip:")) {
        std::vector<std::string> typeCollection;
        std::map<std::string, std::vector<std::string>>::iterator it = parasMap.find(VCARD_PARAM_TYPE);
        if (it == parasMap.end()) {
            TELEPHONY_LOGE("Map does not contain this key, %{public}s", VCARD_PARAM_TYPE);
            return;
        } else {
            typeCollection = it->second;
        }
        HandleSipCase(propValue, typeCollection);
    }
}

std::vector<std::string> VCardContact::GetValueListFromParasMap(
    std::string rawValue, std::string propValue, std::map<std::string, std::vector<std::string>> parasMap)
{
    return VCardUtils::Split(((parasMap.size() == 0) ? rawValue : propValue), ";");
}

} // namespace Telephony
} // namespace OHOS

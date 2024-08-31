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

#ifndef OHOS_VCARD_CONSRACT_H
#define OHOS_VCARD_CONSRACT_H
#include <memory>
#include <mutex>
#include <type_traits>
#include <vector>

#include "vcard_anniversary_data.h"
#include "vcard_birthday_data.h"
#include "vcard_constant.h"
#include "vcard_contact_data.h"
#include "vcard_email_data.h"
#include "vcard_event_data.h"
#include "vcard_im_data.h"
#include "vcard_name_data.h"
#include "vcard_nickname_data.h"
#include "vcard_note_data.h"
#include "vcard_organization_data.h"
#include "vcard_phone_data.h"
#include "vcard_photo_data.h"
#include "vcard_postal_data.h"
#include "vcard_raw_data.h"
#include "vcard_rdb_helper.h"
#include "vcard_relation_data.h"
#include "vcard_sip_data.h"
#include "vcard_website_data.h"

namespace OHOS {
namespace Telephony {
class VCardContact {
public:
    VCardContact()
    {
        vCardType_ = VERSION_21;
        nameData_ = std::make_shared<VCardNameData>();
        birthday_ = std::make_shared<VCardBirthdayData>();
        anniversary_ = std::make_shared<VCardAnniversaryData>();
    };
    ~VCardContact() {}
    void AddRawData(std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    int32_t BuildContactData(int32_t rawId, std::vector<DataShare::DataShareValuesBucket> &contactDataValues);
    int32_t BuildContact(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    void Init();
    std::shared_ptr<VCardNameData> GetNameData();
    std::vector<std::shared_ptr<VCardNameData>> GetNames();
    std::vector<std::shared_ptr<VCardRelationData>> GetRelations();
    std::vector<std::shared_ptr<VCardImData>> GetIms();
    std::vector<std::shared_ptr<VCardSipData>> GetSips();
    std::vector<std::shared_ptr<VCardPhoneData>> GetPhones();
    std::vector<std::shared_ptr<VCardOrganizationData>> GetOrganizations();
    std::vector<std::shared_ptr<VCardWebsiteData>> GetWebsites();
    std::vector<std::shared_ptr<VCardPhotoData>> GetPhotos();
    std::vector<std::shared_ptr<VCardEmailData>> GetEmails();
    std::vector<std::shared_ptr<VCardNicknameData>> GetNicknames();
    std::vector<std::shared_ptr<VCardPostalData>> GetPostalDatas();
    std::vector<std::shared_ptr<VCardEventData>> GetEventDatas();
    std::vector<std::shared_ptr<VCardNoteData>> GetNotes();
    std::shared_ptr<VCardBirthdayData> GetBirthdays();

private:
    void BuildValuesBucket(int32_t rawId, std::vector<DataShare::DataShareValuesBucket> &contactDataValues,
        std::shared_ptr<VCardContactData> contactData);
    template<typename T>
    void BuildValuesBuckets(int32_t rawId, std::vector<DataShare::DataShareValuesBucket> &contactDataValues,
        std::vector<std::shared_ptr<T>> &contactDatas);
    template<typename T>
    void BuildData(
        std::shared_ptr<DataShare::DataShareResultSet> resultSet, std::vector<std::shared_ptr<T>> &contactDatas);
    int32_t BuildOneData(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    int32_t BuildOtherData(int32_t typeId, std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    void AddDatas(std::string name, std::string rawValue, std::string byte, std::vector<std::string> values,
        std::string propValue, std::vector<std::string> groups,
        std::map<std::string, std::vector<std::string>> parasMap);
    void HandleName(std::vector<std::string> values, std::map<std::string, std::vector<std::string>> parasMap);
    void HandleSortAsName(std::map<std::string, std::vector<std::string>> parasMap);
    void HandleNickName(std::string nickName);
    void HandlePhoneticNameFromSound(std::vector<std::string> elems);
    void AddPostal(int32_t type, std::vector<std::string> propValueList, std::string label, bool isPrimary);
    void AddEmail(int32_t type, std::string data, std::string label, std::string displayname, bool isPrimary);
    void HandleOrgValue(int32_t type, std::vector<std::string> orgList,
        std::map<std::string, std::vector<std::string>> paramMap, bool isPrimary);
    std::string BuildSinglePhoneticNameFromSortAsParam(std::map<std::string, std::vector<std::string>> paramMap);
    void AddNewOrganization(std::string organizationName, std::string departmentName, std::string company,
        std::string titleName, std::string phoneticName, int32_t type, bool isPrimary);
    void HandleTitleValue(std::string title);
    void AddPhotoBytes(std::string formatName, std::string photoBytes, bool isPrimary);
    void HandleSipCase(std::string propValue, std::vector<std::string> typeCollection);
    void AddPhone(int32_t type, std::string data, std::string label, bool isPrimary);
    void AddSip(std::string sipData, int32_t type, std::string label, bool isPrimary);
    void AddNote(const std::string note);
    void AddIms(std::string name, std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddNameData(std::string name, std::string rawValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap, std::string propValue);
    void AddCustom(
        std::string rawValue, std::map<std::string, std::vector<std::string>> parasMap, std::string propValue);
    void SetSip(std::string rawValue, std::map<std::string, std::vector<std::string>> parasMap, std::string propValue);
    void AddSipData(
        std::string rawValue, std::map<std::string, std::vector<std::string>> parasMap, std::string propValue);
    void AddPhonesData(std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddOrganizationsData(std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddEmailsData(std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddPostalDatas(std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddSoundDatas(std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddPhotoDatas(std::string byte, std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddSkypePstnNumDatas(std::string propValue, std::map<std::string, std::vector<std::string>> parasMap);
    void AddWebSiteDatas(std::string rawValue, std::string propValue, std::vector<std::string> values,
        std::map<std::string, std::vector<std::string>> parasMap);
    void AddBirthdayDatas(std::string rawValue);
    void AddAnniversaryDatas(std::string propValue);
    void AddImppDatas(std::string propValue, std::map<std::string, std::vector<std::string>> parasMap);
    void HandlePhoneCase(std::string phoneNumber, std::string rawValue, std::string propValue,
        std::vector<std::string> values, std::map<std::string, std::vector<std::string>> parasMap);
    void AddOtherDatas(std::string name, std::string rawValue, std::string byte, std::vector<std::string> values,
        std::string propValue, std::vector<std::string> groups,
        std::map<std::string, std::vector<std::string>> parasMap);
    std::vector<std::string> GetValueListFromParasMap(
        std::string rawValue, std::string propValue, std::map<std::string, std::vector<std::string>> parasMap);
    void CheckNameExist();
    std::string ConvertHarmonyEvents(std::string type, std::string value);

private:
    const int32_t SORT_NAME_MAX_VALUE_SIZE = 3;
    const int32_t N_MAX_VALUE_SIZE = 5;
    const int32_t N_SUFFIX_VALUE_INDEX = 4;
    const int32_t N_PREFIX_VALUE_INDEX = 3;
    const int32_t N_MIDDLE_VALUE_INDEX = 2;
    const int32_t N_GIVEN_VALUE_INDEX = 1;
    const int32_t N_FAMILY_VALUE_INDEX = 0;
    const int32_t PHONETIC_FAMILY_VALUE_INDEX = 0;
    const int32_t PHONETIC_GIVEN_VALUE_INDEX = 1;
    const int32_t PHONETIC_MIDDLE_VALUE_INDEX = 2;
    const int32_t PHONE_NAME_SOUND_MAX_VALUE_SIZE = 3;
    std::string vCardType_;
    std::shared_ptr<VCardNameData> nameData_;
    std::shared_ptr<VCardBirthdayData> birthday_;
    std::shared_ptr<VCardAnniversaryData> anniversary_;
    std::vector<std::shared_ptr<VCardNameData>> names_;
    std::vector<std::shared_ptr<VCardPhoneData>> phones_;
    std::vector<std::shared_ptr<VCardRelationData>> relations_;
    std::vector<std::shared_ptr<VCardEmailData>> emails_;
    std::vector<std::shared_ptr<VCardPostalData>> postals_;
    std::vector<std::shared_ptr<VCardOrganizationData>> organizations_;
    std::vector<std::shared_ptr<VCardImData>> ims_;
    std::vector<std::shared_ptr<VCardPhotoData>> photos_;
    std::vector<std::shared_ptr<VCardWebsiteData>> websites_;
    std::vector<std::shared_ptr<VCardSipData>> sips_;
    std::vector<std::shared_ptr<VCardNicknameData>> nicknames_;
    std::vector<std::shared_ptr<VCardNoteData>> notes_;
    std::vector<std::shared_ptr<VCardEventData>> events_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_OHOS_VCARD_CONSRACT_H

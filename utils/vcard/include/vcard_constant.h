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

#ifndef VCARD_CONSTANT_H
#define VCARD_CONSTANT_H
#include <cstdint>

namespace OHOS {
namespace Telephony {
const int32_t DB_FAILD = -1;
const int32_t ID_NONE = -1;
constexpr const int32_t VERSION_21_NUM = 0;
constexpr const int32_t VERSION_30_NUM = 1;
constexpr const int32_t VERSION_40_NUM = 2;
constexpr const char *VERSION_21 = "2.1";
constexpr const char *VERSION_30 = "3.0";
constexpr const char *VERSION_40 = "4.0";
constexpr const char *DEFAULT_INTERMEDIATE_CHARSET = "ISO-8859-1";
constexpr const char *DEFAULT_IMPORT_CHARSET = "UTF-8";
constexpr const char *DEFAULT_EXPORT_CHARSET = "UTF-8";
constexpr const char *DEFAULT_ENCODING = "8BIT";
constexpr const char *DEFAULT_CHARSET = "UTF-8";
constexpr const char *VCARD_TYPE_VERSION = "VERSION";
constexpr const char *VCARD_TYPE_BEGIN = "BEGIN";
constexpr const char *VCARD_TYPE_N = "N";
constexpr const char *VCARD_TYPE_FN = "FN";
constexpr const char *VCARD_TYPE_ADR = "ADR";
constexpr const char *VCARD_TYPE_EMAIL = "EMAIL";
constexpr const char *VCARD_TYPE_NOTE = "NOTE";
constexpr const char *VCARD_TYPE_ORG = "ORG";
constexpr const char *VCARD_TYPE_SOUND = "SOUND";
constexpr const char *VCARD_TYPE_TEL = "TEL";
constexpr const char *VCARD_TYPE_TITLE = "TITLE";
constexpr const char *VCARD_TYPE_ROLE = "ROLE";
constexpr const char *VCARD_TYPE_PHOTO = "PHOTO";
constexpr const char *VCARD_TYPE_LOGO = "LOGO";
constexpr const char *VCARD_TYPE_URL = "URL";
constexpr const char *VCARD_TYPE_BDAY = "BDAY";
constexpr const char *VCARD_TYPE_ANNIVERSARY = "ANNIVERSARY";
constexpr const char *VCARD_TYPE_NAME = "NAME";
constexpr const char *VCARD_TYPE_NICKNAME = "NICKNAME";
constexpr const char *VCARD_TYPE_SORT_STRING = "SORT-STRING";
constexpr const char *VCARD_TYPE_IMPP = "IMPP";
constexpr const char *VCARD_TYPE_END = "END";
constexpr const char *VCARD_TYPE_REV = "REV";
constexpr const char *VCARD_TYPE_AGENT = "AGENT";
constexpr const char *VCARD_TYPE_GENDER = "GENDER";
constexpr const char *VCARD_TYPE_XML = "XML";
constexpr const char *VCARD_TYPE_FBURL = "FBURL";
constexpr const char *VCARD_TYPE_PRODID = "PRODID";
constexpr const char *VCARD_TYPE_RELATED = "RELATED";
constexpr const char *VCARD_TYPE_CATEGORIES = "CATEGORIES";
constexpr const char *VCARD_TYPE_CLIENTPIDMAP = "CLIENTPIDMAP";
constexpr const char *VCARD_TYPE_CALURI = "CALURI";
constexpr const char *VCARD_TYPE_X_SIP = "X-SIP";
constexpr const char *VCARD_TYPE_X_PHONETIC_FIRST_NAME = "X-PHONETIC-FIRST-NAME";
constexpr const char *VCARD_TYPE_X_PHONETIC_MIDDLE_NAME = "X-PHONETIC-MIDDLE-NAME";
constexpr const char *VCARD_TYPE_X_PHONETIC_LAST_NAME = "X-PHONETIC-LAST-NAME";
constexpr const char *VCARD_TYPE_X_AIM = "X-AIM";
constexpr const char *VCARD_TYPE_X_MSN = "X-MSN";
constexpr const char *VCARD_TYPE_X_YAHOO = "X-YAHOO";
constexpr const char *VCARD_TYPE_X_ICQ = "X-ICQ";
constexpr const char *VCARD_TYPE_X_JABBER = "X-JABBER";
constexpr const char *VCARD_TYPE_X_SKYPE_USERNAME = "X-SKYPE-USERNAME";
constexpr const char *VCARD_TYPE_X_QQ = "X-QQ";
constexpr const char *VCARD_TYPE_X_NETMEETING = "X-NETMEETING";
constexpr const char *VCARD_TYPE_X_SKYPE_PSTNNUMBER = "X-SKYPE-PSTNNUMBER";

constexpr const char *VCARD_TYPE_X_CLASS = "X-CLASS";
constexpr const char *VCARD_TYPE_X_REDUCTION = "X-REDUCTION";
constexpr const char *VCARD_TYPE_X_NO = "X-NO";
constexpr const char *VCARD_TYPE_X_DCM_HMN_MODE = "X-DCM-HMN-MODE";
constexpr const char *VCARD_TYPE_X_OHOS_CUSTOM = "X_OHOS_CUSTOM";

constexpr const char *VCARD_PARAM_TYPE = "TYPE";
constexpr const char *VCARD_PARAM_X_IRMC_N = "X-IRMC-N";

constexpr const char *VCARD_PARAM_TYPE_HOME = "HOME";
constexpr const char *VCARD_PARAM_TYPE_WORK = "WORK";
constexpr const char *VCARD_PARAM_TYPE_FAX = "FAX";
constexpr const char *VCARD_PARAM_TYPE_CELL = "CELL";
constexpr const char *VCARD_PARAM_TYPE_VOICE = "VOICE";
constexpr const char *VCARD_PARAM_TYPE_INTERNET = "INTERNET";

constexpr const char *VCARD_PARAM_VALUE = "VALUE";
constexpr const char *VCARD_PARAM_CHARSET = "CHARSET";
constexpr const char *VCARD_PARAM_ENCODING = "ENCODING";

constexpr const char *VCARD_PARAM_TYPE_PREF = "PREF";

constexpr const char *VCARD_PARAM_TYPE_CAR = "CAR";
constexpr const char *VCARD_PARAM_TYPE_ISDN = "ISDN";
constexpr const char *VCARD_PARAM_TYPE_PAGER = "PAGER";
constexpr const char *VCARD_PARAM_TYPE_TLX = "TLX";

constexpr const char *VCARD_PARAM_TYPE_MODEM = "MODEM";
constexpr const char *VCARD_PARAM_TYPE_MSG = "MSG";
constexpr const char *VCARD_PARAM_TYPE_BBS = "BBS";
constexpr const char *VCARD_PARAM_TYPE_VIDEO = "VIDEO";

constexpr const char *VCARD_PARAM_ENCODING_7BIT = "7BIT";
constexpr const char *VCARD_PARAM_ENCODING_8BIT = "8BIT";
constexpr const char *VCARD_PARAM_ENCODING_QP = "QUOTED-PRINTABLE";
constexpr const char *VCARD_PARAM_ENCODING_BASE64 = "BASE64";
constexpr const char *VCARD_PARAM_ENCODING_B = "B";

constexpr const char *VCARD_PARAM_PHONE_EXTRA_TYPE_CALLBACK = "CALLBACK";
constexpr const char *VCARD_PARAM_PHONE_EXTRA_TYPE_RADIO = "RADIO";
constexpr const char *VCARD_PARAM_PHONE_EXTRA_TYPE_TTY_TDD = "TTY-TDD";
constexpr const char *VCARD_PARAM_PHONE_EXTRA_TYPE_ASSISTANT = "ASSISTANT";
constexpr const char *VCARD_PARAM_PHONE_EXTRA_TYPE_COMPANY_MAIN = "COMPANY-MAIN";
constexpr const char *VCARD_PARAM_PHONE_EXTRA_TYPE_OTHER = "OTHER";

constexpr const char *VCARD_PARAM_ADR_TYPE_PARCEL = "PARCEL";
constexpr const char *VCARD_PARAM_ADR_TYPE_DOM = "DOM";
constexpr const char *VCARD_PARAM_ADR_TYPE_INTL = "INTL";
constexpr const char *VCARD_PARAM_ADR_EXTRA_TYPE_OTHER = "OTHER";

constexpr const char *VCARD_PARAM_LANGUAGE = "LANGUAGE";

constexpr const char *VCARD_PARAM_SORT_AS = "SORT-AS";

constexpr const char *VCARD_PARAM_EXTRA_TYPE_COMPANY = "COMPANY";
constexpr const char *VCARD_EXPORT_FILE_PATH = "/data/storage/el2/base/files/";
constexpr const char *VCARD_TIME_FORMAT = "%Y%m%d_%H%M%S";
constexpr const char *VCARD_FILE_EXTENSION = ".vcf";

constexpr const int32_t VCARD_PHONE_NUM_FORMAT_JAPAN = 2;
constexpr const int32_t VCARD_PHONE_NUM_FORMAT_NANP = 1;
constexpr const int32_t SIZE_ZERO = 0;
constexpr const int32_t SIZE_ONE = 1;
constexpr const int32_t SIZE_TWO = 2;
constexpr const int32_t SIZE_THREE = 3;
constexpr const int32_t SIZE_FOUR = 4;
constexpr const int32_t SIZE_FIVE = 5;
constexpr const int32_t VALUE_INDEX_ZERO = 0;
constexpr const int32_t VALUE_INDEX_ONE = 1;
constexpr const int32_t VALUE_INDEX_TWO = 2;
constexpr const int32_t VALUE_INDEX_THREE = 3;
constexpr const int32_t VALUE_INDEX_FOUR = 4;
constexpr const int32_t VALUE_INDEX_FIVE = 5;
constexpr const int32_t VALUE_LEN_ZERO = 0;
constexpr const int32_t VALUE_LEN_ONE = 1;
constexpr const int32_t VALUE_LEN_TWO = 2;
constexpr const int32_t VALUE_LEN_THREE = 3;
constexpr const int32_t VALUE_LEN_FOUR = 4;
constexpr const int32_t VALUE_LEN_FIVE = 5;
constexpr const int32_t CONTACTS_NOT_DELETED = 0;
constexpr const int32_t ENCODEN_QUOTED_PRIN_MAX_LEN = 67;
constexpr const int32_t NUM_MINUS_ONE = -1;
constexpr const int32_t DECODE_CHAR_MAX_SIZE = 16;
constexpr const int32_t BATCH_INSERT_MAX_SIZE = 300;

class TypeId {
public:
    static constexpr int32_t EMAIL = 1;
    static constexpr int32_t IM = 2;
    static constexpr int32_t NICKNAME = 3;
    static constexpr int32_t ORGANIZATION = 4;
    static constexpr int32_t PHONE = 5;
    static constexpr int32_t NAME = 6;
    static constexpr int32_t POSTAL_ADDRESS = 7;
    static constexpr int32_t PHOTO = 8;
    static constexpr int32_t NOTE = 10;
    static constexpr int32_t CONTACT_EVENT = 11;
    static constexpr int32_t WEBSITE = 12;
    static constexpr int32_t RELATION = 13;
    static constexpr int32_t SIP_ADDRESS = 17;
};

class TypeData {
public:
    static constexpr const char *EMAIL = "email";
    static constexpr const char *IM = "im";
    static constexpr const char *NICKNAME = "nickname";
    static constexpr const char *ORGANIZATION = "organization";
    static constexpr const char *PHONE = "phone";
    static constexpr const char *NAME = "name";
    static constexpr const char *ADDRESS = "postal_address";
    static constexpr const char *PHOTO = "photo";
    static constexpr const char *GROUP_MEMBERSHIP = "group_membership";
    static constexpr const char *NOTE = "note";
    static constexpr const char *CONTACT_EVENT = "contact_event";
    static constexpr const char *WEBSITE = "website";
    static constexpr const char *RELATION = "relation";
    static constexpr const char *CONTACT_MISC = "contact_misc";
    static constexpr const char *HICALL_DEVICE = "hicall_device";
    static constexpr const char *CAMCARD = "camcard";
    static constexpr const char *SIP_ADDRESS = "sip_address";
};

// account
class Account {
public:
    static constexpr const char *ID = "id";
    static constexpr const char *ACCOUNT_TYPE = "account_type";
};

// contact
class Contact {
public:
    static constexpr const char *ID = "id";
};

// raw_contact
class RawContact {
public:
    static constexpr const char *ID = "id";
    static constexpr const char *ACCOUNT_ID = "account_id";
    static constexpr const char *CONTACT_ID = "contact_id";
    static constexpr const char *IS_DELETED = "is_deleted";
};

// contact_data
class ContactData {
public:
    static constexpr const char *CONTACT_DATA_ID = "id";
    static constexpr const char *RAW_CONTACT_ID = "raw_contact_id";
    static constexpr const char *TYPE_ID = "type_id";
    static constexpr const char *DETAIL_INFO = "detail_info";
    static constexpr const char *LABEL_ID = "extend7";
    static constexpr const char *LABEL_NAME = "custom_data";
    static constexpr const char *FULL_NAME = "detail_info";
    static constexpr const char *FAMILY_NAME = "family_name";
    static constexpr const char *FAMILY_NAME_PHONETIC = "phonetic_name";
    static constexpr const char *GIVEN_NAME = "given_name";
    static constexpr const char *GIVEN_NAME_PHONETIC = "given_name_phonetic";
    static constexpr const char *MIDDLE_NAME_PHONETIC = "middle_name_phonetic";
    static constexpr const char *MIDDLE_NAME = "other_lan_last_name";
    static constexpr const char *ALIAS_DETAIL_INFO_KEY = "alias_detail_info";
    static constexpr const char *NAME_PREFIX = "alpha_name";
    static constexpr const char *NAME_SUFFIX = "other_lan_first_name";
    static constexpr const char *POBOX = "pobox";
    static constexpr const char *POSTCODE = "postcode";
    static constexpr const char *REGION = "region";
    static constexpr const char *STREET = "street";
    static constexpr const char *COUNTRY = "country";
    static constexpr const char *CITY = "city";
    static constexpr const char *POSITION = "position";
    static constexpr const char *PHONETIC_NAME = "phonetic_name";
};

enum class EmailType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -1,
    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = 0,

    /**
     * Indicates a home email.
     */
    EMAIL_HOME = 1,

    /**
     * Indicates a work email.
     */
    EMAIL_WORK = 2,

    /**
     * Indicates an email of the OTHER type.
     */
    EMAIL_OTHER = 3,
};

enum class EventType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -1,
    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = 0,

    /**
     * Indicates an anniversary event.
     */
    EVENT_ANNIVERSARY = 1,

    /**
     * Indicates an event of the OTHER type.
     */
    EVENT_OTHER = 2,

    /**
     * Indicates an birthday event.
     */
    EVENT_BIRTHDAY = 3,
};

enum class ImType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -2,

    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = -1,

    /**
     * Indicates an AIM instant message.
     */
    IM_AIM = 0,

    /**
     * Indicates a Windows Live instant message.
     */
    IM_MSN = 1,

    /**
     * Indicates a Yahoo instant message.
     */
    IM_YAHOO = 2,

    /**
     * Indicates a Skype instant message.
     */
    IM_SKYPE = 3,

    /**
     * Indicates a QQ instant message.
     */
    IM_QQ = 4,

    /**
     * Indicates an ICQ instant message.
     */
    IM_ICQ = 6,

    /**
     * Indicates a Jabber instant message.
     */
    IM_JABBER = 7,
};

enum class PhoneVcType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -1,

    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = 0,

    /**
     * Indicates a home number.
     */
    NUM_HOME = 1,

    /**
     * Indicates a mobile phone number.
     */
    NUM_MOBILE = 2,

    /**
     * Indicates a work number.
     */
    NUM_WORK = 3,

    /**
     * Indicates a work fax number.
     */
    NUM_FAX_WORK = 4,

    /**
     * Indicates a home fax number.
     */
    NUM_FAX_HOME = 5,

    /**
     * Indicates a pager number.
     */
    NUM_PAGER = 6,

    /**
     * Indicates a number of the OTHER type.
     */
    NUM_OTHER = 7,

    /**
     * Indicates a callback number.
     */
    NUM_CALLBACK = 8,

    /**
     * Indicates a car number.
     */
    NUM_CAR = 9,

    /**
     * Indicates a company director number.
     */
    NUM_COMPANY_MAIN = 10,

    /**
     * Indicates an Integrated Services Digital Network (ISDN) number.
     */
    NUM_ISDN = 11,

    /**
     * Indicates a main number.
     */
    NUM_MAIN = 12,

    /**
     * Indicates a number of the OTHER_FAX type.
     */
    NUM_OTHER_FAX = 13,

    /**
     * Indicates a radio number.
     */
    NUM_RADIO = 14,

    /**
     * Indicates a telex number.
     */
    NUM_TELEX = 15,

    /**
     * Indicates a teletypewriter (TTY) or test-driven development (TDD) number.
     */
    NUM_TTY_TDD = 16,

    /**
     * Indicates a work mobile phone number.
     */
    NUM_WORK_MOBILE = 17,

    /**
     * Indicates a work pager number.
     */
    NUM_WORK_PAGER = 18,

    /**
     * Indicates an assistant number.
     */
    NUM_ASSISTANT = 19,

    /**
     * Indicates an MMS number.
     */
    NUM_MMS = 20,
};

enum class PostalType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -1,

    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = 0,

    /**
     * Indicates a home address.
     */
    ADDR_HOME = 1,

    /**
     * Indicates a work address.
     */
    ADDR_WORK = 2,

    /**
     * Indicates an address of the OTHER type.
     */
    ADDR_OTHER = 3,
};

enum class SipType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -1,

    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = 0,

    /**
     * Indicates a home SIP address.
     */
    SIP_HOME = 1,

    /**
     * Indicates a work SIP address.
     */
    SIP_WORK = 2,

    /**
     * Indicates an SIP address of the OTHER type.
     */
    SIP_OTHER = 3,
};

enum class RelationType {
    /**
     * Indicates an invalid label ID.
     */
    INVALID_LABEL_ID = -1,

    /**
     * Indicates a custom label.
     */
    CUSTOM_LABEL = 0,

    /**
     * Indicates an assistant.
     */
    RELATION_ASSISTANT = 1,

    /**
     * Indicates a brother.
     */
    RELATION_BROTHER = 2,

    /**
     * Indicates a child.
     */
    RELATION_CHILD = 3,

    /**
     * Indicates a domestic partner.
     */
    RELATION_DOMESTIC_PARTNER = 4,

    /**
     * Indicates a father.
     */
    RELATION_FATHER = 5,

    /**
     * Indicates a friend.
     */
    RELATION_FRIEND = 6,

    /**
     * Indicates a relation manager.
     */
    RELATION_MANAGER = 7,

    /**
     * Indicates a mother.
     */
    RELATION_MOTHER = 8,

    /**
     * Indicates a parent.
     */
    RELATION_PARENT = 9,

    /**
     * Indicates a partner.
     */
    RELATION_PARTNER = 10,

    /**
     * Indicates a referrer.
     */
    RELATION_REFERRED_BY = 11,

    /**
     * Indicates a relative.
     */
    RELATION_RELATIVE = 12,

    /**
     * Indicates a sister.
     */
    RELATION_SISTER = 13,

    /**
     * Indicates a spouse.
     */
    RELATION_SPOUSE = 14,
};

constexpr const char *DATA_VCARD = "VCARD";
constexpr const char *DATA_PUBLIC = "PUBLIC";

constexpr const char *PARAM_SEPARATOR = ";";
constexpr const char *PARAM_SEPARATOR_V3_V4 = ",";
constexpr const char *END_OF_LINE = "\r\n";
constexpr const char *DATA_SEPARATOR = ":";
constexpr const char *ITEM_SEPARATOR = ";";
constexpr const char *WS = " ";
constexpr const char *PARAM_EQUAL = "=";

constexpr const char *PARAM_ENCODING_QP = "ENCODING=QUOTED-PRINTABLE";
constexpr const char *PARAM_ENCODING_BASE64_V21 = "ENCODING=BASE64";
constexpr const char *PARAM_ENCODING_BASE64_AS_B = "ENCODING=B";

constexpr const char *SHIFT_JIS = "SHIFT_JIS";
const int32_t MAX_LINE_NUMS_BASE64_V30 = 75;

} // namespace Telephony
} // namespace OHOS
#endif // VCARD_CONSTANT_H

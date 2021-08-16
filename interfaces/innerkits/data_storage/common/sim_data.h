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

#ifndef DATA_STORAGE_SIM_DATA_H
#define DATA_STORAGE_SIM_DATA_H

namespace OHOS {
namespace Telephony {
const std::string SIM_ID = "sim_id";
const std::string ICC_ID = "icc_id";
const std::string CARD_ID = "card_id";
const std::string SLOT_INDEX = "slot_index";
const std::string SHOW_NAME = "show_name";
const std::string PHONE_NUMBER = "phone_number";
const std::string COUNTRY_CODE = "country_code";
const std::string LANGUAGE = "language";
const std::string IMSI = "imsi";
const std::string CARD_TYPE = "card_type";
const std::string IS_ACTIVE = "is_active";
const std::string IS_MAIN_CARD = "is_main_card";
const std::string IS_MESSAGE_CARD = "is_message_card";
const std::string IS_CELLULAR_DATA_CARD = "is_cellular_data_card";

struct SimInfo {
    int simId;
    std::string iccId;
    std::string cardId;
    int slotIndex;
    int cardType;
    std::string showName;
    std::string phoneNumber;
    std::string countryCode;
    std::string language;
    std::string imsi;
    int isMainCard;
    int isMessageCard;
    int isCellularDataCard;
    int isActive;
};

const std::string SIM_URI = "dataability://telephony.sim";

enum SimUriType { ALL, MAIN_CARD, CELLULAR_DATA_CARD, MESSAGE_CARD, CURRENT, ID, DELETE, UPDATE, INSERT };
} // namespace Telephony
} // namespace OHOS
#endif // DATA_STORAGE_SIM_DATA_H
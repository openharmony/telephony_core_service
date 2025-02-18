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

#include "mcc_pool.h"

using namespace std;

namespace OHOS {
namespace Telephony {
std::mutex mccMutex_;
std::mutex initMutex_;
std::vector<std::shared_ptr<MccAccess>> MccPool::mccAccessTable_;
std::vector<std::string> MccPool::specialMccMnc_;
std::vector<std::string> MccPool::indiaMccMnc_;
constexpr size_t MCC_ACCESS_TABLE_LEN = 240;
std::shared_ptr<MccAccess> MccPool::AccessToMcc(int mcc)
{
    std::lock_guard<std::mutex> lock(mccMutex_);
    InitMccTables();
    auto it = std::find_if(mccAccessTable_.begin(), mccAccessTable_.end(),
        [mcc](const auto &p) { return p != nullptr && p->mcc_ == mcc; });
    if (it != mccAccessTable_.end()) {
        return *it;
    } else {
        return std::make_shared<MccAccess>(mcc, "", 0);
    }
}

std::string MccPool::MccCountryCode(int mcc)
{
    auto entry = AccessToMcc(mcc);
    if (entry == nullptr) {
        return "";
    }
    return entry->iso_;
}

int MccPool::ShortestMncLengthFromMcc(int mcc)
{
    auto access = AccessToMcc(mcc);
    if (access == nullptr || access->iso_.empty()) {
        return MCC_SHORT;
    } else {
        return access->mncShortestLength_;
    }
}

void MccPool::InitMccTables()
{
    if (mccAccessTable_.size() == 0) {
        mccAccessTable_.reserve(MCC_ACCESS_TABLE_LEN);
        AddMccForAsia();
        AddMccForEurope();
        AddMccForAfrica();
        AddMccForNorthAmerica();
        AddMccForSouthAmerica();
        AddMccForAustralia();
        std::sort(mccAccessTable_.begin(), mccAccessTable_.end(), MccPool::MccCompare);
    }
}

void MccPool::AddMccForAsia()
{
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GR, "gr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NL, "nl", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BE, "be", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_FR, "fr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MC, "mc", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AD, "ad", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ES, "es", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_HU, "hu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BA, "ba", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_HR, "hr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_RS, "rs", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IT, "it", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VA, "va", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_RO, "ro", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CH, "ch", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CZ, "cz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SK, "sk", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AT, "at", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GB_A, "gb", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GB_B, "gb", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_DK, "dk", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SE, "se", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NO, "no", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_FI, "fi", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LT, "lt", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LV, "lv", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_EE, "ee", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_RU, "ru", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_UA, "ua", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BY, "by", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MD, "md", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PL, "pl", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_DE, "de", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GI, "gi", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PT, "pt", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LU, "lu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IE, "ie", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IS, "is", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AL, "al", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MT, "mt", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CY, "cy", MCC_SHORT));
}

void MccPool::AddMccForEurope()
{
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GE_A, "ge", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AM, "am", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BG, "bg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TR, "tr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_FO, "fo", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GE_B, "ge", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GL, "gl", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SM, "sm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SI, "si", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MK, "mk", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LI, "li", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ME, "me", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CA, "ca", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PM, "pm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_A, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_B, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_C, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_D, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_E, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_F, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_US_G, "us", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PR, "pr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VI, "vi", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MX, "mx", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_JM, "jm", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GP, "gp", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BB, "bb", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AG, "ag", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KY, "ky", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VG, "vg", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BM, "bm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GD, "gd", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MS, "ms", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KN, "kn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LC, "lc", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VC, "vc", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AI_A, "ai", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AW, "aw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BS, "bs", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AI_B, "ai", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_DM, "dm", MCC_SHORT));
}

void MccPool::AddMccForAfrica()
{
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CU, "cu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_DO, "do", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_HT, "ht", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TT, "tt", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TC, "tc", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AZ, "az", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KZ, "kz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BT, "bt", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IN_A, "in", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IN_B, "in", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IN_C, "in", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PK, "pk", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AF, "af", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LK, "lk", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MM, "mm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LB, "lb", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_JO, "jo", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SY, "sy", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IQ, "iq", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KW, "kw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SA, "sa", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_YE, "ye", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_OM, "om", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PS, "ps", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AE_A, "ae", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IL, "il", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BH, "bh", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_QA, "qa", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MN, "mn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NP, "np", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AE_B, "ae", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AE_C, "ae", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_IR, "ir", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_UZ, "uz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TJ, "tj", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KG, "kg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TM, "tm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_JP_A, "jp", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_JP_B, "jp", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KR, "kr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VN, "vn", MCC_SHORT));
}

void MccPool::AddMccForNorthAmerica()
{
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_HK, "hk", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MO, "mo", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KH, "kh", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LA, "la", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CN_A, "cn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CN_B, "cn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TW, "tw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KP, "kp", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BD, "bd", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MV, "mv", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MY, "my", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AU, "au", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ID, "id", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TL, "tl", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PH, "ph", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TH, "th", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SG, "sg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BN, "bn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NZ, "nz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MP, "mp", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GU, "gu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NR, "nr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PG, "pg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TO, "to", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SB, "sb", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VU, "vu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_FJ, "fj", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_WF, "wf", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AS, "as", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KI, "ki", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NC, "nc", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PF, "pf", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CK, "ck", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_WS, "ws", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_FM, "fm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MH, "mh", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PW, "pw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TV, "tv", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NU, "nu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_EG, "eg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_DZ, "dz", MCC_SHORT));
}

void MccPool::AddMccForSouthAmerica()
{
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MA, "ma", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TN, "tn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LY, "ly", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GM, "gm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SN, "sn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MR, "mr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ML, "ml", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GN, "gn", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CI, "ci", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BF, "bf", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NE, "ne", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TG, "tg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BJ, "bj", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MU, "mu", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LR, "lr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SL, "sl", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GH, "gh", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NG, "ng", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TD, "td", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CF, "cf", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CM, "cm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CV, "cv", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ST, "st", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GQ, "gq", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GA, "ga", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CG, "cg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CD, "cd", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AO, "ao", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GW, "gw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SC, "sc", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SD, "sd", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_RW, "rw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ET, "et", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SO, "so", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_DJ, "dj", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KE, "ke", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_TZ, "tz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_UG, "ug", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BI, "bi", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MZ, "mz", MCC_SHORT));
}

void MccPool::AddMccForAustralia()
{
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ZM, "zm", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MG, "mg", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_RE, "re", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ZW, "zw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NA, "na", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_MW, "mw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_LS, "ls", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BW, "bw", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SZ, "sz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_KM, "km", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ZA, "za", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_ER, "er", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SH, "sh", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SS, "ss", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BZ, "bz", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GT, "gt", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SV, "sv", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_HN, "hn", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_NI, "ni", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CR, "cr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PA, "pa", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PE, "pe", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_AR, "ar", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BR, "br", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CL, "cl", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_CO, "co", MCC_LONG));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_VE, "ve", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_BO, "bo", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GY, "gy", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_EC, "ec", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_GF, "gf", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_PY, "py", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_SR, "sr", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_UY, "uy", MCC_SHORT));
    mccAccessTable_.push_back(std::make_shared<MccAccess>(MCC_FK, "fk", MCC_SHORT));
}

bool MccPool::MccCompare(const std::shared_ptr<MccAccess> &mccAccessA, const std::shared_ptr<MccAccess> &mccAccessB)
{
    if (mccAccessA == nullptr || mccAccessB == nullptr) {
        return false;
    }
    return (mccAccessA->mcc_ < mccAccessB->mcc_);
}

bool MccPool::LengthIsTwoMnc(const std::string &mccMncCode)
{
    InitIndiaTables();
    std::vector<std::string>::iterator obj = std::find(indiaMccMnc_.begin(), indiaMccMnc_.end(), mccMncCode);
    return (obj == indiaMccMnc_.end()) ? false : true;
}

void MccPool::InitIndiaTables()
{
    if (indiaMccMnc_.size() == 0) {
        indiaMccMnc_ = {"40400", "40401", "40402", "40403", "40404", "40405", "40407", "40409",
            "40410", "40411", "40412", "40413", "40414", "40415", "40416", "40417",
            "40418", "40419", "40420", "40421", "40422", "40424", "40425", "40427",
            "40428", "40429", "40430", "40431", "40433", "40434", "40435", "40436",
            "40437", "40438", "40440", "40441", "40442", "40443", "40444", "40445",
            "40446", "40449", "40450", "40451", "40452", "40453", "40454", "40455",
            "40456", "40457", "40458", "40459", "40460", "40462", "40464", "40466",
            "40467", "40468", "40469", "40470", "40471", "40472", "40473", "40474",
            "40475", "40476", "40477", "40478", "40479", "40480", "40481", "40482",
            "40483", "40484", "40485", "40486", "40487", "40488", "40489", "40490",
            "40491", "40492", "40493", "40494", "40495", "40496", "40497", "40498",
            "40501", "40505", "40506", "40507", "40508", "40509", "40510", "40511",
            "40512", "40513", "40514", "40515", "40517", "40518", "40519", "40520",
            "40521", "40522", "40523", "40524", "40548", "40551", "40552", "40553",
            "40554", "40555", "40556", "40566", "40567", "40570"};
    }
}

bool MccPool::LengthIsThreeMnc(const std::string &mccMncCode)
{
    InitSpecialMccMncTables();
    std::vector<std::string>::iterator obj = std::find(specialMccMnc_.begin(), specialMccMnc_.end(), mccMncCode);
    return (obj == specialMccMnc_.end()) ? false : true;
}

void MccPool::InitSpecialMccMncTables()
{
    std::lock_guard<std::mutex> lck(initMutex_);
    if (specialMccMnc_.size() == 0) {
        AddMccMncForCa();
        AddMccMncForInAirtel();
        AddMccMncForInHutch();
        AddMccMncForMy();
    }
}

void MccPool::AddMccMncForCa()
{
    specialMccMnc_.push_back("302370");
    specialMccMnc_.push_back("302720");
    specialMccMnc_.push_back("310260");
    specialMccMnc_.push_back("405025");
    specialMccMnc_.push_back("405026");
    specialMccMnc_.push_back("405027");
    specialMccMnc_.push_back("405028");
    specialMccMnc_.push_back("405029");
    specialMccMnc_.push_back("405030");
    specialMccMnc_.push_back("405031");
    specialMccMnc_.push_back("405032");
    specialMccMnc_.push_back("405033");
    specialMccMnc_.push_back("405034");
    specialMccMnc_.push_back("405035");
    specialMccMnc_.push_back("405036");
    specialMccMnc_.push_back("405037");
    specialMccMnc_.push_back("405038");
    specialMccMnc_.push_back("405039");
    specialMccMnc_.push_back("405040");
    specialMccMnc_.push_back("405041");
    specialMccMnc_.push_back("405042");
    specialMccMnc_.push_back("405043");
    specialMccMnc_.push_back("405044");
    specialMccMnc_.push_back("405045");
    specialMccMnc_.push_back("405046");
    specialMccMnc_.push_back("405047");
    specialMccMnc_.push_back("405750");
    specialMccMnc_.push_back("405751");
    specialMccMnc_.push_back("405752");
    specialMccMnc_.push_back("405753");
    specialMccMnc_.push_back("405754");
    specialMccMnc_.push_back("405755");
    specialMccMnc_.push_back("405756");
    specialMccMnc_.push_back("405799");
    specialMccMnc_.push_back("405800");
    specialMccMnc_.push_back("405801");
}

void MccPool::AddMccMncForInAirtel()
{
    specialMccMnc_.push_back("405802");
    specialMccMnc_.push_back("405803");
    specialMccMnc_.push_back("405804");
    specialMccMnc_.push_back("405805");
    specialMccMnc_.push_back("405806");
    specialMccMnc_.push_back("405807");
    specialMccMnc_.push_back("405808");
    specialMccMnc_.push_back("405809");
    specialMccMnc_.push_back("405810");
    specialMccMnc_.push_back("405811");
    specialMccMnc_.push_back("405812");
    specialMccMnc_.push_back("405813");
    specialMccMnc_.push_back("405814");
    specialMccMnc_.push_back("405815");
    specialMccMnc_.push_back("405816");
    specialMccMnc_.push_back("405817");
    specialMccMnc_.push_back("405818");
    specialMccMnc_.push_back("405819");
    specialMccMnc_.push_back("405820");
    specialMccMnc_.push_back("405821");
    specialMccMnc_.push_back("405822");
    specialMccMnc_.push_back("405823");
    specialMccMnc_.push_back("405824");
    specialMccMnc_.push_back("405825");
    specialMccMnc_.push_back("405826");
    specialMccMnc_.push_back("405827");
    specialMccMnc_.push_back("405828");
    specialMccMnc_.push_back("405829");
    specialMccMnc_.push_back("405830");
    specialMccMnc_.push_back("405831");
    specialMccMnc_.push_back("405832");
    specialMccMnc_.push_back("405833");
    specialMccMnc_.push_back("405834");
    specialMccMnc_.push_back("405835");
    specialMccMnc_.push_back("405836");
}

void MccPool::AddMccMncForInHutch()
{
    specialMccMnc_.push_back("405837");
    specialMccMnc_.push_back("405838");
    specialMccMnc_.push_back("405839");
    specialMccMnc_.push_back("405840");
    specialMccMnc_.push_back("405841");
    specialMccMnc_.push_back("405842");
    specialMccMnc_.push_back("405843");
    specialMccMnc_.push_back("405844");
    specialMccMnc_.push_back("405845");
    specialMccMnc_.push_back("405846");
    specialMccMnc_.push_back("405847");
    specialMccMnc_.push_back("405848");
    specialMccMnc_.push_back("405849");
    specialMccMnc_.push_back("405850");
    specialMccMnc_.push_back("405851");
    specialMccMnc_.push_back("405852");
    specialMccMnc_.push_back("405853");
    specialMccMnc_.push_back("405854");
    specialMccMnc_.push_back("405855");
    specialMccMnc_.push_back("405856");
    specialMccMnc_.push_back("405857");
    specialMccMnc_.push_back("405858");
    specialMccMnc_.push_back("405859");
    specialMccMnc_.push_back("405860");
    specialMccMnc_.push_back("405861");
    specialMccMnc_.push_back("405862");
    specialMccMnc_.push_back("405863");
    specialMccMnc_.push_back("405864");
    specialMccMnc_.push_back("405865");
    specialMccMnc_.push_back("405866");
    specialMccMnc_.push_back("405867");
    specialMccMnc_.push_back("405868");
    specialMccMnc_.push_back("405869");
    specialMccMnc_.push_back("405870");
    specialMccMnc_.push_back("405871");
    specialMccMnc_.push_back("405872");
    specialMccMnc_.push_back("405873");
    specialMccMnc_.push_back("405874");
    specialMccMnc_.push_back("405875");
}

void MccPool::AddMccMncForMy()
{
    specialMccMnc_.push_back("405876");
    specialMccMnc_.push_back("405877");
    specialMccMnc_.push_back("405878");
    specialMccMnc_.push_back("405879");
    specialMccMnc_.push_back("405880");
    specialMccMnc_.push_back("405881");
    specialMccMnc_.push_back("405882");
    specialMccMnc_.push_back("405883");
    specialMccMnc_.push_back("405884");
    specialMccMnc_.push_back("405885");
    specialMccMnc_.push_back("405886");
    specialMccMnc_.push_back("405908");
    specialMccMnc_.push_back("405909");
    specialMccMnc_.push_back("405910");
    specialMccMnc_.push_back("405911");
    specialMccMnc_.push_back("405912");
    specialMccMnc_.push_back("405913");
    specialMccMnc_.push_back("405914");
    specialMccMnc_.push_back("405915");
    specialMccMnc_.push_back("405916");
    specialMccMnc_.push_back("405917");
    specialMccMnc_.push_back("405918");
    specialMccMnc_.push_back("405919");
    specialMccMnc_.push_back("405920");
    specialMccMnc_.push_back("405921");
    specialMccMnc_.push_back("405922");
    specialMccMnc_.push_back("405923");
    specialMccMnc_.push_back("405924");
    specialMccMnc_.push_back("405925");
    specialMccMnc_.push_back("405926");
    specialMccMnc_.push_back("405927");
    specialMccMnc_.push_back("405928");
    specialMccMnc_.push_back("405929");
    specialMccMnc_.push_back("405930");
    specialMccMnc_.push_back("405931");
    specialMccMnc_.push_back("405932");
    specialMccMnc_.push_back("502142");
    specialMccMnc_.push_back("502143");
    specialMccMnc_.push_back("502145");
    specialMccMnc_.push_back("502146");
    specialMccMnc_.push_back("502147");
    specialMccMnc_.push_back("502148");
}

MccPool::MccPool() {}

MccPool::~MccPool() {}
} // namespace Telephony
} // namespace OHOS

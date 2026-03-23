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
#include "telephony_log_wrapper.h"

using namespace std;

namespace OHOS {
namespace Telephony {
std::mutex MccPool::mccMutex_;
std::vector<MccPool::MccAccessData> MccPool::mccAccessDataTable_;
std::vector<std::string> MccPool::specialMccMnc_;
std::vector<std::string> MccPool::indiaMccMnc_;
constexpr size_t MCC_ACCESS_TABLE_LEN = 240;
constexpr const char MCC_ISO_GR[] = "gr";
constexpr const char MCC_ISO_NL[] = "nl";
constexpr const char MCC_ISO_BE[] = "be";
constexpr const char MCC_ISO_FR[] = "fr";
constexpr const char MCC_ISO_MC[] = "mc";
constexpr const char MCC_ISO_AD[] = "ad";
constexpr const char MCC_ISO_ES[] = "es";
constexpr const char MCC_ISO_HU[] = "hu";
constexpr const char MCC_ISO_BA[] = "ba";
constexpr const char MCC_ISO_HR[] = "hr";
constexpr const char MCC_ISO_RS[] = "rs";
constexpr const char MCC_ISO_IT[] = "it";
constexpr const char MCC_ISO_VA[] = "va";
constexpr const char MCC_ISO_RO[] = "ro";
constexpr const char MCC_ISO_CH[] = "ch";
constexpr const char MCC_ISO_CZ[] = "cz";
constexpr const char MCC_ISO_SK[] = "sk";
constexpr const char MCC_ISO_AT[] = "at";
constexpr const char MCC_ISO_GB[] = "gb";
constexpr const char MCC_ISO_DK[] = "dk";
constexpr const char MCC_ISO_SE[] = "se";
constexpr const char MCC_ISO_NO[] = "no";
constexpr const char MCC_ISO_FI[] = "fi";
constexpr const char MCC_ISO_LT[] = "lt";
constexpr const char MCC_ISO_LV[] = "lv";
constexpr const char MCC_ISO_EE[] = "ee";
constexpr const char MCC_ISO_RU[] = "ru";
constexpr const char MCC_ISO_UA[] = "ua";
constexpr const char MCC_ISO_BY[] = "by";
constexpr const char MCC_ISO_MD[] = "md";
constexpr const char MCC_ISO_PL[] = "pl";
constexpr const char MCC_ISO_DE[] = "de";
constexpr const char MCC_ISO_GI[] = "gi";
constexpr const char MCC_ISO_PT[] = "pt";
constexpr const char MCC_ISO_LU[] = "lu";
constexpr const char MCC_ISO_IE[] = "ie";
constexpr const char MCC_ISO_IS[] = "is";
constexpr const char MCC_ISO_AL[] = "al";
constexpr const char MCC_ISO_MT[] = "mt";
constexpr const char MCC_ISO_CY[] = "cy";
constexpr const char MCC_ISO_GE[] = "ge";
constexpr const char MCC_ISO_AM[] = "am";
constexpr const char MCC_ISO_BG[] = "bg";
constexpr const char MCC_ISO_TR[] = "tr";
constexpr const char MCC_ISO_FO[] = "fo";
constexpr const char MCC_ISO_GL[] = "gl";
constexpr const char MCC_ISO_SM[] = "sm";
constexpr const char MCC_ISO_SI[] = "si";
constexpr const char MCC_ISO_MK[] = "mk";
constexpr const char MCC_ISO_LI[] = "li";
constexpr const char MCC_ISO_ME[] = "me";
constexpr const char MCC_ISO_CA[] = "ca";
constexpr const char MCC_ISO_PM[] = "pm";
constexpr const char MCC_ISO_US[] = "us";
constexpr const char MCC_ISO_PR[] = "pr";
constexpr const char MCC_ISO_VI[] = "vi";
constexpr const char MCC_ISO_MX[] = "mx";
constexpr const char MCC_ISO_JM[] = "jm";
constexpr const char MCC_ISO_GP[] = "gp";
constexpr const char MCC_ISO_BB[] = "bb";
constexpr const char MCC_ISO_AG[] = "ag";
constexpr const char MCC_ISO_KY[] = "ky";
constexpr const char MCC_ISO_VG[] = "vg";
constexpr const char MCC_ISO_BM[] = "bm";
constexpr const char MCC_ISO_GD[] = "gd";
constexpr const char MCC_ISO_MS[] = "ms";
constexpr const char MCC_ISO_KN[] = "kn";
constexpr const char MCC_ISO_LC[] = "lc";
constexpr const char MCC_ISO_VC[] = "vc";
constexpr const char MCC_ISO_AI[] = "ai";
constexpr const char MCC_ISO_AW[] = "aw";
constexpr const char MCC_ISO_BS[] = "bs";
constexpr const char MCC_ISO_DM[] = "dm";
constexpr const char MCC_ISO_CU[] = "cu";
constexpr const char MCC_ISO_DO[] = "do";
constexpr const char MCC_ISO_HT[] = "ht";
constexpr const char MCC_ISO_TT[] = "tt";
constexpr const char MCC_ISO_TC[] = "tc";
constexpr const char MCC_ISO_AZ[] = "az";
constexpr const char MCC_ISO_KZ[] = "kz";
constexpr const char MCC_ISO_BT[] = "bt";
constexpr const char MCC_ISO_IN[] = "in";
constexpr const char MCC_ISO_PK[] = "pk";
constexpr const char MCC_ISO_AF[] = "af";
constexpr const char MCC_ISO_LK[] = "lk";
constexpr const char MCC_ISO_MM[] = "mm";
constexpr const char MCC_ISO_LB[] = "lb";
constexpr const char MCC_ISO_JO[] = "jo";
constexpr const char MCC_ISO_SY[] = "sy";
constexpr const char MCC_ISO_IQ[] = "iq";
constexpr const char MCC_ISO_KW[] = "kw";
constexpr const char MCC_ISO_SA[] = "sa";
constexpr const char MCC_ISO_YE[] = "ye";
constexpr const char MCC_ISO_OM[] = "om";
constexpr const char MCC_ISO_PS[] = "ps";
constexpr const char MCC_ISO_AE[] = "ae";
constexpr const char MCC_ISO_IL[] = "il";
constexpr const char MCC_ISO_BH[] = "bh";
constexpr const char MCC_ISO_QA[] = "qa";
constexpr const char MCC_ISO_MN[] = "mn";
constexpr const char MCC_ISO_NP[] = "np";
constexpr const char MCC_ISO_IR[] = "ir";
constexpr const char MCC_ISO_UZ[] = "uz";
constexpr const char MCC_ISO_TJ[] = "tj";
constexpr const char MCC_ISO_KG[] = "kg";
constexpr const char MCC_ISO_TM[] = "tm";
constexpr const char MCC_ISO_JP[] = "jp";
constexpr const char MCC_ISO_KR[] = "kr";
constexpr const char MCC_ISO_VN[] = "vn";
constexpr const char MCC_ISO_HK[] = "hk";
constexpr const char MCC_ISO_MO[] = "mo";
constexpr const char MCC_ISO_KH[] = "kh";
constexpr const char MCC_ISO_LA[] = "la";
constexpr const char MCC_ISO_CN[] = "cn";
constexpr const char MCC_ISO_TW[] = "tw";
constexpr const char MCC_ISO_KP[] = "kp";
constexpr const char MCC_ISO_BD[] = "bd";
constexpr const char MCC_ISO_MV[] = "mv";
constexpr const char MCC_ISO_MY[] = "my";
constexpr const char MCC_ISO_AU[] = "au";
constexpr const char MCC_ISO_ID[] = "id";
constexpr const char MCC_ISO_TL[] = "tl";
constexpr const char MCC_ISO_PH[] = "ph";
constexpr const char MCC_ISO_TH[] = "th";
constexpr const char MCC_ISO_SG[] = "sg";
constexpr const char MCC_ISO_BN[] = "bn";
constexpr const char MCC_ISO_NZ[] = "nz";
constexpr const char MCC_ISO_MP[] = "mp";
constexpr const char MCC_ISO_GU[] = "gu";
constexpr const char MCC_ISO_NR[] = "nr";
constexpr const char MCC_ISO_PG[] = "pg";
constexpr const char MCC_ISO_TO[] = "to";
constexpr const char MCC_ISO_SB[] = "sb";
constexpr const char MCC_ISO_VU[] = "vu";
constexpr const char MCC_ISO_FJ[] = "fj";
constexpr const char MCC_ISO_WF[] = "wf";
constexpr const char MCC_ISO_AS[] = "as";
constexpr const char MCC_ISO_KI[] = "ki";
constexpr const char MCC_ISO_NC[] = "nc";
constexpr const char MCC_ISO_PF[] = "pf";
constexpr const char MCC_ISO_CK[] = "ck";
constexpr const char MCC_ISO_WS[] = "ws";
constexpr const char MCC_ISO_FM[] = "fm";
constexpr const char MCC_ISO_MH[] = "mh";
constexpr const char MCC_ISO_PW[] = "pw";
constexpr const char MCC_ISO_TV[] = "tv";
constexpr const char MCC_ISO_NU[] = "nu";
constexpr const char MCC_ISO_EG[] = "eg";
constexpr const char MCC_ISO_DZ[] = "dz";
constexpr const char MCC_ISO_MA[] = "ma";
constexpr const char MCC_ISO_TN[] = "tn";
constexpr const char MCC_ISO_LY[] = "ly";
constexpr const char MCC_ISO_GM[] = "gm";
constexpr const char MCC_ISO_SN[] = "sn";
constexpr const char MCC_ISO_MR[] = "mr";
constexpr const char MCC_ISO_ML[] = "ml";
constexpr const char MCC_ISO_GN[] = "gn";
constexpr const char MCC_ISO_CI[] = "ci";
constexpr const char MCC_ISO_BF[] = "bf";
constexpr const char MCC_ISO_NE[] = "ne";
constexpr const char MCC_ISO_TG[] = "tg";
constexpr const char MCC_ISO_BJ[] = "bj";
constexpr const char MCC_ISO_MU[] = "mu";
constexpr const char MCC_ISO_LR[] = "lr";
constexpr const char MCC_ISO_SL[] = "sl";
constexpr const char MCC_ISO_GH[] = "gh";
constexpr const char MCC_ISO_NG[] = "ng";
constexpr const char MCC_ISO_TD[] = "td";
constexpr const char MCC_ISO_CF[] = "cf";
constexpr const char MCC_ISO_CM[] = "cm";
constexpr const char MCC_ISO_CV[] = "cv";
constexpr const char MCC_ISO_ST[] = "st";
constexpr const char MCC_ISO_GQ[] = "gq";
constexpr const char MCC_ISO_GA[] = "ga";
constexpr const char MCC_ISO_CG[] = "cg";
constexpr const char MCC_ISO_CD[] = "cd";
constexpr const char MCC_ISO_AO[] = "ao";
constexpr const char MCC_ISO_GW[] = "gw";
constexpr const char MCC_ISO_SC[] = "sc";
constexpr const char MCC_ISO_SD[] = "sd";
constexpr const char MCC_ISO_RW[] = "rw";
constexpr const char MCC_ISO_ET[] = "et";
constexpr const char MCC_ISO_SO[] = "so";
constexpr const char MCC_ISO_DJ[] = "dj";
constexpr const char MCC_ISO_KE[] = "ke";
constexpr const char MCC_ISO_TZ[] = "tz";
constexpr const char MCC_ISO_UG[] = "ug";
constexpr const char MCC_ISO_BI[] = "bi";
constexpr const char MCC_ISO_MZ[] = "mz";
constexpr const char MCC_ISO_ZM[] = "zm";
constexpr const char MCC_ISO_MG[] = "mg";
constexpr const char MCC_ISO_RE[] = "re";
constexpr const char MCC_ISO_ZW[] = "zw";
constexpr const char MCC_ISO_NA[] = "na";
constexpr const char MCC_ISO_MW[] = "mw";
constexpr const char MCC_ISO_LS[] = "ls";
constexpr const char MCC_ISO_BW[] = "bw";
constexpr const char MCC_ISO_SZ[] = "sz";
constexpr const char MCC_ISO_KM[] = "km";
constexpr const char MCC_ISO_ZA[] = "za";
constexpr const char MCC_ISO_ER[] = "er";
constexpr const char MCC_ISO_SH[] = "sh";
constexpr const char MCC_ISO_SS[] = "ss";
constexpr const char MCC_ISO_BZ[] = "bz";
constexpr const char MCC_ISO_GT[] = "gt";
constexpr const char MCC_ISO_SV[] = "sv";
constexpr const char MCC_ISO_HN[] = "hn";
constexpr const char MCC_ISO_NI[] = "ni";
constexpr const char MCC_ISO_CR[] = "cr";
constexpr const char MCC_ISO_PA[] = "pa";
constexpr const char MCC_ISO_PE[] = "pe";
constexpr const char MCC_ISO_AR[] = "ar";
constexpr const char MCC_ISO_BR[] = "br";
constexpr const char MCC_ISO_CL[] = "cl";
constexpr const char MCC_ISO_CO[] = "co";
constexpr const char MCC_ISO_VE[] = "ve";
constexpr const char MCC_ISO_BO[] = "bo";
constexpr const char MCC_ISO_GY[] = "gy";
constexpr const char MCC_ISO_EC[] = "ec";
constexpr const char MCC_ISO_GF[] = "gf";
constexpr const char MCC_ISO_PY[] = "py";
constexpr const char MCC_ISO_SR[] = "sr";
constexpr const char MCC_ISO_UY[] = "uy";
constexpr const char MCC_ISO_FK[] = "fk";

std::shared_ptr<MccAccess> MccPool::AccessToMcc(int mcc)
{
    std::lock_guard<std::mutex> lock(mccMutex_);
    InitMccTables();
    auto it = std::find_if(mccAccessDataTable_.begin(), mccAccessDataTable_.end(),
        [mcc](const auto &p) { return p.mcc_ == mcc; });
    if (it != mccAccessDataTable_.end()) {
        return std::make_shared<MccAccess>(it->mcc_, it->iso_, it->mncShortestLength_);
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
    if (mccAccessDataTable_.size() == 0) {
        mccAccessDataTable_.reserve(MCC_ACCESS_TABLE_LEN);
        AddMccForAsia();
        AddMccForEurope();
        AddMccForAfrica();
        AddMccForNorthAmerica();
        AddMccForSouthAmerica();
        AddMccForAustralia();
        std::sort(mccAccessDataTable_.begin(), mccAccessDataTable_.end(), MccPool::MccCompare);
    }
}

void MccPool::AddMccForAsia()
{
    std::vector<MccAccessData> tmp = {
        {MCC_GR, MCC_ISO_GR, MCC_SHORT},
        {MCC_NL, MCC_ISO_NL, MCC_SHORT},
        {MCC_BE, MCC_ISO_BE, MCC_SHORT},
        {MCC_FR, MCC_ISO_FR, MCC_SHORT},
        {MCC_MC, MCC_ISO_MC, MCC_SHORT},
        {MCC_AD, MCC_ISO_AD, MCC_SHORT},
        {MCC_ES, MCC_ISO_ES, MCC_SHORT},
        {MCC_HU, MCC_ISO_HU, MCC_SHORT},
        {MCC_BA, MCC_ISO_BA, MCC_SHORT},
        {MCC_HR, MCC_ISO_HR, MCC_SHORT},
        {MCC_RS, MCC_ISO_RS, MCC_SHORT},
        {MCC_IT, MCC_ISO_IT, MCC_SHORT},
        {MCC_VA, MCC_ISO_VA, MCC_SHORT},
        {MCC_RO, MCC_ISO_RO, MCC_SHORT},
        {MCC_CH, MCC_ISO_CH, MCC_SHORT},
        {MCC_CZ, MCC_ISO_CZ, MCC_SHORT},
        {MCC_SK, MCC_ISO_SK, MCC_SHORT},
        {MCC_AT, MCC_ISO_AT, MCC_SHORT},
        {MCC_GB_A, MCC_ISO_GB, MCC_SHORT},
        {MCC_GB_B, MCC_ISO_GB, MCC_SHORT},
        {MCC_DK, MCC_ISO_DK, MCC_SHORT},
        {MCC_SE, MCC_ISO_SE, MCC_SHORT},
        {MCC_NO, MCC_ISO_NO, MCC_SHORT},
        {MCC_FI, MCC_ISO_FI, MCC_SHORT},
        {MCC_LT, MCC_ISO_LT, MCC_SHORT},
        {MCC_LV, MCC_ISO_LV, MCC_SHORT},
        {MCC_EE, MCC_ISO_EE, MCC_SHORT},
        {MCC_RU, MCC_ISO_RU, MCC_SHORT},
        {MCC_UA, MCC_ISO_UA, MCC_SHORT},
        {MCC_BY, MCC_ISO_BY, MCC_SHORT},
        {MCC_MD, MCC_ISO_MD, MCC_SHORT},
        {MCC_PL, MCC_ISO_PL, MCC_SHORT},
        {MCC_DE, MCC_ISO_DE, MCC_SHORT},
        {MCC_GI, MCC_ISO_GI, MCC_SHORT},
        {MCC_PT, MCC_ISO_PT, MCC_SHORT},
        {MCC_LU, MCC_ISO_LU, MCC_SHORT},
        {MCC_IE, MCC_ISO_IE, MCC_SHORT},
        {MCC_IS, MCC_ISO_IS, MCC_SHORT},
        {MCC_AL, MCC_ISO_AL, MCC_SHORT},
        {MCC_MT, MCC_ISO_MT, MCC_SHORT},
        {MCC_CY, MCC_ISO_CY, MCC_SHORT}
    };
    mccAccessDataTable_.insert(mccAccessDataTable_.end(), tmp.begin(), tmp.end());
}

void MccPool::AddMccForEurope()
{
    std::vector<MccAccessData> tmp = {
        {MCC_GE_A, MCC_ISO_GE, MCC_SHORT},
        {MCC_AM, MCC_ISO_AM, MCC_SHORT},
        {MCC_BG, MCC_ISO_BG, MCC_SHORT},
        {MCC_TR, MCC_ISO_TR, MCC_SHORT},
        {MCC_FO, MCC_ISO_FO, MCC_SHORT},
        {MCC_GE_B, MCC_ISO_GE, MCC_SHORT},
        {MCC_GL, MCC_ISO_GL, MCC_SHORT},
        {MCC_SM, MCC_ISO_SM, MCC_SHORT},
        {MCC_SI, MCC_ISO_SI, MCC_SHORT},
        {MCC_MK, MCC_ISO_MK, MCC_SHORT},
        {MCC_LI, MCC_ISO_LI, MCC_SHORT},
        {MCC_ME, MCC_ISO_ME, MCC_SHORT},
        {MCC_CA, MCC_ISO_CA, MCC_LONG},
        {MCC_PM, MCC_ISO_PM, MCC_SHORT},
        {MCC_US_A, MCC_ISO_US, MCC_LONG},
        {MCC_US_B, MCC_ISO_US, MCC_LONG},
        {MCC_US_C, MCC_ISO_US, MCC_LONG},
        {MCC_US_D, MCC_ISO_US, MCC_LONG},
        {MCC_US_E, MCC_ISO_US, MCC_LONG},
        {MCC_US_F, MCC_ISO_US, MCC_LONG},
        {MCC_US_G, MCC_ISO_US, MCC_LONG},
        {MCC_PR, MCC_ISO_PR, MCC_SHORT},
        {MCC_VI, MCC_ISO_VI, MCC_SHORT},
        {MCC_MX, MCC_ISO_MX, MCC_SHORT},
        {MCC_JM, MCC_ISO_JM, MCC_LONG},
        {MCC_GP, MCC_ISO_GP, MCC_SHORT},
        {MCC_BB, MCC_ISO_BB, MCC_LONG},
        {MCC_AG, MCC_ISO_AG, MCC_LONG},
        {MCC_KY, MCC_ISO_KY, MCC_LONG},
        {MCC_VG, MCC_ISO_VG, MCC_LONG},
        {MCC_BM, MCC_ISO_BM, MCC_SHORT},
        {MCC_GD, MCC_ISO_GD, MCC_SHORT},
        {MCC_MS, MCC_ISO_MS, MCC_SHORT},
        {MCC_KN, MCC_ISO_KN, MCC_SHORT},
        {MCC_LC, MCC_ISO_LC, MCC_SHORT},
        {MCC_VC, MCC_ISO_VC, MCC_SHORT},
        {MCC_AI_A, MCC_ISO_AI, MCC_SHORT},
        {MCC_AW, MCC_ISO_AW, MCC_SHORT},
        {MCC_BS, MCC_ISO_BS, MCC_SHORT},
        {MCC_AI_B, MCC_ISO_AI, MCC_LONG},
        {MCC_DM, MCC_ISO_DM, MCC_SHORT}
    };
    mccAccessDataTable_.insert(mccAccessDataTable_.end(), tmp.begin(), tmp.end());
}

void MccPool::AddMccForAfrica()
{
    std::vector<MccAccessData> tmp = {
        {MCC_CU, MCC_ISO_CU, MCC_SHORT},
        {MCC_DO, MCC_ISO_DO, MCC_SHORT},
        {MCC_HT, MCC_ISO_HT, MCC_SHORT},
        {MCC_TT, MCC_ISO_TT, MCC_SHORT},
        {MCC_TC, MCC_ISO_TC, MCC_SHORT},
        {MCC_AZ, MCC_ISO_AZ, MCC_SHORT},
        {MCC_KZ, MCC_ISO_KZ, MCC_SHORT},
        {MCC_BT, MCC_ISO_BT, MCC_SHORT},
        {MCC_IN_A, MCC_ISO_IN, MCC_SHORT},
        {MCC_IN_B, MCC_ISO_IN, MCC_SHORT},
        {MCC_IN_C, MCC_ISO_IN, MCC_SHORT},
        {MCC_PK, MCC_ISO_PK, MCC_SHORT},
        {MCC_AF, MCC_ISO_AF, MCC_SHORT},
        {MCC_LK, MCC_ISO_LK, MCC_SHORT},
        {MCC_MM, MCC_ISO_MM, MCC_SHORT},
        {MCC_LB, MCC_ISO_LB, MCC_SHORT},
        {MCC_JO, MCC_ISO_JO, MCC_SHORT},
        {MCC_SY, MCC_ISO_SY, MCC_SHORT},
        {MCC_IQ, MCC_ISO_IQ, MCC_SHORT},
        {MCC_KW, MCC_ISO_KW, MCC_SHORT},
        {MCC_SA, MCC_ISO_SA, MCC_SHORT},
        {MCC_YE, MCC_ISO_YE, MCC_SHORT},
        {MCC_OM, MCC_ISO_OM, MCC_SHORT},
        {MCC_PS, MCC_ISO_PS, MCC_SHORT},
        {MCC_AE_A, MCC_ISO_AE, MCC_SHORT},
        {MCC_IL, MCC_ISO_IL, MCC_SHORT},
        {MCC_BH, MCC_ISO_BH, MCC_SHORT},
        {MCC_QA, MCC_ISO_QA, MCC_SHORT},
        {MCC_MN, MCC_ISO_MN, MCC_SHORT},
        {MCC_NP, MCC_ISO_NP, MCC_SHORT},
        {MCC_AE_B, MCC_ISO_AE, MCC_SHORT},
        {MCC_AE_C, MCC_ISO_AE, MCC_SHORT},
        {MCC_IR, MCC_ISO_IR, MCC_SHORT},
        {MCC_UZ, MCC_ISO_UZ, MCC_SHORT},
        {MCC_TJ, MCC_ISO_TJ, MCC_SHORT},
        {MCC_KG, MCC_ISO_KG, MCC_SHORT},
        {MCC_TM, MCC_ISO_TM, MCC_SHORT},
        {MCC_JP_A, MCC_ISO_JP, MCC_SHORT},
        {MCC_JP_B, MCC_ISO_JP, MCC_SHORT},
        {MCC_KR, MCC_ISO_KR, MCC_SHORT},
        {MCC_VN, MCC_ISO_VN, MCC_SHORT}
    };
    mccAccessDataTable_.insert(mccAccessDataTable_.end(), tmp.begin(), tmp.end());
}

void MccPool::AddMccForNorthAmerica()
{
    std::vector<MccAccessData> tmp = {
        {MCC_HK, MCC_ISO_HK, MCC_SHORT},
        {MCC_MO, MCC_ISO_MO, MCC_SHORT},
        {MCC_KH, MCC_ISO_KH, MCC_SHORT},
        {MCC_LA, MCC_ISO_LA, MCC_SHORT},
        {MCC_CN_A, MCC_ISO_CN, MCC_SHORT},
        {MCC_CN_B, MCC_ISO_CN, MCC_SHORT},
        {MCC_TW, MCC_ISO_TW, MCC_SHORT},
        {MCC_KP, MCC_ISO_KP, MCC_SHORT},
        {MCC_BD, MCC_ISO_BD, MCC_SHORT},
        {MCC_MV, MCC_ISO_MV, MCC_SHORT},
        {MCC_MY, MCC_ISO_MY, MCC_SHORT},
        {MCC_AU, MCC_ISO_AU, MCC_SHORT},
        {MCC_ID, MCC_ISO_ID, MCC_SHORT},
        {MCC_TL, MCC_ISO_TL, MCC_SHORT},
        {MCC_PH, MCC_ISO_PH, MCC_SHORT},
        {MCC_TH, MCC_ISO_TH, MCC_SHORT},
        {MCC_SG, MCC_ISO_SG, MCC_SHORT},
        {MCC_BN, MCC_ISO_BN, MCC_SHORT},
        {MCC_NZ, MCC_ISO_NZ, MCC_SHORT},
        {MCC_MP, MCC_ISO_MP, MCC_SHORT},
        {MCC_GU, MCC_ISO_GU, MCC_SHORT},
        {MCC_NR, MCC_ISO_NR, MCC_SHORT},
        {MCC_PG, MCC_ISO_PG, MCC_SHORT},
        {MCC_TO, MCC_ISO_TO, MCC_SHORT},
        {MCC_SB, MCC_ISO_SB, MCC_SHORT},
        {MCC_VU, MCC_ISO_VU, MCC_SHORT},
        {MCC_FJ, MCC_ISO_FJ, MCC_SHORT},
        {MCC_WF, MCC_ISO_WF, MCC_SHORT},
        {MCC_AS, MCC_ISO_AS, MCC_SHORT},
        {MCC_KI, MCC_ISO_KI, MCC_SHORT},
        {MCC_NC, MCC_ISO_NC, MCC_SHORT},
        {MCC_PF, MCC_ISO_PF, MCC_SHORT},
        {MCC_CK, MCC_ISO_CK, MCC_SHORT},
        {MCC_WS, MCC_ISO_WS, MCC_SHORT},
        {MCC_FM, MCC_ISO_FM, MCC_SHORT},
        {MCC_MH, MCC_ISO_MH, MCC_SHORT},
        {MCC_PW, MCC_ISO_PW, MCC_SHORT},
        {MCC_TV, MCC_ISO_TV, MCC_SHORT},
        {MCC_NU, MCC_ISO_NU, MCC_SHORT},
        {MCC_EG, MCC_ISO_EG, MCC_SHORT},
        {MCC_DZ, MCC_ISO_DZ, MCC_SHORT}
    };
    mccAccessDataTable_.insert(mccAccessDataTable_.end(), tmp.begin(), tmp.end());
}

void MccPool::AddMccForSouthAmerica()
{
    std::vector<MccAccessData> tmp = {
        {MCC_MA, MCC_ISO_MA, MCC_SHORT},
        {MCC_TN, MCC_ISO_TN, MCC_SHORT},
        {MCC_LY, MCC_ISO_LY, MCC_SHORT},
        {MCC_GM, MCC_ISO_GM, MCC_SHORT},
        {MCC_SN, MCC_ISO_SN, MCC_SHORT},
        {MCC_MR, MCC_ISO_MR, MCC_SHORT},
        {MCC_ML, MCC_ISO_ML, MCC_SHORT},
        {MCC_GN, MCC_ISO_GN, MCC_SHORT},
        {MCC_CI, MCC_ISO_CI, MCC_SHORT},
        {MCC_BF, MCC_ISO_BF, MCC_SHORT},
        {MCC_NE, MCC_ISO_NE, MCC_SHORT},
        {MCC_TG, MCC_ISO_TG, MCC_SHORT},
        {MCC_BJ, MCC_ISO_BJ, MCC_SHORT},
        {MCC_MU, MCC_ISO_MU, MCC_SHORT},
        {MCC_LR, MCC_ISO_LR, MCC_SHORT},
        {MCC_SL, MCC_ISO_SL, MCC_SHORT},
        {MCC_GH, MCC_ISO_GH, MCC_SHORT},
        {MCC_NG, MCC_ISO_NG, MCC_SHORT},
        {MCC_TD, MCC_ISO_TD, MCC_SHORT},
        {MCC_CF, MCC_ISO_CF, MCC_SHORT},
        {MCC_CM, MCC_ISO_CM, MCC_SHORT},
        {MCC_CV, MCC_ISO_CV, MCC_SHORT},
        {MCC_ST, MCC_ISO_ST, MCC_SHORT},
        {MCC_GQ, MCC_ISO_GQ, MCC_SHORT},
        {MCC_GA, MCC_ISO_GA, MCC_SHORT},
        {MCC_CG, MCC_ISO_CG, MCC_SHORT},
        {MCC_CD, MCC_ISO_CD, MCC_SHORT},
        {MCC_AO, MCC_ISO_AO, MCC_SHORT},
        {MCC_GW, MCC_ISO_GW, MCC_SHORT},
        {MCC_SC, MCC_ISO_SC, MCC_SHORT},
        {MCC_SD, MCC_ISO_SD, MCC_SHORT},
        {MCC_RW, MCC_ISO_RW, MCC_SHORT},
        {MCC_ET, MCC_ISO_ET, MCC_SHORT},
        {MCC_SO, MCC_ISO_SO, MCC_SHORT},
        {MCC_DJ, MCC_ISO_DJ, MCC_SHORT},
        {MCC_KE, MCC_ISO_KE, MCC_SHORT},
        {MCC_TZ, MCC_ISO_TZ, MCC_SHORT},
        {MCC_UG, MCC_ISO_UG, MCC_SHORT},
        {MCC_BI, MCC_ISO_BI, MCC_SHORT},
        {MCC_MZ, MCC_ISO_MZ, MCC_SHORT}
    };
    mccAccessDataTable_.insert(mccAccessDataTable_.end(), tmp.begin(), tmp.end());
}

void MccPool::AddMccForAustralia()
{
    std::vector<MccAccessData> tmp = {
        {MCC_ZM, MCC_ISO_ZM, MCC_SHORT},
        {MCC_MG, MCC_ISO_MG, MCC_SHORT},
        {MCC_RE, MCC_ISO_RE, MCC_SHORT},
        {MCC_ZW, MCC_ISO_ZW, MCC_SHORT},
        {MCC_NA, MCC_ISO_NA, MCC_SHORT},
        {MCC_MW, MCC_ISO_MW, MCC_SHORT},
        {MCC_LS, MCC_ISO_LS, MCC_SHORT},
        {MCC_BW, MCC_ISO_BW, MCC_SHORT},
        {MCC_SZ, MCC_ISO_SZ, MCC_SHORT},
        {MCC_KM, MCC_ISO_KM, MCC_SHORT},
        {MCC_ZA, MCC_ISO_ZA, MCC_SHORT},
        {MCC_ER, MCC_ISO_ER, MCC_SHORT},
        {MCC_SH, MCC_ISO_SH, MCC_SHORT},
        {MCC_SS, MCC_ISO_SS, MCC_SHORT},
        {MCC_BZ, MCC_ISO_BZ, MCC_SHORT},
        {MCC_GT, MCC_ISO_GT, MCC_SHORT},
        {MCC_SV, MCC_ISO_SV, MCC_SHORT},
        {MCC_HN, MCC_ISO_HN, MCC_LONG},
        {MCC_NI, MCC_ISO_NI, MCC_SHORT},
        {MCC_CR, MCC_ISO_CR, MCC_SHORT},
        {MCC_PA, MCC_ISO_PA, MCC_SHORT},
        {MCC_PE, MCC_ISO_PE, MCC_SHORT},
        {MCC_AR, MCC_ISO_AR, MCC_SHORT},
        {MCC_BR, MCC_ISO_BR, MCC_SHORT},
        {MCC_CL, MCC_ISO_CL, MCC_SHORT},
        {MCC_CO, MCC_ISO_CO, MCC_LONG},
        {MCC_VE, MCC_ISO_VE, MCC_SHORT},
        {MCC_BO, MCC_ISO_BO, MCC_SHORT},
        {MCC_GY, MCC_ISO_GY, MCC_SHORT},
        {MCC_EC, MCC_ISO_EC, MCC_SHORT},
        {MCC_GF, MCC_ISO_GF, MCC_SHORT},
        {MCC_PY, MCC_ISO_PY, MCC_SHORT},
        {MCC_SR, MCC_ISO_SR, MCC_SHORT},
        {MCC_UY, MCC_ISO_UY, MCC_SHORT},
        {MCC_FK, MCC_ISO_FK, MCC_SHORT}
    };
    mccAccessDataTable_.insert(mccAccessDataTable_.end(), tmp.begin(), tmp.end());
}

bool MccPool::MccCompare(const MccAccessData &mccAccessDataA, const MccAccessData &mccAccessDataB)
{
    return (mccAccessDataA.mcc_ < mccAccessDataB.mcc_);
}

bool MccPool::LengthIsTwoMnc(const std::string &mccMncCode)
{
    std::lock_guard<std::mutex> lock(mccMutex_);
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
    std::lock_guard<std::mutex> lock(mccMutex_);
    InitSpecialMccMncTables();
    std::vector<std::string>::iterator obj = std::find(specialMccMnc_.begin(), specialMccMnc_.end(), mccMncCode);
    return (obj == specialMccMnc_.end()) ? false : true;
}

void MccPool::InitSpecialMccMncTables()
{
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

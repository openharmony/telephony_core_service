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

#ifndef OHOS_MCC_POOL_H
#define OHOS_MCC_POOL_H

#include <algorithm>
#include <cstdio>
#include <functional>
#include <iostream>
#include <vector>

enum MccCountry {
    MCC_GR = 202,
    MCC_NL = 204,
    MCC_BE = 206,
    MCC_FR = 208,
    MCC_MC = 212,
    MCC_AD = 213,
    MCC_ES = 214,
    MCC_HU = 216,
    MCC_BA = 218,
    MCC_HR = 219,
    MCC_RS = 220,
    MCC_IT = 222,
    MCC_VA = 225,
    MCC_RO = 226,
    MCC_CH = 228,
    MCC_CZ = 230,
    MCC_SK = 231,
    MCC_AT = 232,
    MCC_GB_A = 234,
    MCC_GB_B = 235,
    MCC_DK = 238,
    MCC_SE = 240,
    MCC_NO = 242,
    MCC_FI = 244,
    MCC_LT = 246,
    MCC_LV = 247,
    MCC_EE = 248,
    MCC_RU = 250,
    MCC_UA = 255,
    MCC_BY = 257,
    MCC_MD = 259,
    MCC_PL = 260,
    MCC_DE = 262,
    MCC_GI = 266,
    MCC_PT = 268,
    MCC_LU = 270,
    MCC_IE = 272,
    MCC_IS = 274,
    MCC_AL = 276,
    MCC_MT = 278,
    MCC_CY = 280,
    MCC_GE_A = 282,
    MCC_AM = 283,
    MCC_BG = 284,
    MCC_TR = 286,
    MCC_FO = 288,
    MCC_GE_B = 289,
    MCC_GL = 290,
    MCC_SM = 292,
    MCC_SI = 293,
    MCC_MK = 294,
    MCC_LI = 295,
    MCC_ME = 297,
    MCC_CA = 302,
    MCC_PM = 308,
    MCC_US_A = 310,
    MCC_US_B = 311,
    MCC_US_C = 312,
    MCC_US_D = 313,
    MCC_US_E = 314,
    MCC_US_F = 315,
    MCC_US_G = 316,
    MCC_PR = 330,
    MCC_VI = 332,
    MCC_MX = 334,
    MCC_JM = 338,
    MCC_GP = 340,
    MCC_BB = 342,
    MCC_AG = 344,
    MCC_KY = 346,
    MCC_VG = 348,
    MCC_BM = 350,
    MCC_GD = 352,
    MCC_MS = 354,
    MCC_KN = 356,
    MCC_LC = 358,
    MCC_VC = 360,
    MCC_AI_A = 362,
    MCC_AW = 363,
    MCC_BS = 364,
    MCC_AI_B = 365,
    MCC_DM = 366,
    MCC_CU = 368,
    MCC_DO = 370,
    MCC_HT = 372,
    MCC_TT = 374,
    MCC_TC = 376,
    MCC_AZ = 400,
    MCC_KZ = 401,
    MCC_BT = 402,
    MCC_IN_A = 404,
    MCC_IN_B = 405,
    MCC_IN_C = 406,
    MCC_PK = 410,
    MCC_AF = 412,
    MCC_LK = 413,
    MCC_MM = 414,
    MCC_LB = 415,
    MCC_JO = 416,
    MCC_SY = 417,
    MCC_IQ = 418,
    MCC_KW = 419,
    MCC_SA = 420,
    MCC_YE = 421,
    MCC_OM = 422,
    MCC_PS = 423,
    MCC_AE_A = 424,
    MCC_IL = 425,
    MCC_BH = 426,
    MCC_QA = 427,
    MCC_MN = 428,
    MCC_NP = 429,
    MCC_AE_B = 430,
    MCC_AE_C = 431,
    MCC_IR = 432,
    MCC_UZ = 434,
    MCC_TJ = 436,
    MCC_KG = 437,
    MCC_TM = 438,
    MCC_JP_A = 440,
    MCC_JP_B = 441,
    MCC_KR = 450,
    MCC_VN = 452,
    MCC_HK = 454,
    MCC_MO = 455,
    MCC_KH = 456,
    MCC_LA = 457,
    MCC_CN_A = 460,
    MCC_CN_B = 461,
    MCC_TW = 466,
    MCC_KP = 467,
    MCC_BD = 470,
    MCC_MV = 472,
    MCC_MY = 502,
    MCC_AU = 505,
    MCC_ID = 510,
    MCC_TL = 514,
    MCC_PH = 515,
    MCC_TH = 520,
    MCC_SG = 525,
    MCC_BN = 528,
    MCC_NZ = 530,
    MCC_MP = 534,
    MCC_GU = 535,
    MCC_NR = 536,
    MCC_PG = 537,
    MCC_TO = 539,
    MCC_SB = 540,
    MCC_VU = 541,
    MCC_FJ = 542,
    MCC_WF = 543,
    MCC_AS = 544,
    MCC_KI = 545,
    MCC_NC = 546,
    MCC_PF = 547,
    MCC_CK = 548,
    MCC_WS = 549,
    MCC_FM = 550,
    MCC_MH = 551,
    MCC_PW = 552,
    MCC_TV = 553,
    MCC_NU = 555,
    MCC_EG = 602,
    MCC_DZ = 603,
    MCC_MA = 604,
    MCC_TN = 605,
    MCC_LY = 606,
    MCC_GM = 607,
    MCC_SN = 608,
    MCC_MR = 609,
    MCC_ML = 610,
    MCC_GN = 611,
    MCC_CI = 612,
    MCC_BF = 613,
    MCC_NE = 614,
    MCC_TG = 615,
    MCC_BJ = 616,
    MCC_MU = 617,
    MCC_LR = 618,
    MCC_SL = 619,
    MCC_GH = 620,
    MCC_NG = 621,
    MCC_TD = 622,
    MCC_CF = 623,
    MCC_CM = 624,
    MCC_CV = 625,
    MCC_ST = 626,
    MCC_GQ = 627,
    MCC_GA = 628,
    MCC_CG = 629,
    MCC_CD = 630,
    MCC_AO = 631,
    MCC_GW = 632,
    MCC_SC = 633,
    MCC_SD = 634,
    MCC_RW = 635,
    MCC_ET = 636,
    MCC_SO = 637,
    MCC_DJ = 638,
    MCC_KE = 639,
    MCC_TZ = 640,
    MCC_UG = 641,
    MCC_BI = 642,
    MCC_MZ = 643,
    MCC_ZM = 645,
    MCC_MG = 646,
    MCC_RE = 647,
    MCC_ZW = 648,
    MCC_NA = 649,
    MCC_MW = 650,
    MCC_LS = 651,
    MCC_BW = 652,
    MCC_SZ = 653,
    MCC_KM = 654,
    MCC_ZA = 655,
    MCC_ER = 657,
    MCC_SH = 658,
    MCC_SS = 659,
    MCC_BZ = 702,
    MCC_GT = 704,
    MCC_SV = 706,
    MCC_HN = 708,
    MCC_NI = 710,
    MCC_CR = 712,
    MCC_PA = 714,
    MCC_PE = 716,
    MCC_AR = 722,
    MCC_BR = 724,
    MCC_CL = 730,
    MCC_CO = 732,
    MCC_VE = 734,
    MCC_BO = 736,
    MCC_GY = 738,
    MCC_EC = 740,
    MCC_GF = 742,
    MCC_PY = 744,
    MCC_SR = 746,
    MCC_UY = 748,
    MCC_FK = 750
};

enum MccType { MCC_SHORT = 2, MCC_LONG = 3 };

namespace OHOS {
namespace Telephony {
class MccAccess {
public:
    int mcc_ = 0;
    std::string iso_ = "";
    int mncShortestLength_ = 0;
    MccAccess(int mcc, std::string iso, int shortestMnc)
    {
        mcc_ = mcc;
        iso_ = iso;
        mncShortestLength_ = shortestMnc;
    }
};

class MccPool {
public:
    MccPool();
    ~MccPool();
    //TODO
    static std::string MccCountryCode(int mcc);
    static int ShortestMncLengthFromMcc(int mcc);
    static bool LengthIsThreeMnc(const std::string &mccMncCode);
    static std::vector<std::shared_ptr<MccAccess>> mccAccessTable_;
    static std::vector<std::string> specialMccMnc_

private:
    static std::shared_ptr<MccAccess> AccessToMcc(int mcc);
    static void InitMccTables();
    static bool MccCompare(const std::shared_ptr<MccAccess> &mccAccessA, const std::shared_ptr<MccAccess> &mccAccessB);
    static void AddMccForAsia();
    static void AddMccForEurope();
    static void AddMccForAfrica();
    static void AddMccForNorthAmerica();
    static void AddMccForSouthAmerica();
    static void AddMccForAustralia();

    static void InitSpecialMccMncTables();
    static void AddMccMncForCa();
    static void AddMccMncForInAirtel();
    static void AddMccMncForInHutch();
    static void AddMccMncForMy();
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MCC_TABLE_H
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

// define country mcc code
#define MCC_GR 202
#define MCC_NL 204
#define MCC_BE 206
#define MCC_FR 208
#define MCC_MC 212
#define MCC_AD 213
#define MCC_ES 214
#define MCC_HU 216
#define MCC_BA 218
#define MCC_HR 219
#define MCC_RS 220
#define MCC_IT 222
#define MCC_VA 225
#define MCC_RO 226
#define MCC_CH 228
#define MCC_CZ 230
#define MCC_SK 231
#define MCC_AT 232
#define MCC_GB_A 234
#define MCC_GB_B 235
#define MCC_DK 238
#define MCC_SE 240
#define MCC_NO 242
#define MCC_FI 244
#define MCC_LT 246
#define MCC_LV 247
#define MCC_EE 248
#define MCC_RU 250
#define MCC_UA 255
#define MCC_BY 257
#define MCC_MD 259
#define MCC_PL 260
#define MCC_DE 262
#define MCC_GI 266
#define MCC_PT 268
#define MCC_LU 270
#define MCC_IE 272
#define MCC_IS 274
#define MCC_AL 276
#define MCC_MT 278
#define MCC_CY 280
#define MCC_GE_A 282
#define MCC_AM 283
#define MCC_BG 284
#define MCC_TR 286
#define MCC_FO 288
#define MCC_GE_B 289
#define MCC_GL 290
#define MCC_SM 292
#define MCC_SI 293
#define MCC_MK 294
#define MCC_LI 295
#define MCC_ME 297
#define MCC_CA 302
#define MCC_PM 308
#define MCC_US_A 310
#define MCC_US_B 311
#define MCC_US_C 312
#define MCC_US_D 313
#define MCC_US_E 314
#define MCC_US_F 315
#define MCC_US_G 316
#define MCC_PR 330
#define MCC_VI 332
#define MCC_MX 334
#define MCC_JM 338
#define MCC_GP 340
#define MCC_BB 342
#define MCC_AG 344
#define MCC_KY 346
#define MCC_VG 348
#define MCC_BM 350
#define MCC_GD 352
#define MCC_MS 354
#define MCC_KN 356
#define MCC_LC 358
#define MCC_VC 360
#define MCC_AI_A 362
#define MCC_AW 363
#define MCC_BS 364
#define MCC_AI_B 365
#define MCC_DM 366
#define MCC_CU 368
#define MCC_DO 370
#define MCC_HT 372
#define MCC_TT 374
#define MCC_TC 376
#define MCC_AZ 400
#define MCC_KZ 401
#define MCC_BT 402
#define MCC_IN_A 404
#define MCC_IN_B 405
#define MCC_IN_C 406
#define MCC_PK 410
#define MCC_AF 412
#define MCC_LK 413
#define MCC_MM 414
#define MCC_LB 415
#define MCC_JO 416
#define MCC_SY 417
#define MCC_IQ 418
#define MCC_KW 419
#define MCC_SA 420
#define MCC_YE 421
#define MCC_OM 422
#define MCC_PS 423
#define MCC_AE_A 424
#define MCC_IL 425
#define MCC_BH 426
#define MCC_QA 427
#define MCC_MN 428
#define MCC_NP 429
#define MCC_AE_B 430
#define MCC_AE_C 431
#define MCC_IR 432
#define MCC_UZ 434
#define MCC_TJ 436
#define MCC_KG 437
#define MCC_TM 438
#define MCC_JP_A 440
#define MCC_JP_B 441
#define MCC_KR 450
#define MCC_VN 452
#define MCC_HK 454
#define MCC_MO 455
#define MCC_KH 456
#define MCC_LA 457
#define MCC_CN_A 460
#define MCC_CN_B 461
#define MCC_TW 466
#define MCC_KP 467
#define MCC_BD 470
#define MCC_MV 472
#define MCC_MY 502
#define MCC_AU 505
#define MCC_ID 510
#define MCC_TL 514
#define MCC_PH 515
#define MCC_TH 520
#define MCC_SG 525
#define MCC_BN 528
#define MCC_NZ 530
#define MCC_MP 534
#define MCC_GU 535
#define MCC_NR 536
#define MCC_PG 537
#define MCC_TO 539
#define MCC_SB 540
#define MCC_VU 541
#define MCC_FJ 542
#define MCC_WF 543
#define MCC_AS 544
#define MCC_KI 545
#define MCC_NC 546
#define MCC_PF 547
#define MCC_CK 548
#define MCC_WS 549
#define MCC_FM 550
#define MCC_MH 551
#define MCC_PW 552
#define MCC_TV 553
#define MCC_NU 555
#define MCC_EG 602
#define MCC_DZ 603
#define MCC_MA 604
#define MCC_TN 605
#define MCC_LY 606
#define MCC_GM 607
#define MCC_SN 608
#define MCC_MR 609
#define MCC_ML 610
#define MCC_GN 611
#define MCC_CI 612
#define MCC_BF 613
#define MCC_NE 614
#define MCC_TG 615
#define MCC_BJ 616
#define MCC_MU 617
#define MCC_LR 618
#define MCC_SL 619
#define MCC_GH 620
#define MCC_NG 621
#define MCC_TD 622
#define MCC_CF 623
#define MCC_CM 624
#define MCC_CV 625
#define MCC_ST 626
#define MCC_GQ 627
#define MCC_GA 628
#define MCC_CG 629
#define MCC_CD 630
#define MCC_AO 631
#define MCC_GW 632
#define MCC_SC 633
#define MCC_SD 634
#define MCC_RW 635
#define MCC_ET 636
#define MCC_SO 637
#define MCC_DJ 638
#define MCC_KE 639
#define MCC_TZ 640
#define MCC_UG 641
#define MCC_BI 642
#define MCC_MZ 643
#define MCC_ZM 645
#define MCC_MG 646
#define MCC_RE 647
#define MCC_ZW 648
#define MCC_NA 649
#define MCC_MW 650
#define MCC_LS 651
#define MCC_BW 652
#define MCC_SZ 653
#define MCC_KM 654
#define MCC_ZA 655
#define MCC_ER 657
#define MCC_SH 658
#define MCC_SS 659
#define MCC_BZ 702
#define MCC_GT 704
#define MCC_SV 706
#define MCC_HN 708
#define MCC_NI 710
#define MCC_CR 712
#define MCC_PA 714
#define MCC_PE 716
#define MCC_AR 722
#define MCC_BR 724
#define MCC_CL 730
#define MCC_CO 732
#define MCC_VE 734
#define MCC_BO 736
#define MCC_GY 738
#define MCC_EC 740
#define MCC_GF 742
#define MCC_PY 744
#define MCC_SR 746
#define MCC_UY 748
#define MCC_FK 750

#define MCC_SHORT 2
#define MCC_LONG 3

namespace OHOS {
namespace SIM {
class MccAccess {
public:
    int mcc_ = 0;
    std::string iso_ = "";
    int mncShortestLength_ = 0;
    MccAccess(int mnc, std::string iso, int ShortestMnc)
    {
        mcc_ = mnc;
        iso_ = iso;
        mncShortestLength_ = ShortestMnc;
    }

    bool operator==(MccAccess m)
    {
        return (mcc_ == m.mcc_);
    }
};

static std::vector<MccAccess> mccAccessTable_;
static std::vector<std::string> specialMccMnc_;
class MccPool {
public:
    MccPool();
    ~MccPool();
    static std::string MccCountryCode(int mcc);
    static int ShortestMncLengthFromMcc(int mcc);
    static bool LengthIsThreeMnc(std::string &mccmncCode);

private:
    static MccAccess AccessToMcc(int mcc);
    static void InitMccTables();
    static bool MccCompare(MccAccess &a, MccAccess &b);
    static void AddMccForAisa();
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
} // namespace SIM
} // namespace OHOS
#endif // OHOS_MCC_TABLE_H
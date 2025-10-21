/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include <gtest/gtest.h>

#include "core_manager_inner.h"
#include "mock_sim_manager.h"
#include "string_ex.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;
class CoreManagerInnerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    CoreManagerInner mInner;
    std::shared_ptr<MockSimManager> mockeSimManager = std::make_shared<MockSimManager>();
};

void CoreManagerInnerTest::SetUpTestCase() {}

void CoreManagerInnerTest::TearDownTestCase() {}

void CoreManagerInnerTest::SetUp() {}

void CoreManagerInnerTest::TearDown() {}

HWTEST_F(CoreManagerInnerTest, ObtainSpnCondition_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    bool roaming = true;
    std::string operatorNum;
    int32_t ret = mInner.ObtainSpnCondition(slotId, roaming, operatorNum);
    EXPECT_EQ(ret, 0);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, ObtainSpnCondition(_, _, _)).WillOnce(
        Return(SpnShowType::SPN_CONDITION_DISPLAY_PLMN));
    ret = mInner.ObtainSpnCondition(slotId, roaming, operatorNum);
    EXPECT_EQ(ret, SpnShowType::SPN_CONDITION_DISPLAY_PLMN);
}

HWTEST_F(CoreManagerInnerTest, GetSimSpn_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string spn;
    int32_t ret = mInner.GetSimSpn(slotId, spn);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimSpn(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetSimSpn(slotId, spn);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetSimEons_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::string plmn;
    int32_t lac = 1;;
    bool longNameRequired = true;
    std::u16string ret = mInner.GetSimEons(slotId, plmn, lac, longNameRequired);
    EXPECT_EQ(ret, u"");

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimEons(_, _, _, _)).WillOnce(
        Return(u""));
    ret = mInner.GetSimEons(slotId, plmn, lac, longNameRequired);
    EXPECT_EQ(ret, u"");
}

HWTEST_F(CoreManagerInnerTest, SetVoiceMailInfo_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string mailName;
    std::u16string mailNumber;
    int32_t ret = mInner.SetVoiceMailInfo(slotId, mailName, mailNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetVoiceMailInfo(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetVoiceMailInfo(slotId, mailName, mailNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, QueryIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int type = 1;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    int32_t ret = mInner.QueryIccDiallingNumbers(slotId, type, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, QueryIccDiallingNumbers(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.QueryIccDiallingNumbers(slotId, type, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, AddIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int type = 1;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber;
    int32_t ret = mInner.AddIccDiallingNumbers(slotId, type, diallingNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, AddIccDiallingNumbers(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.AddIccDiallingNumbers(slotId, type, diallingNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, DelIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int type = 1;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber;
    int32_t ret = mInner.DelIccDiallingNumbers(slotId, type, diallingNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, DelIccDiallingNumbers(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.DelIccDiallingNumbers(slotId, type, diallingNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, UpdateIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int type = 1;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber;
    int32_t ret = mInner.UpdateIccDiallingNumbers(slotId, type, diallingNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, UpdateIccDiallingNumbers(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.UpdateIccDiallingNumbers(slotId, type, diallingNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, AddSmsToIcc_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int status = 1;
    std::string pdu;
    std::string smsc;
    int32_t ret = mInner.AddSmsToIcc(slotId, status, pdu, smsc);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, AddSmsToIcc(_, _, _, _)).WillOnce(
        Return(TELEPHONY_ERR_SLOTID_INVALID));
    ret = mInner.AddSmsToIcc(slotId, status, pdu, smsc);
    EXPECT_EQ(ret, TELEPHONY_ERR_SLOTID_INVALID);
}

HWTEST_F(CoreManagerInnerTest, UpdateSmsIcc_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int index = 1;
    int status = 1;
    std::string pduData;
    std::string smsc;
    int32_t ret = mInner.UpdateSmsIcc(slotId, index, status, pduData, smsc);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, UpdateSmsIcc(_, _, _, _, _)).WillOnce(
        Return(TELEPHONY_ERR_SLOTID_INVALID));
    ret = mInner.UpdateSmsIcc(slotId, index, status, pduData, smsc);
    EXPECT_EQ(ret, TELEPHONY_ERR_SLOTID_INVALID);
}

HWTEST_F(CoreManagerInnerTest, ObtainAllSmsOfIcc_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    std::vector<std::string> ret = mInner.ObtainAllSmsOfIcc(slotId);
    EXPECT_TRUE(ret.empty());

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, ObtainAllSmsOfIcc(_)).WillOnce(
        Return(std::vector<std::string>()));
    ret = mInner.ObtainAllSmsOfIcc(slotId);
    EXPECT_TRUE(ret.empty());
}

HWTEST_F(CoreManagerInnerTest, DelSmsIcc_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    int index = 1;
    int32_t ret = mInner.DelSmsIcc(slotId, index);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, DelSmsIcc(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SLOTID_INVALID));
    ret = mInner.DelSmsIcc(slotId, index);
    EXPECT_EQ(ret, TELEPHONY_ERR_SLOTID_INVALID);
}

HWTEST_F(CoreManagerInnerTest, IsSimActive_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int slotId = 0;
    bool ret = mInner.IsSimActive(slotId);
    EXPECT_FALSE(ret);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, IsSimActive(_)).WillOnce(
        Return(true));
    ret = mInner.IsSimActive(slotId);
    EXPECT_TRUE(ret);
}

HWTEST_F(CoreManagerInnerTest, SetActiveSim_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t enable = 1;
    int32_t ret = mInner.SetActiveSim(slotId, enable);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetActiveSim(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetActiveSim(slotId, enable);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, ResetSimLoadAccount_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t ret = mInner.ResetSimLoadAccount(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, ResetSimLoadAccount(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.ResetSimLoadAccount(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetSimAccountInfo_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    IccAccountInfo info;
    int32_t ret = mInner.GetSimAccountInfo(slotId, info);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimAccountInfo(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.GetSimAccountInfo(slotId, info);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, SetDefaultVoiceSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t ret = mInner.SetDefaultVoiceSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetDefaultVoiceSlotId(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetDefaultVoiceSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetDefaultSmsSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t ret = mInner.SetDefaultSmsSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetDefaultSmsSlotId(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetDefaultSmsSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetDefaultCellularDataSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t ret = mInner.SetDefaultCellularDataSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetDefaultCellularDataSlotId(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetDefaultCellularDataSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetPrimarySlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    bool isUserSet = true;
    int32_t ret = mInner.SetPrimarySlotId(slotId, isUserSet);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetPrimarySlotId(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetPrimarySlotId(slotId, isUserSet);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetShowNumber_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string number;
    int32_t ret = mInner.SetShowNumber(slotId, number);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetShowNumber(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.SetShowNumber(slotId, number);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, SetShowName_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string name;
    int32_t ret = mInner.SetShowName(slotId, name);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetShowName(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.SetShowName(slotId, name);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultVoiceSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t ret = mInner.GetDefaultVoiceSlotId();
    EXPECT_EQ(ret, TELEPHONY_ERROR);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDefaultVoiceSlotId()).WillOnce(
        Return(DEFAULT_SIM_SLOT_ID));
    ret = mInner.GetDefaultVoiceSlotId();
    EXPECT_EQ(ret, DEFAULT_SIM_SLOT_ID);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultVoiceSimId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t simId = 0;
    int32_t ret = mInner.GetDefaultVoiceSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDefaultVoiceSimId(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetDefaultVoiceSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultSmsSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t ret = mInner.GetDefaultSmsSlotId();
    EXPECT_EQ(ret, TELEPHONY_ERROR);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDefaultSmsSlotId()).WillOnce(
        Return(DEFAULT_SIM_SLOT_ID));
    ret = mInner.GetDefaultSmsSlotId();
    EXPECT_EQ(ret, DEFAULT_SIM_SLOT_ID);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultSmsSimId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t simId = 0;
    int32_t ret = mInner.GetDefaultSmsSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDefaultSmsSimId(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetDefaultSmsSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultCellularDataSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t ret = mInner.GetDefaultCellularDataSlotId();
    EXPECT_EQ(ret, TELEPHONY_ERROR);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDefaultCellularDataSlotId()).WillOnce(
        Return(DEFAULT_SIM_SLOT_ID));
    ret = mInner.GetDefaultCellularDataSlotId();
    EXPECT_EQ(ret, DEFAULT_SIM_SLOT_ID);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultCellularDataSimId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t simId = 0;
    int32_t ret = mInner.GetDefaultCellularDataSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDefaultCellularDataSimId(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetDefaultCellularDataSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetDsdsMode_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t dsdsMode = 0;
    int32_t ret = mInner.GetDsdsMode(dsdsMode);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetDsdsMode(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetDsdsMode(dsdsMode);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetDsdsMode_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t dsdsMode = 0;
    int32_t ret = mInner.SetDsdsMode(dsdsMode);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetDsdsMode(_)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetDsdsMode(dsdsMode);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetShowNumber_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string showNumber;
    int32_t ret = mInner.GetShowNumber(slotId, showNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetShowNumber(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.GetShowNumber(slotId, showNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetShowName_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string showName;
    int32_t ret = mInner.GetShowName(slotId, showName);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetShowName(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.GetShowName(slotId, showName);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetActiveSimAccountInfoList_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    std::vector<IccAccountInfo> iccAccountInfoList;
    int32_t ret = mInner.GetActiveSimAccountInfoList(iccAccountInfoList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    ret = mInner.UpdateOperatorConfigs();
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetActiveSimAccountInfoList(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.GetActiveSimAccountInfoList(iccAccountInfoList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetLocaleFromDefaultSim_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string ret = mInner.GetLocaleFromDefaultSim(slotId);
    EXPECT_EQ(ret, u"");

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetLocaleFromDefaultSim(_)).WillOnce(
        Return(u""));
    ret = mInner.GetLocaleFromDefaultSim(slotId);
    EXPECT_EQ(ret, u"");
}

HWTEST_F(CoreManagerInnerTest, GetSlotId_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::int32_t ret = mInner.GetSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERROR);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSlotId(_)).WillOnce(
        Return(TELEPHONY_ERROR));
    ret = mInner.GetSlotId(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERROR);
}

HWTEST_F(CoreManagerInnerTest, GetSimGid1_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string gid1;
    int32_t ret = mInner.GetSimGid1(slotId, gid1);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimGid1(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetSimGid1(slotId, gid1);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetSimGid2_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string ret = mInner.GetSimGid2(slotId);
    EXPECT_EQ(ret, u"");

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimGid2(_)).WillOnce(
        Return(u""));
    ret = mInner.GetSimGid2(slotId);
    EXPECT_EQ(ret, u"");
}

HWTEST_F(CoreManagerInnerTest, GetOpKeyExt_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string opkeyExt;
    int32_t ret = mInner.GetOpKeyExt(slotId, opkeyExt);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetOpKeyExt(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetOpKeyExt(slotId, opkeyExt);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetOpKey_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    std::u16string opkey;
    int32_t ret = mInner.GetOpKey(opkey);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetOpKey(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetOpKey(opkey);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetOpKey_002, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string opkey;
    int32_t ret = mInner.GetOpKey(slotId, opkey);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetOpKey(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetOpKey(slotId, opkey);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetSimTelephoneNumber_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string telephoneNumber;
    int32_t ret = mInner.GetSimTelephoneNumber(slotId, telephoneNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimTelephoneNumber(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.GetSimTelephoneNumber(slotId, telephoneNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetSimTeleNumberIdentifier_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string telephoneNumber;
    std::u16string ret = mInner.GetSimTeleNumberIdentifier(slotId);
    EXPECT_EQ(ret, u"");

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimTeleNumberIdentifier(_)).WillOnce(
        Return(u""));
    ret = mInner.GetSimTeleNumberIdentifier(slotId);
    EXPECT_EQ(ret, u"");
}

HWTEST_F(CoreManagerInnerTest, GetVoiceMailIdentifier_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string voiceMailIdentifier;
    int32_t ret = mInner.GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetVoiceMailIdentifier(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetVoiceMailNumber_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string voiceMailNumber;
    int32_t ret = mInner.GetVoiceMailNumber(slotId, voiceMailNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetVoiceMailNumber(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetVoiceMailNumber(slotId, voiceMailNumber);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetVoiceMailCount_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t voiceMailCount;
    int32_t ret = mInner.GetVoiceMailCount(slotId, voiceMailCount);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetVoiceMailCount(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetVoiceMailCount(slotId, voiceMailCount);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetVoiceMailCount_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t voiceMailCount = 0;
    int32_t ret = mInner.SetVoiceMailCount(slotId, voiceMailCount);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetVoiceMailCount(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetVoiceMailCount(slotId, voiceMailCount);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetVoiceCallForwarding_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    bool enable = true;
    std::string number;
    int32_t ret = mInner.SetVoiceCallForwarding(slotId, enable, number);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetVoiceCallForwarding(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetVoiceCallForwarding(slotId, enable, number);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetSimIccStatus_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    IccSimStatus iccStatus;
    int32_t ret = mInner.GetSimIccStatus(slotId, iccStatus);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimIccStatus(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetSimIccStatus(slotId, iccStatus);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetCardType_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    CardType cardType;
    int32_t ret = mInner.GetCardType(slotId, cardType);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetCardType(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetCardType(slotId, cardType);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, UnlockPin_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::string pin;
    LockStatusResponse response;
    int32_t ret = mInner.UnlockPin(slotId, pin, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, UnlockPin(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.UnlockPin(slotId, pin, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, UnlockPuk_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::string newPin;
    std::string puk;
    LockStatusResponse response;
    int32_t ret = mInner.UnlockPuk(slotId, newPin, puk, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, UnlockPuk(_, _, _, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.UnlockPuk(slotId, newPin, puk, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, AlterPin_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::string newPin;
    std::string oldPin;
    LockStatusResponse response;
    int32_t ret = mInner.AlterPin(slotId, newPin, oldPin, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, AlterPin(_, _, _, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.AlterPin(slotId, newPin, oldPin, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, SendEnvelopeCmd_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::string cmd;
    int32_t ret = mInner.SendEnvelopeCmd(slotId, cmd);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SendEnvelopeCmd(_, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.SendEnvelopeCmd(slotId, cmd);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, SendTerminalResponseCmd_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::string cmd;
    int32_t ret = mInner.SendTerminalResponseCmd(slotId, cmd);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SendTerminalResponseCmd(_, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.SendTerminalResponseCmd(slotId, cmd);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, SendCallSetupRequestResult_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    bool accept = true;
    int32_t ret = mInner.SendCallSetupRequestResult(slotId, accept);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SendCallSetupRequestResult(_, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.SendCallSetupRequestResult(slotId, accept);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, UnlockSimLock_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    PersoLockInfo lockInfo;
    LockStatusResponse response;
    int32_t ret = mInner.UnlockSimLock(slotId, lockInfo, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, UnlockSimLock(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.UnlockSimLock(slotId, lockInfo, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, HasOperatorPrivileges_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    bool hasOperatorPrivileges = true;
    int32_t ret = mInner.HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, HasOperatorPrivileges(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetSimIst_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string ret = mInner.GetSimIst(slotId);
    EXPECT_TRUE(ret.empty());

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimIst(_)).WillOnce(
        Return(u""));
    ret = mInner.GetSimIst(slotId);
    EXPECT_TRUE(ret.empty());
}

HWTEST_F(CoreManagerInnerTest, SaveImsSwitch_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t imsSwitchValue = 1;
    int32_t ret = mInner.SaveImsSwitch(slotId, imsSwitchValue);
    EXPECT_EQ(ret, TELEPHONY_ERROR);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SaveImsSwitch(_, _)).WillOnce(
        Return(TELEPHONY_ERR_ARGUMENT_INVALID));
    ret = mInner.SaveImsSwitch(slotId, imsSwitchValue);
    EXPECT_EQ(ret, TELEPHONY_ERR_ARGUMENT_INVALID);
}

HWTEST_F(CoreManagerInnerTest, GetAllSimAccountInfoList_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    std::vector<IccAccountInfo> iccAccountInfoList;
    int32_t ret = mInner.GetAllSimAccountInfoList(iccAccountInfoList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetAllSimAccountInfoList(_, _)).WillOnce(
        Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    ret = mInner.GetAllSimAccountInfoList(iccAccountInfoList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreManagerInnerTest, GetSimLabel_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    SimLabel simLabel;
    int32_t ret = mInner.GetSimLabel(slotId, simLabel);
    EXPECT_EQ(ret, INVALID_VALUE);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, GetSimLabel(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetSimLabel(slotId, simLabel);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetSimLabelIndex_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    std::string iccId;
    int32_t labelIndex = 1;
    int32_t ret = mInner.SetSimLabelIndex(iccId, labelIndex);
    EXPECT_EQ(ret, INVALID_VALUE);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetSimLabelIndex(_, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetSimLabelIndex(iccId, labelIndex);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, InsertEsimData_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    std::string iccId;
    int32_t esimLabel = 1;
    std::string operatorName;
    int32_t ret = mInner.InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_EQ(ret, INVALID_VALUE);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, InsertEsimData(_, _, _)).WillOnce(
        Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, NotifySimSlotsMapping_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t ret = mInner.NotifySimSlotsMapping(slotId);
    EXPECT_EQ(ret, INVALID_VALUE);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, NotifySimSlotsMapping(_)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.NotifySimSlotsMapping(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(CoreManagerInnerTest, SetIccCardState_001, Function | MediumTest | Level1)
{
    mInner.simManager_ = nullptr;
    int32_t slotId = 0;
    int32_t ret = mInner.SetIccCardState(slotId, 0);
    EXPECT_EQ(ret, INVALID_VALUE);

    mInner.simManager_ = mockeSimManager;
    EXPECT_CALL(*mockeSimManager, SetIccCardState(_, _)).WillOnce(
        Return(TELEPHONY_ERR_NO_SIM_CARD));
    ret = mInner.SetIccCardState(slotId, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

} // Telephony
} // OHOS
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

#ifndef TELEPHONY_CONFIG_H
#define TELEPHONY_CONFIG_H

#include <string>

namespace OHOS {
namespace Telephony {
class TelephonyConfig {
public:
    enum ConfigType {
        MODEM_CAP_DUAL_PS_ATTACHED = 0,
        MODEM_CAP_BIP_SUPPORT = 1,
        MODEM_CAP_PLUS_TRANSFER_SUPPORT = 2,
        MODEM_CAP_FULL_PREFMODE = 3,
        MODEM_CAP_MANUAL_SET_NETWORK_SUPPORT = 4,
        MODEM_CAP_ONS_MATCH_PHN_SUPPORT = 5,
        MODEM_CAP_RPT_DEREG_ISTER_STATE_DELAY_SUPPORT = 6,
        MODEM_CAP_RETTACH_API_SUPPORT = 7,
        MODEM_CAP_RIL_RECOVERY_ENDCALL = 8,
        MODEM_CAP_GET_MODEM_CAPABILITY = 9,
        MODEM_CAP_DSDS_MANUAL_PS_ATTACH = 10,
        MODEM_CAP_DSDS_SPEECH_CODEC_ADJUST = 11,
        MODEM_CAP_NOUPDATE_LAC_AND_CID = 12,
        MODEM_CAP_NV_FUCTION_RPC = 13,
        MODEM_CAP_CDMA_USE_VIA_HISI = 14,
        MODEM_CAP_SUPPORT_DIFF_ID = 15,
        MODEM_CAP_SUPPORT_SWITCH_SOCKET = 16,
        MODEM_CAP_LONG_SMS_DELAY_RELEASE = 17,
        MODEM_CAP_GET_IMSI_GSM = 18,
        MODEM_CAP_GET_ICCID_AT = 19,
        MODEM_CAP_SUPPORT_DUAL_VOLTE = 21,
        MODEM_CAP_SUPPORT_IMEI_BIND_SLOT = 26,
        MODEM_CAP_DUAL_LTE_STACK = 27,
        MODEM_CAP_GET_MODEM_MTK_CAPABILITY = 28,
        MODEM_CAP_SUPPORT_NR = 29,
        MODEM_CAP_NR_SLICES = 30,
        MODEM_CAP_SUPPORT_DUAL_NR = 31,
        MODEM_CAP_DISABLE_PREFER_DATA_MODEM = 32,
        MODEM_CAP_MAX = 360,
    };

    bool IsCapabilitySupport(uint32_t capablity);
    int32_t ConvertCharToInt(uint32_t &retValue, const std::string &maxCap, uint32_t index);
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_CONFIG_H

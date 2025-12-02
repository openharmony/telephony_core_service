/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OPERATOR_CONFIG_MATCHSIM_INFO_H
#define OPERATOR_CONFIG_MATCHSIM_INFO_H

#include "securec.h"
namespace OHOS {
namespace Telephony {
struct MatchSimInfo {
    int32_t slotId = 0;
    int8_t simState = 0;
    uint8_t matchSimFileState = 0U;
    int8_t matchSimReason = 0;
    uint32_t matchSimStateTracker = 0U;
    uint32_t matchSimFailReason = 0U;
    int8_t matchSimState = 0;
    char opkey[32] = "";
    char opname[32] = "";
    char spn[32] = "";
    char gid1[32] = "";
    char gid2[32] = "";
    char mccMnc[32] = "";

    MatchSimInfo()
        : slotId(0), simState(0), matchSimFileState(0U), matchSimReason(0), matchSimStateTracker(0U),
          matchSimFailReason(0U), matchSimState(0)
    {
        ClearMatchSimFile();
    }

    void ClearMatchSimFile()
    {
        opkey[0] = '\0';
        opname[0] = '\0';
        spn[0] = '\0';
        gid1[0] = '\0';
        gid2[0] = '\0';
        mccMnc[0] = '\0';
    }

    const char* GetOpkey() const
    {
        return opkey;
    }

    const char* GetOpname() const
    {
        return opname;
    }

    const char* GetSpn() const
    {
        return spn;
    }

    const char* GetGid1() const
    {
        return gid1;
    }

    const char* GetGid2() const
    {
        return gid2;
    }

    const char* GetMccMnc() const
    {
        return mccMnc;
    }

    void SetString(char* dest, size_t destSize, const char* src)
    {
        if (dest == nullptr || destSize == 0) {
            return;
        }

        if (src == nullptr) {
            dest[0] = '\0';
            return;
        }

        int err = strncpy_s(dest, destSize, src, destSize - 1);
        if (err != 0) {
            dest[0] = '\0';
        }
    }

    void SetOpkey(const char *s)
    {
        SetString(opkey, sizeof(opkey), s);
    }

    void SetOpname(const char *s)
    {
        SetString(opname, sizeof(opname), s);
    }

    void SetSpn(const char *s)
    {
        SetString(spn, sizeof(spn), s);
    }

    void SetGid1(const char *s)
    {
        SetString(gid1, sizeof(gid1), s);
    }

    void SetGid2(const char *s)
    {
        SetString(gid2, sizeof(gid2), s);
    }

    void SetMccMnc(const char *s)
    {
        SetString(mccMnc, sizeof(mccMnc), s);
    }
};
}
}
#endif
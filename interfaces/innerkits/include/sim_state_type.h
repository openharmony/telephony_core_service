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

#ifndef OHOS_SIM_STATE_TYPE_H
#define OHOS_SIM_STATE_TYPE_H

#include <map>
#include <parcel.h>
#include <string>
#include <vector>

namespace OHOS {
namespace Telephony {
enum class CardType {
    /** Icc card type: Unknow type Card. */
    UNKNOWN_CARD = -1,

    /** Icc card type: Single sim card type. */
    SINGLE_MODE_SIM_CARD = 10,

    /** Icc card type: Single usim card type. */
    SINGLE_MODE_USIM_CARD = 20,

    /** Icc card type: Single ruim card type. */
    SINGLE_MODE_RUIM_CARD = 30,

    /** Icc card type: Double card C+G. */
    DUAL_MODE_CG_CARD = 40,

    /** Icc card type:  Roaming Card (Dual Mode). */
    CT_NATIONAL_ROAMING_CARD = 41,

    /** Icc card type: China Unicom Dual Mode Card. */
    CU_DUAL_MODE_CARD = 42,

    /** Icc card type: LTE Card (Dual Mode). */
    DUAL_MODE_TELECOM_LTE_CARD = 43,

    /** Icc card type: Double card U+G. */
    DUAL_MODE_UG_CARD = 50,

    /** Icc card type: Single isim card type. */
    SINGLE_MODE_ISIM_CARD = 60,
};

enum class SimState {
    /**
     * Indicates unknown SIM card state, that is, the accurate status cannot be obtained.
     */
    SIM_STATE_UNKNOWN,

    /**
     * Indicates that the SIM card is in the <b>not present</b> state, that is, no SIM card is inserted
     * into the card slot.
     */
    SIM_STATE_NOT_PRESENT,

    /**
     * Indicates that the SIM card is in the <b>locked</b> state, that is, the SIM card is locked by the
     * personal identification number (PIN)/PIN unblocking key (PUK) or network.
     */
    SIM_STATE_LOCKED,

    /**
     * Indicates that the SIM card is in the <b>not ready</b> state, that is, the SIM card is in position
     * but cannot work properly.
     */
    SIM_STATE_NOT_READY,

    /**
     * Indicates that the SIM card is in the <b>ready</b> state, that is, the SIM card is in position and
     * is working properly.
     */
    SIM_STATE_READY,

    /**
     * Indicates that the SIM card is in the <b>loaded</b> state, that is, the SIM card is in position and
     * is working properly.
     */
    SIM_STATE_LOADED
};

enum class LockReason {
    SIM_NONE,
    SIM_PIN,
    SIM_PUK,
    SIM_PN_PIN, // Network Personalization (refer 3GPP TS 22.022 [33])
    SIM_PN_PUK,
    SIM_PU_PIN, // network sUbset Personalization (refer 3GPP TS 22.022 [33])
    SIM_PU_PUK,
    SIM_PP_PIN, // service supplier Personalization (refer 3GPP TS 22.022 [33])
    SIM_PP_PUK,
    SIM_PC_PIN, // Corporate Personalization (refer 3GPP TS 22.022 [33])
    SIM_PC_PUK,
    SIM_SIM_PIN, // SIM/USIM personalisation (refer 3GPP TS 22.022 [33])
    SIM_SIM_PUK,
};

enum class PersoLockType {
    PN_PIN_LOCK, // Network Personalization (refer 3GPP TS 22.022 [33])
    PN_PUK_LOCK,
    PU_PIN_LOCK, // network sUbset Personalization (refer 3GPP TS 22.022 [33])
    PU_PUK_LOCK,
    PP_PIN_LOCK, // service supplier Personalization (refer 3GPP TS 22.022 [33])
    PP_PUK_LOCK,
    PC_PIN_LOCK, // Corporate Personalization (refer 3GPP TS 22.022 [33])
    PC_PUK_LOCK,
    SIM_PIN_LOCK, // SIM/USIM personalisation (refer 3GPP TS 22.022 [33])
    SIM_PUK_LOCK,
};

enum class LockType {
    PIN_LOCK = 1,
    FDN_LOCK = 2,
};

enum class LockState {
    /**Indicates that the lock state card is in the <b>off</b> state. */
    LOCK_OFF = 0,

    /**Indicates that the lock state card is in the <b>open</b> state. */
    LOCK_ON,

    /**Indicates that the lock state card is in the <b>error</b> state. */
    LOCK_ERROR,
};

struct LockInfo {
    LockType lockType;
    std::u16string password;
    LockState lockState;
};

struct PersoLockInfo {
    PersoLockType lockType;
    std::u16string password;
};

enum UnlockResult {
    UNLOCK_FAIL = -2, // unlock fail
    UNLOCK_INCORRECT = -1, // password error
    UNLOCK_OK = 0, // unlock successful
};

struct LockStatusResponse {
    int32_t result;
    int32_t remain;
};

struct SimAuthenticationResponse {
    int32_t sw1;
    int32_t sw2;
    std::string response;
};

enum SimAuthResult {
    SIM_AUTH_FAIL = -1,
    SIM_AUTH_SUCCESS = 0,
};

struct IccAccountInfo : public Parcelable {
    int32_t simId; // sim Id for card
    int32_t slotIndex; // slot index for card
    bool isEsim; // mark card is eSim or not
    bool isActive; // active status for card
    std::u16string iccId; // iccId for card
    std::u16string showName; // show name for card
    std::u16string showNumber; // show number for card
    inline static const std::u16string DEFAULT_SHOW_NAME = u"Card";
    inline static const std::u16string DEFAULT_SHOW_NUMBER = u"";
    inline static const std::u16string DEFAULT_ICC_ID = u"";

    void Init(int32_t simCardId, int32_t slotId)
    {
        this->simId = simCardId;
        this->slotIndex = slotId;
        this->isEsim = false;
        this->isActive = true;
        this->iccId = DEFAULT_ICC_ID;
        this->showName = DEFAULT_SHOW_NAME;
        this->showNumber = DEFAULT_SHOW_NUMBER;
    };

    void SetIsEsim(bool isEsimType)
    {
        this->isEsim = isEsimType;
    }

    void SetIsActive(bool activeEnabled)
    {
        this->isActive = activeEnabled;
    }

    void SetIccId(std::u16string id)
    {
        this->iccId = id;
    }

    void SetShowName(std::u16string name)
    {
        this->showName = name;
    }

    void SetShowNumber(std::u16string number)
    {
        this->showNumber = number;
    }

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(simId)) {
            return false;
        }
        if (!parcel.WriteInt32(slotIndex)) {
            return false;
        }
        if (!parcel.WriteBool(isEsim)) {
            return false;
        }
        if (!parcel.WriteBool(isActive)) {
            return false;
        }
        if (!parcel.WriteString16(iccId)) {
            return false;
        }
        if (!parcel.WriteString16(showName)) {
            return false;
        }
        if (!parcel.WriteString16(showNumber)) {
            return false;
        }
        return true;
    };

    std::shared_ptr<IccAccountInfo> UnMarshalling(Parcel &parcel)
    {
        std::shared_ptr<IccAccountInfo> param = std::make_shared<IccAccountInfo>();
        if (param == nullptr || !param->ReadFromParcel(parcel)) {
            param = nullptr;
        }
        return param;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        parcel.ReadInt32(simId);
        parcel.ReadInt32(slotIndex);
        parcel.ReadBool(isEsim);
        parcel.ReadBool(isActive);
        parcel.ReadString16(iccId);
        parcel.ReadString16(showName);
        parcel.ReadString16(showNumber);
        return true;
    };

    bool operator==(const IccAccountInfo &p)
    {
        return (slotIndex == p.slotIndex && simId == p.simId);
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_STATE_TYPE_H

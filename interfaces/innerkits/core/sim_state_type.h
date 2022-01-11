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

    /** Icc card type: LTE Card (Dual Mode).  */
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
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_STATE_TYPE_H

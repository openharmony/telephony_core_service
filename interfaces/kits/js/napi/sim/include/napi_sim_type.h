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

#ifndef NAPI_SIM_INCLUDE_NAPI_SIM_TYPE_H
#define NAPI_SIM_INCLUDE_NAPI_SIM_TYPE_H

enum CardType {
    UNKNOWN_CARD = -1, /** Icc card type: Unknow type Card. */
    SINGLE_MODE_SIM_CARD = 10, /** Icc card type: Single sim card type. */
    SINGLE_MODE_USIM_CARD = 20, /** Icc card type: Single usim card type. */
    SINGLE_MODE_RUIM_CARD = 30, /** Icc card type: Single ruim card type. */
    DUAL_MODE_CG_CARD = 40, /** Icc card type: Double card C+G. */
    CT_NATIONAL_ROAMING_CARD = 41, /** Icc card type: China Telecom Internal Roaming Card (Dual Mode). */
    CU_DUAL_MODE_CARD = 42, /** Icc card type: China Unicom Dual Mode Card. */
    DUAL_MODE_TELECOM_LTE_CARD = 43, /** Icc card type: China Telecom LTE Card (Dual Mode). */
    DUAL_MODE_UG_CARD = 50 /** Icc card type: Double card U+G. */
};

enum SimState {
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

enum LockReason { SIM_NONE, SIM_PIN, SIM_PUK };

#endif
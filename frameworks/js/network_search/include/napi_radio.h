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

#ifndef NAPI_RADIO_H
#define NAPI_RADIO_H

#include <codecvt>
#include <locale>
#include <string>
#include <mutex>
#include <condition_variable>

#include "cell_information.h"
#include "napi_radio_types.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_util.h"
#include "network_state.h"
#include "signal_information.h"
#include "network_information.h"
#include "network_search_result.h"
#include "telephony_napi_hril_error_code.h"
#include "telephony_napi_common_error.h"
#include "telephony_types.h"
#include "napi_ims_video_callback.h"
#include "napi_ims_voice_callback.h"
#include "napi_ims_ut_callback.h"
#include "napi_ims_sms_callback.h"

namespace OHOS {
namespace Telephony {
constexpr int DEFAULT_ERROR = ERROR_SERVICE_UNAVAILABLE;
constexpr int BUF_SIZE = 32;
constexpr int WAIT_TIME_SECOND = 60 * 3;
const static std::string GSM = "GSM";
const static std::string GPRS = "GPRS";
const static std::string WCDMA = "WCDMA";
const static std::string LTE = "LTE";
const int32_t ARRAY_INDEX_FIRST = 0;
const int32_t ARRAY_INDEX_SECOND = 1;
const int32_t ARRAY_INDEX_THIRD = 2;
const int32_t ARRAY_INDEX_FOURTH = 3;
const int32_t THREE_PARAMETERS = 3;
const int32_t FOUR_PARAMETERS = 4;

enum NativeSelectionMode {
    NATIVE_NETWORK_SELECTION_AUTOMATIC = 0,
    NATIVE_NETWORK_SELECTION_MANUAL = 1
};

enum NetworkSelectionMode {
    /** Unknown network selection modes. */
    NETWORK_SELECTION_UNKNOWN,

    /** Automatic network selection modes. */
    NETWORK_SELECTION_AUTOMATIC,

    /** Manual network selection modes. */
    NETWORK_SELECTION_MANUAL
};

enum NetworkInformationState {
    /** Indicates that the network state is unknown. */
    NETWORK_UNKNOWN,

    /** Indicates that the network is available for registration. */
    NETWORK_AVAILABLE,

    /** Indicates that you have already registered with the network. */
    NETWORK_CURRENT,

    /** Indicates that the network is unavailable for registration. */
    NETWORK_FORBIDDEN
};

enum NrOptionMode {
    /** Indicates unknown NR networking mode. */
    NR_OPTION_UNKNOWN,

    /** Indicates that the NR networking mode is NSA only. */
    NR_OPTION_NSA_ONLY,

    /** Indicates that the NR networking mode is SA only. */
    NR_OPTION_SA_ONLY,

    /** Indicates that the NR networking mode is NSA and SA. */
    NR_OPTION_NSA_AND_SA,
};

enum SlotIdState { SLOTID_INPUT_ERROR = 111, ENUMERATION_INPUT_ERROR = 222 };

enum PreferredNetwork {
    PREFERRED_NETWORK_MODE_AUTO = 0,
    PREFERRED_NETWORK_MODE_GSM = 1,
    PREFERRED_NETWORK_MODE_WCDMA = 2,
    PREFERRED_NETWORK_MODE_LTE = 3,
    PREFERRED_NETWORK_MODE_LTE_WCDMA = 4,
    PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM = 5,
    PREFERRED_NETWORK_MODE_WCDMA_GSM = 6,
    PREFERRED_NETWORK_MODE_CDMA = 7,
    PREFERRED_NETWORK_MODE_EVDO = 8,
    PREFERRED_NETWORK_MODE_EVDO_CDMA = 9,
    PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA = 10,
    PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA = 11,
    PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA = 12,
    PREFERRED_NETWORK_MODE_TDSCDMA = 13,
    PREFERRED_NETWORK_MODE_TDSCDMA_GSM = 14,
    PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA = 15,
    PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM = 16,
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA = 17,
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM = 18,
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA = 19,
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM = 20,
    PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 21,
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 22,
    PREFERRED_NETWORK_MODE_NR = 31,
    PREFERRED_NETWORK_MODE_NR_LTE = 32,
    PREFERRED_NETWORK_MODE_NR_LTE_WCDMA = 33,
    PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM = 34,
    PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA = 35,
    PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA = 36,
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA = 37,
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM = 38,
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA = 39,
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM = 40,
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 41,
};

struct AsyncContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    int status = DEFAULT_ERROR;
    int32_t result = DEFAULT_ERROR;
};

struct CallbackContext : BaseContext {
    std::mutex callbackMutex;
    std::condition_variable cv;
    bool callbackEnd = false;
    bool sendRequest = false;
    int32_t errorCode = HRIL_ERR_GENERIC_FAILURE;
};

struct RadioTechContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t csTech = DEFAULT_ERROR;
    int32_t psTech = DEFAULT_ERROR;
};

struct SignalInfoListContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::vector<sptr<SignalInformation>> signalInfoList;
};

struct GetSelectModeContext : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t selectMode = DEFAULT_ERROR;
};

struct SetSelectModeContext : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t selectMode = DEFAULT_ERROR;
    std::string operatorName = "";
    std::string operatorNumeric = "";
    int32_t state = NETWORK_UNKNOWN;
    std::string radioTech = "";
    bool resumeSelection = false;
    bool setResult = false;
};

struct GetSearchInfoContext : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    sptr<NetworkSearchResult> searchResult = nullptr;
};

struct GetStateContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::string longOperatorName = "";
    std::string shortOperatorName = "";
    std::string plmnNumeric = "";
    int32_t psRoamingStatus = 0;
    int32_t csRoamingStatus = 0;
    int32_t cfgTech = 0;
    bool isRoaming = false;
    int32_t regStatus = 0;
    int32_t nsaState = static_cast<int32_t>(NsaState::NSA_STATE_NOT_SUPPORT);
    bool isCaActive = false;
    bool isEmergency = false;
};

struct GetISOCountryCodeContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::string countryCode = "";
};

struct IsRadioOnContext : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    bool isRadioOn = false;
    bool sendRequestSlot2 = false;
};

struct SwitchRadioContext : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    bool sendRequestSlot2 = false;
};

struct GetOperatorNameContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    char operatorName[BUF_SIZE + 1] = {0};
    size_t operatorNameLength = 0;
};

struct PreferredNetworkModeContext : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t preferredNetworkMode = DEFAULT_ERROR;
};

struct GetIMEIContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::string getIMEIResult = "";
};

struct GetMEIDContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::string getMEIDResult = "";
};

struct SendUpdateCellLocationRequest : CallbackContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    bool sendRequestSlot2 = false;
};

struct CellInformationContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::vector<sptr<CellInformation>> cellInformations;
    napi_value callbackValue = nullptr;
};

struct GetPrimarySlotIdContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
};

struct GetUniqueDeviceIdContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::string getUniqueDeviceId = "";
};

struct GetNrOptionModeContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t nrOptionMode = DEFAULT_ERROR;
};

struct SetPrimarySlotIdContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    bool setResult = false;
};

struct GetImsRegInfoContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t imsSrvType = DEFAULT_ERROR;
    ImsRegInfo imsRegInfo = ERROR_IMS_REG_INFO;
};

struct ImsRegInfoContext : BaseContext {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    ImsRegInfo imsRegInfo = ERROR_IMS_REG_INFO;
};

struct ImsStateCallback {
    ImsStateCallback()
        :env(nullptr),
        thisVar(nullptr),
        callbackRef(nullptr),
        deferred(nullptr),
        callbackBeginTime_(0),
        slotId(0),
        imsSrvType(TYPE_VOICE),
        voiceCallback(nullptr),
        videoCallback(nullptr),
        utCallback(nullptr),
        smsCallback(nullptr)
    {}
    napi_env env;
    napi_value thisVar;
    napi_ref callbackRef;
    napi_deferred deferred;
    time_t callbackBeginTime_;
    int32_t slotId;
    ImsServiceType imsSrvType;
    sptr<ImsVoiceCallback> voiceCallback;
    sptr<ImsVideoCallback> videoCallback;
    sptr<ImsUtCallback> utCallback;
    sptr<ImsSmsCallback> smsCallback;
};

struct ImsStateWorker {
    ImsRegInfo info;
    ImsStateCallback callback;
};
} // namespace Telephony
} // namespace OHOS
#endif // NAPI_RADIO_H
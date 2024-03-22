/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef CORE_SERVICE_CLIENT_H
#define CORE_SERVICE_CLIENT_H

#include <cstdint>
#include <iremote_object.h>
#include <singleton.h>
#include <string_ex.h>

#include "i_core_service.h"

namespace OHOS {
namespace Telephony {
class CoreServiceClient : public DelayedRefSingleton<CoreServiceClient> {
    DECLARE_DELAYED_REF_SINGLETON(CoreServiceClient);

public:
    sptr<ICoreService> GetProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);

    /**
     * @brief Obtain the list of signal strength information of the registered network
     *
     * @param slotId[in], sim slot id
     * @param signalslist[out], list of signal strength information of the registered network
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals);

    /**
     * @brief Checks whether the device supports 5G New Radio (NR).
     *
     * @param slotId[in], sim slot id
     * @return returns true if the device supports 5G NR; returns false otherwise.
     */
    bool IsNrSupported(int32_t slotId);

    /**
     * @brief Obtain radio access technology (RAT) of the PS domain
     *
     * @param slotId[in], sim slot id
     * @param psRadioTech[out], RAT of the PS domain on the registered network
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetPsRadioTech(int32_t slotId, int32_t &psRadioTech);

    /**
     * @brief Obtain radio access technology (RAT) of the CS domain
     *
     * @param slotId[in], sim slot id
     * @param csRadioTech[out], RAT of the CS domain on the registered network
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCsRadioTech(int32_t slotId, int32_t &csRadioTech);

    /**
     * @brief Obtain the selection mode of NR
     *
     * @param slotId[in], sim slot id
     * @param mode[in], the selection mode of NR
     * @param callback[out], Indicates the result of setting NR mode
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the selection mode of NR
     *
     * @param slotId[in], sim slot id
     * @param callback[out], the callback of NR mode
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the unique ID
     *
     * @param slotId[in], sim slot id
     * @param deviceId[out], the unique ID of a device
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId);

    /**
     * @brief Obtain the mobile equipment identifier
     *
     * @param slotId[in], sim slot id
     * @param meid[out], the mobile equipment identifier of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetMeid(int32_t slotId, std::u16string &meid);

    /**
     * @brief Obtain the operator numeric
     *
     * @param slotId[in], sim slot id
     * @return std::u16string operator numeric of PLMN of the SIM card.
     */
    std::u16string GetOperatorNumeric(int32_t slotId);

    /**
     * @brief Obtain the resident network numeric
     *
     * @param slotId[in], sim slot id
     * @return std::string resident network numeric of PLMN of the SIM card.
     */
    std::string GetResidentNetworkNumeric(int32_t slotId);

    /**
     * @brief Obtain the operator name
     *
     * @param slotId[in], sim slot id
     * @param operatorName[out], the operator name of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetOperatorName(int32_t slotId, std::u16string &operatorName);

    /**
     * @brief Obtain the network state
     *
     * @param slotId[in], sim slot id
     * @param networkState[out], the callback of network registration state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState);

    /**
     * @brief Set the radio state
     *
     * @param slotId[in], sim slot id
     * @param isOn[in], turn on or turn off the radio service
     * @param callback[out], the callback of radio state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the radio state
     *
     * @param slotId[in], sim slot id
     * @param callback[out], the callback of radio state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the International Mobile Equipment Identification
     *
     * @param slotId[in], sim slot id
     * @param imei[out], the International Mobile Equipment Identification Number of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImei(int32_t slotId, std::u16string &imei);

    /**
     * @brief Checks whether a SIM card is inserted in a specified slot.
     *
     * @param slotId[in], sim slot id
     * @param hasSimCard[out], returns true if a SIM card is inserted; return false otherwise
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HasSimCard(int32_t slotId, bool &hasSimCard);

    /**
     * @brief Obtain the state of the SIM card
     *
     * @param slotId[in], sim slot id
     * @param simState[out], the state of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimState(int32_t slotId, SimState &simState);

    /**
     * @brief Obtain the value of dsds mode
     *
     * @param dsdsMode[out], the value of dsds mode
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDsdsMode(int32_t &dsdsMode);

    /**
     * @brief Obtain the operator numeric of PLMN
     *
     * @param slotId[in], sim slot id
     * @param operatorNumeric[out], the operator numeric of PLMN of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric);

    /**
     * @brief Obtain the ISO country code
     *
     * @param slotId[in], sim slot id
     * @param countryCode[out], the ISO country code of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode);

    /**
     * @brief Obtain the service provider name
     *
     * @param slotId[in], sim slot id
     * @param spn[out], the service provider name of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimSpn(int32_t slotId, std::u16string &spn);

    /**
     * @brief Obtain the integrated circuit card identity
     *
     * @param slotId[in], sim slot id
     * @param iccId[out], the integrated circuit card identity of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimIccId(int32_t slotId, std::u16string &iccId);

    /**
     * @brief Obtain the international mobile subscriber identity
     *
     * @param slotId[in], sim slot id
     * @param imsi[out], the international mobile subscriber identity of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetIMSI(int32_t slotId, std::u16string &imsi);

    /**
     * @brief Check whther the SIM card in a specified slot is China Telecom SIM.
     *
     * @param slotId[in], sim slot id
     * @param isCTSimCard[out], returns true if a SIM card is inserted; return false otherwise
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t IsCTSimCard(int32_t slotId, bool &isCTSimCard);

    /**
     * @brief Checks whether the SIM card in a specified slot is activated
     *
     * @param slotId[in], sim slot id
     * @return returns true if the SIM card activated; returns false otherwise.
     */
    bool IsSimActive(int32_t slotId);

    /**
     * @brief Obtain the sim slot id of the simId
     *
     * @param simId[in], sim card id
     * @return return the sim slot id of the simId.
     */
    int32_t GetSlotId(int32_t simId);

    /**
     * @brief Obtain the sim card id
     *
     * @param slotId[in], sim slot id
     * @return return the sim card id of the SIM card.
     */
    int32_t GetSimId(int32_t slotId);

    /**
     * @brief Obtain the callback of network search information
     *
     * @param slotId[in], sim slot id
     * @param callback[out], the callback of network search information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the callback of network selection mode
     *
     * @param slotId[in], sim slot id
     * @param callback[out], the callback of network selection mode
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the locale from the default sim
     *
     * @return std::u16string locale from default sim.
     */
    std::u16string GetLocaleFromDefaultSim();

    /**
     * @brief Obtain the group identifier level 1
     *
     * @param slotId[in], sim slot id
     * @param gid1[out], the group identifier level 1 of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimGid1(int32_t slotId, std::u16string &gid1);

    /**
     * @brief Obtain the group identifier level 2
     *
     * @param slotId[in], sim slot id
     * @return std::u16string the group identifier level 2 of the SIM card.
     */
    std::u16string GetSimGid2(int32_t slotId);

    /**
     * @brief Obtain the enhanced operator name string
     *
     * @param slotId[in], sim slot id
     * @param plmn[in], public land mobile network
     * @param lac[in], location area code
     * @param longNameRequired[in], required long name or not
     * @return std::u16string the enhanced operator name string of the SIM card.
     */
    std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired);

    /**
     * @brief Set the network search mode
     *
     * @param slotId[in], sim slot id
     * @param selectMode[in], the network search mode of the SIM card
     * @param networkInformation[in], the network information
     * @param resumeSelection[in], whether to continue selecting the network selection mode
     * @param callback[in], the callback of set network selection mode
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the ISO-defined country code
     *
     * @param slotId[in], sim slot id
     * @param countryCode[out], the ISO-defined country code of the country where the registered network is deployed
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode);

    /**
     * @brief Obtain the sim account information
     *
     * @param slotId[in], sim slot id
     * @param info[out], account information of SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);

    /**
     * @brief Set default voice slotId
     *
     * @param slotId[in], sim slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDefaultVoiceSlotId(int32_t slotId);

    /**
     * @brief Obtain default voice slotId
     *
     * @return int32_t default voice slotId.
     */
    int32_t GetDefaultVoiceSlotId();

    /**
     * @brief Obtain default voice simId
     *
     * @param simId[out], default voice simId
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDefaultVoiceSimId(int32_t &simId);

    /**
     * @brief Set the SIM card show number
     *
     * @param slotId[in], sim slot id
     * @param number[in], the SIM card show number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetShowNumber(int32_t slotId, const std::u16string &number);

    /**
     * @brief Obtain the SIM card show number
     *
     * @param slotId[in], sim slot id
     * @param showNumber[out], the SIM card show number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetShowNumber(int32_t slotId, std::u16string &showNumber);

    /**
     * @brief Set the SIM card show name
     *
     * @param slotId[in], sim slot id
     * @param name[in], the SIM card show name
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetShowName(int32_t slotId, const std::u16string &name);

    /**
     * @brief Obtain the SIM card show name
     *
     * @param slotId[in], sim slot id
     * @param showName[out], the SIM card show name
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetShowName(int32_t slotId, std::u16string &showName);

    /**
     * @brief Obtain the list of active SIM card account information
     *
     * @param iccAccountInfoList[out], the list of active SIM card account information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);

    /**
     * @brief Obtain the operator configs
     *
     * @param slotId[in], sim slot id
     * @param poc[out], the operator configs of SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);

    /**
     * @brief Unlock Pin
     *
     * @param slotId[in], sim slot id
     * @param pin[in], the password of the SIM card
     * @param response[out], the response of unlock pin
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnlockPin(int32_t slotId, const std::u16string &pin, LockStatusResponse &response);

    /**
     * @brief Unlock Puk
     *
     * @param slotId[in], sim slot id
     * @param newPin[in], newPin to reset the SIM card password
     * @param puk[in], the unlock password of the SIM card password
     * @param response[out], the response of unlock puk
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnlockPuk(
        int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response);

    /**
     * @brief Alter Pin
     *
     * @param slotId[in], sim slot id
     * @param newPin[in], newPin to change the SIM card password
     * @param oldPin[in], old password
     * @param response[out], the response of alter pin
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t AlterPin(
        int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin, LockStatusResponse &response);

    /**
     * @brief Unlock Pin2
     *
     * @param slotId[in], sim slot id
     * @param pin2[in], the password of the SIM card
     * @param response[out], the response of unlock pin2
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnlockPin2(int32_t slotId, const std::u16string &pin2, LockStatusResponse &response);

    /**
     * @brief Unlock Puk2
     *
     * @param slotId[in], sim slot id
     * @param newPin2[in], newPin2 to reset the SIM card password
     * @param puk2[in], the unlock password of the SIM card password
     * @param response[out], the response of unlock puk2
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnlockPuk2(
        int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2, LockStatusResponse &response);

    /**
     * @brief Alter Pin2
     *
     * @param slotId[in], sim slot id
     * @param newPin2[in], newPin2 to change the SIM card password
     * @param oldPin2[in], old password
     * @param response[out], the response of alter pin2
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t AlterPin2(
        int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2, LockStatusResponse &response);

    /**
     * @brief Set the SIM card lock state
     *
     * @param slotId[in], sim slot id
     * @param options[in], lock information
     * @param response[out], the response of set lock state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);

    /**
     * @brief Obtain the SIM card lock state
     *
     * @param slotId[in], sim slot id
     * @param lockType[in], lock type
     * @param lockState[out], the response of get lock state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState);

    /**
     * @brief Refresh the SIM card State
     *
     * @param slotId[in], sim slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RefreshSimState(int32_t slotId);

    /**
     * @brief Set the active sim enable or not
     *
     * @param slotId[in], sim slot id
     * @param enable[in], set active sim enable or not
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetActiveSim(const int32_t slotId, int32_t enable);

    /**
     * @brief Obtain the preferred network
     *
     * @param slotId[in], sim slot id
     * @param callback[out], the callback of get preferred network
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Set the preferred network
     *
     * @param slotId[in], sim slot id
     * @param networkMode[in], the preferred network mode
     * @param callback[out], the callback of set preferred network
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);

    /**
     * @brief Obtain the telephone number of the SIM card
     *
     * @param slotId[in], sim slot id
     * @param telephoneNumber[out], telephone number of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber);

    /**
     * @brief Get network capability
     *
     * @param slotId[in], sim slot id
     * @param networkCapabilityType[in], network capability type
     * @param networkCapabilityState[out], network capability state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetNetworkCapability(int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState);

    /**
     * @brief Set network capability
     *
     * @param slotId[in], sim slot id
     * @param networkCapabilityType[in], network capability type
     * @param networkCapabilityState[in], network capability state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetNetworkCapability(int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState);

    /**
     * @brief Obtain the voiceMail identifier
     *
     * @param slotId[in], sim slot id
     * @param voiceMailIdentifier[out], voiceMail identifier of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier);

    /**
     * @brief Obtain the voiceMail number
     *
     * @param slotId[in], sim slot id
     * @param voiceMailNumber[out], voiceMail number of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber);

    /**
     * @brief Obtain the voiceMail count
     *
     * @param slotId[in], sim slot id
     * @param voiceMailCount[out], voiceMail count of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount);

    /**
     * @brief Set the voiceMail count
     *
     * @param slotId[in], sim slot id
     * @param voiceMailCount[in], voiceMail count of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount);

    /**
     * @brief Set the voice call forwarding
     *
     * @param slotId[in], sim slot id
     * @param enable[in], enable voice call forwarding or not
     * @param number[in], voice call forwarding number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number);

    /**
     * @brief Query icc dialling numbers
     *
     * @param slotId[in], sim slot id
     * @param type[in], icc dialling numbers type
     * @param result[out], vector of icc dialling numbers
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t QueryIccDiallingNumbers(int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result);

    /**
     * @brief Add icc dialling numbers
     *
     * @param slotId[in], sim slot id
     * @param type[in], icc dialling number type
     * @param diallingNumber[in], dialing number information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);

    /**
     * @brief Delete icc dialling numbers
     *
     * @param slotId[in], sim slot id
     * @param type[in], icc dialling number type
     * @param diallingNumber[in], dialing number information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);

    /**
     * @brief Update icc dialling numbers
     *
     * @param slotId[in], sim slot id
     * @param type[in], icc dialling number type
     * @param diallingNumber[in], dialing number information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);

    /**
     * @brief Set the VoiceMail information
     *
     * @param slotId[in], sim slot id
     * @param mailName[in], VoiceMail name
     * @param mailNumber[in], VoiceMail number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);

    /**
     * @brief Obtain the IMS register status info
     *
     * @param slotId[in], sim slot id
     * @param imsSrvType[in], ims service type
     * @param info[out], ims register status info
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info);

    /**
     * @brief Obtain the maximum number of SIM card slots
     *
     * @return int32_t the maximum number of SIM card slots.
     */
    int32_t GetMaxSimCount();

    /**
     * @brief Obtain the operator key
     *
     * @param slotId[in], sim slot id
     * @param opkey[out], operator key of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetOpKey(int32_t slotId, std::u16string &opkey);

    /**
     * @brief Obtain the operator nv identity
     *
     * @param slotId[in], sim slot id
     * @param opkeyExt[out], operator nv identity of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt);

    /**
     * @brief Obtain the operator name
     *
     * @param slotId[in], sim slot id
     * @param opname[out], operator name of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetOpName(int32_t slotId, std::u16string &opname);

    /**
     * @brief Obtain the card type
     *
     * @param slotId[in], sim slot id
     * @param cardType[out], card type of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCardType(int32_t slotId, CardType &cardType);

    /**
     * @brief Send envelope command to SIM card
     *
     * @param slotId[in], sim slot id
     * @param cmd[in], envelope command to SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd);

    /**
     * @brief Send terminal response command to SIM card
     *
     * @param slotId[in], sim slot id
     * @param cmd[in], terminal response command to SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd);

    /**
     * @brief Send call setup request result
     *
     * @param slotId[in], sim slot id
     * @param accept[in], whether accept the call setup request
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept);

    /**
     * @brief Unlock sim lock
     *
     * @param slotId[in], sim slot id
     * @param lockInfo[in], customized lock type information
     * @param response[out], the response of unlock sim lock
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);

    /**
     * @brief Check whether your the caller has been granted the operator permissions
     *
     * @param slotId[in], sim slot id
     * @param hasOperatorPrivileges[out], whether your the caller has been granted the operator permissions
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges);

    /**
     * @brief Performs SIM card authentication
     *
     * @param slotId[in], sim slot id
     * @param aid[in], app id
     * @param authData[in], authentication data
     * @param response[out], the response of sim card authentication
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response);

    /**
     * @brief Obtain the primary slotId
     *
     * @param slotId[out], primary slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetPrimarySlotId(int32_t &slotId);

    /**
     * @brief Set the primary slotId
     *
     * @param slotId[in], primary slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPrimarySlotId(int32_t slotId);

    /**
     * @brief Obtain the cell information list
     *
     * @param slotId[in], primary slot id
     * @param cellInfo[out], the current cell information of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo);

    /**
     * @brief Requests for a cell location update
     *
     * @param slotId[in], primary slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCellLocationRequest(int32_t slotId);

    /**
     * @brief Register IMS registry information callback
     *
     * @param slotId[in], sim slot id
     * @param imsSrvType[in], ims service type
     * @param callback[out], the callback of ims register status info
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback);

    /**
     * @brief Unregister IMS registry information callback
     *
     * @param slotId[in], sim slot id
     * @param imsSrvType[in], ims service type
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType);

    /**
     * @brief Obtain the base band version
     *
     * @param slotId[in], sim slot id
     * @param version[out], the the baseband version of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetBasebandVersion(int32_t slotId, std::string &version);

    /**
     * @brief Obtain the NR ssb id information
     *
     * @param slotId[in], sim slot id
     * @param nrSsbInfomation[out], the nr ssb information of the SIM card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation);

    /**
     * @brief Reset all network settings of telephony
     *
     * @param slotId[in], sim slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t FactoryReset(int32_t slotId);

    /**
     * @brief init extra module function, for extra slot.
     *
     * @param slotId[in], sim slot id
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t InitExtraModule(int32_t slotId);

    /**
     * @brief Check whether insert apn in table.
     *
     * @param value[in], apn value
     * @return return true if need insert, otherwise return false
     */
    bool IsAllowedInsertApn(std::string &value);

    /**
     * @brief get cust opkey for sim card
     *
     * @param slotId[in], sim slot id
     * @param opkey[out], cust opkey for sim card
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetTargetOpkey(int32_t slotId, std::u16string &opkey);

private:
    void RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied);
    class CoreServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit CoreServiceDeathRecipient(CoreServiceClient &client) : client_(client) {}
        ~CoreServiceDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        CoreServiceClient &client_;
    };

private:
    std::mutex mutexProxy_;
    sptr<ICoreService> proxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
};
} // namespace Telephony
} // namespace OHOS
#endif // CORE_SERVICE_CLIENT_H

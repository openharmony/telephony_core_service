/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef ESIM_SERVICE_CLIENT_H
#define ESIM_SERVICE_CLIENT_H

#include <cstdint>
#include <iremote_object.h>
#include <singleton.h>
#include <string_ex.h>

#include "iesim_service.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS {
namespace Telephony {
class EsimServiceClientCallback : public SystemAbilityLoadCallbackStub {
public:
    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject) override;
    void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;
    bool IsFailed();
    const sptr<IRemoteObject> &GetRemoteObject() const;

private:
    bool isLoadSAFailed_ = false;
    sptr<IRemoteObject> remoteObject_ = nullptr;
};

class EsimServiceClient : public DelayedRefSingleton<EsimServiceClient> {
    DECLARE_DELAYED_REF_SINGLETON(EsimServiceClient);

public:
    /**
     * @brief Get the EID identifying for the eUICC hardware.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param eId[out], the EID identifying the eUICC hardware.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetEid(int32_t slotId, std::string &eId);

    /**
     * @brief Get the current status of eUICC OSU.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param osuStatus[out], the status of eUICC OSU update.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetOsuStatus(int32_t slotId, int32_t &osuStatus);

    /**
     * @brief Execute OSU if current OSU is not the latest one.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param startOsuResult[out], the status of OSU update when OSU status changed.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t StartOsu(int32_t slotId, int32_t &startOsuResult);

    /**
     * @brief Fills in the metadata for a downloadable profile.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param portIndex[in], index of the port from the slot.
     * @param profile[in], the Bound Profile Package data returned by SM-DP+ server.
     * @param forceDisableProfile[in], if true, and if an active SIM must be deactivated to access the eUICC,
     * perform this action automatically.
     * @param profileMetadataResult[out], the metadata for profile.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDownloadableProfileMetadata(int32_t slotId, int32_t portIndex, const DownloadableProfile &profile,
        bool forceDisableProfile, GetDownloadableProfileMetadataResult &profileMetadataResult);

    /**
     * @brief Gets downloadable profile List which are available for download on this device.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param forceDisableProfile[in], if true, and if an active SIM must be deactivated to access the eUICC,
     * perform this action automatically.
     * @param profileListResult[out], the metadata for downloadableProfile which are
     * available for download on this device.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDownloadableProfiles(
        int32_t slotId, int32_t portIndex, bool forceDisableProfile, GetDownloadableProfilesResult &profileListResult);

    /**
     * @brief Attempt to download the given downloadable Profile.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param configInfo[in], downloadprofile config info.
     * @param profile[in], the Bound Profile Package data returned by SM-DP+ server.
     * @param downloadProfileResult[out], the given downloadableProfile.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DownloadProfile(int32_t slotId, DownloadProfileConfigInfo configInfo, const DownloadableProfile &profile,
        DownloadProfileResult &downloadProfileResult);

    /**
     * @brief Get a list of all euiccProfile informations.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param euiccProfileInfoList[out], a list of eUICC profile information.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResult &euiccProfileInfoList);

    /**
     * @brief Get information about the eUICC chip/device.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param eUiccInfo[out], the eUICC information to obtain.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo);

    /**
     * @brief Delete the given profile.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param iccId[in], the iccId of the profile.
     * @param deleteProfileResult[out], the response to deletes the given profile.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t DeleteProfile(int32_t slotId, const std::string &iccId, int32_t &deleteProfileResult);

    /**
     * @brief Switch to (enable) the given profile.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param portIndex[in], index of the port from the slot.
     * @param iccId[in], the iccId of the profile.
     * @param forceDisableProfile[in], if true, and if an active SIM must be deactivated to access the eUICC,
     * perform this action automatically.
     * @param switchToProfileResult[out], the response to switch profile.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SwitchToProfile(int32_t slotId, int32_t portIndex,
        const std::string &iccId, bool forceDisableProfile, int32_t &switchToProfileResult);

    /**
     * @brief Set the nickname for the given profile.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param iccId[in], the iccId of the profile.
     * @param nickname[in], the nickname of the profile.
     * @param setProfileNicknameResult[out], the result of the set nickname operation.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetProfileNickname(
        int32_t slotId, const std::string &iccId, const std::string &nickname, int32_t &setProfileNicknameResult);

    /**
     * @brief Erase all specific profiles and reset the eUICC.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param resetOption[in], options for resetting eUICC memory.
     * @param resetMemoryResult[out], the result of the reset operation.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ResetMemory(int32_t slotId, int32_t resetOption, int32_t &resetMemoryResult);

    /**
     * @brief Ensure that profiles will be retained on the next factory reset.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param restoreResult[out], the result code.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ReserveProfilesForFactoryRestore(int32_t slotId, int32_t &restoreResult);

    /**
     * @brief Set or update the default SM-DP+ address stored in an eUICC.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param defaultSmdpAddress[in], the default SM-DP+ address to set.
     * @param setDefaultSmdpAddressResult[out], the result code.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDefaultSmdpAddress(
        int32_t slotId, const std::string &defaultSmdpAddress, int32_t &setDefaultSmdpAddressResult);

    /**
     * @brief Gets the default SM-DP+ address stored in an eUICC.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param defaultSmdpAddress[out], the default SM-DP+ address.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t GetDefaultSmdpAddress(int32_t slotId, std::string &defaultSmdpAddress);

    /**
     * @brief Cancel session.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param transactionId[in], the transaction ID returned by SM-DP+ server.
     * @param cancelReason[in], the cancel reason.
     * @param responseResult[out], the result code and cancel session response string.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CancelSession(int32_t slotId, const std::string &transactionId,
        int32_t cancelReason, ResponseEsimResult &responseResult);

    /**
     * @brief Check whether embedded subscriptions are currently supported.
     *
     * @param slotId[in], indicates the card slot index number.
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t IsSupported(int32_t slotId);

    /**
     * @brief Starts a page through an ability, on which users can touch the button to download a profile.
     *
     * @param slotId[in], indicates the card slot index number.
     * @param profile[in], the Bound Profile Package data returned by SM-DP+ server.
     * @return Return int32_t TELEPHONY_SUCCESS if the profile is added successfully; others on failure.
     */
    int32_t AddProfile(int32_t slotId, DownloadableProfile profile);

private:
    void RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied);
    class EsimServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit EsimServiceDeathRecipient(EsimServiceClient &client) : client_(client) {}
        ~EsimServiceDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        EsimServiceClient &client_;
    };

private:
    std::mutex mutexProxy_;
    sptr<IEsimService> proxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
    sptr<IEsimService> GetProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);
};
} // namespace Telephony
} // namespace OHOS
#endif // ESIM_SERVICE_CLIENT_H
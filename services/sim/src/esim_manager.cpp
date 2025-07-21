/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#include "esim_manager.h"
#include "string_ex.h"
#include "telephony_errors.h"

#ifdef CORE_SERVICE_SUPPORT_ESIM
namespace OHOS {
namespace Telephony {
EsimManager::EsimManager(std::shared_ptr<ITelRilManager> telRilManager) : telRilManager_(telRilManager)
{
    TELEPHONY_LOGI("EsimManager::EsimManager()");
}

EsimManager::~EsimManager() {}

bool EsimManager::OnInit(int32_t slotCount)
{
    TELEPHONY_LOGI("EsimManager OnInit, slotCount = %{public}d", slotCount);
    if (slotCount < ESIM_SLOT_ID_ZERO || slotCount > ESIM_MAX_SLOT_COUNT) {
        TELEPHONY_LOGI("EsimManager, slotCount is out of range");
        return false;
    }
    slotCount_ = slotCount;
    esimFiles_.resize(slotCount_);
    for (int32_t slotId = 0; slotId < slotCount_; slotId++) {
        esimFiles_[slotId] = std::make_shared<EsimFile>(telRilManager_, slotId);
    }
    return true;
}

template<class N>
bool EsimManager::IsValidSlotId(int32_t slotId, std::vector<N> vec)
{
    if ((slotId < ESIM_SLOT_ID_ZERO) || (slotId >= static_cast<int32_t>(vec.size()))) {
        TELEPHONY_LOGE("slotId is invalid by vec.size(), slotId = %{public}d", slotId);
        return false;
    }
    return true;
}

int32_t EsimManager::GetEid(int32_t slotId, std::u16string &eId)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("esimFiles_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eId = Str8ToStr16(esimFiles_[slotId]->ObtainEid());
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListInnerResult &euiccProfileInfoList)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    euiccProfileInfoList = esimFiles_[slotId]->GetEuiccProfileInfoList();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eUiccInfo = esimFiles_[slotId]->GetEuiccInfo();
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::DisableProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->DisableProfile(portIndex, iccId);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    smdsAddress = Str8ToStr16(esimFiles_[slotId]->ObtainSmdsAddress(portIndex));
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetRulesAuthTable(
    int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eUiccRulesAuthTable = esimFiles_[slotId]->ObtainRulesAuthTable(portIndex);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetEuiccChallenge(int32_t slotId, int32_t portIndex, ResponseEsimInnerResult &responseResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    responseResult = esimFiles_[slotId]->ObtainEuiccChallenge(portIndex);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    defaultSmdpAddress = Str8ToStr16(esimFiles_[slotId]->ObtainDefaultSmdpAddress());
    if (defaultSmdpAddress == Str8ToStr16("")) {
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::CancelSession(int32_t slotId, const std::u16string &transactionId,
    CancelReason cancelReason, ResponseEsimInnerResult &responseResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    responseResult = esimFiles_[slotId]->CancelSession(transactionId, cancelReason);
    if (responseResult.resultCode_ != static_cast<int32_t>(EsimResultCode::RESULT_OK)) {
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eUiccProfile = esimFiles_[slotId]->ObtainProfile(portIndex, iccId);
    if (eUiccProfile.state_ != ProfileState::PROFILE_STATE_DISABLED) {
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::ResetMemory(int32_t slotId, ResetOption resetOption, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or esimFiles_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->ResetMemory(resetOption);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::SetDefaultSmdpAddress(
    int32_t slotId, const std::u16string &defaultSmdpAddress, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or esimFiles_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->SetDefaultSmdpAddress(defaultSmdpAddress);
    return TELEPHONY_ERR_SUCCESS;
}

bool EsimManager::IsSupported(int32_t slotId)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or esimFiles_ is null!");
        return false;
    }
    return esimFiles_[slotId]->IsSupported();
}

int32_t EsimManager::SendApduData(
    int32_t slotId, const std::u16string &aid, const EsimApduData &apduData, ResponseEsimInnerResult &responseResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("slotId is invalid or esimFiles_ is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    responseResult = esimFiles_[slotId]->SendApduData(aid, apduData);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::PrepareDownload(int32_t slotId, const DownLoadConfigInfo &downLoadConfigInfo,
    ResponseEsimInnerResult &responseResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    responseResult = esimFiles_[slotId]->ObtainPrepareDownload(downLoadConfigInfo);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::LoadBoundProfilePackage(int32_t slotId, int32_t portIndex,
    const std::u16string &boundProfilePackage, ResponseEsimBppResult &responseResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    responseResult = esimFiles_[slotId]->ObtainLoadBoundProfilePackage(portIndex, boundProfilePackage);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::ListNotifications(
    int32_t slotId, int32_t portIndex, EsimEvent events, EuiccNotificationList &notificationList)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    notificationList = esimFiles_[slotId]->ListNotifications(portIndex, events);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::RetrieveNotificationList(
    int32_t slotId, int32_t portIndex, EsimEvent events, EuiccNotificationList &notificationList)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("RetrieveNotificationList simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    notificationList = esimFiles_[slotId]->RetrieveNotificationList(portIndex, events);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::RetrieveNotification(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("RetrieveNotification simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    notification = esimFiles_[slotId]->ObtainRetrieveNotification(portIndex, seqNumber);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::RemoveNotificationFromList(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("RemoveNotificationFromList simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->RemoveNotificationFromList(portIndex, seqNumber);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::DeleteProfile(int32_t slotId, const std::u16string &iccId, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->DeleteProfile(iccId);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::SwitchToProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool forceDisableProfile, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->SwitchToProfile(portIndex, iccId, forceDisableProfile);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::SetProfileNickname(
    int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, int32_t &enumResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    enumResult = esimFiles_[slotId]->SetProfileNickname(iccId, nickname);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetEuiccInfo2(int32_t slotId, int32_t portIndex, EuiccInfo2 &euiccInfo2)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    euiccInfo2 = esimFiles_[slotId]->ObtainEuiccInfo2(portIndex);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::AuthenticateServer(
    int32_t slotId, const AuthenticateConfigInfo &authenticateConfigInfo, ResponseEsimInnerResult &responseResult)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    responseResult = esimFiles_[slotId]->AuthenticateServer(authenticateConfigInfo);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t EsimManager::GetContractInfo(
    int32_t slotId, const GetContractInfoRequest &getContractInfoRequest, std::string& response)
{
    if ((!IsValidSlotId(slotId, esimFiles_)) || (esimFiles_[slotId] == nullptr)) {
        TELEPHONY_LOGE("simFileManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    response = esimFiles_[slotId]->GetContractInfo(getContractInfoRequest);
    return TELEPHONY_ERR_SUCCESS;
}

} // namespace Telephony
} // namespace OHOS

#else
namespace OHOS {
namespace Telephony {
EsimManager::EsimManager(std::shared_ptr<ITelRilManager> telRilManager) : telRilManager_(telRilManager)
{
    TELEPHONY_LOGI("EsimManager, unsupport esim, not init");
}

EsimManager::~EsimManager() {}

bool EsimManager::OnInit(int32_t slotCount)
{
    return false;
}

template<class N>
bool EsimManager::IsValidSlotId(int32_t slotId, std::vector<N> vec)
{
    return false;
}

int32_t EsimManager::GetEid(int32_t slotId, std::u16string &eId)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListInnerResult &euiccProfileInfoList)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::DisableProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetRulesAuthTable(
    int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetEuiccChallenge(int32_t slotId, int32_t portIndex, ResponseEsimInnerResult &responseResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::CancelSession(int32_t slotId, const std::u16string &transactionId,
    CancelReason cancelReason, ResponseEsimInnerResult &responseResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::ResetMemory(int32_t slotId, ResetOption resetOption, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::SetDefaultSmdpAddress(
    int32_t slotId, const std::u16string &defaultSmdpAddress, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

bool EsimManager::IsSupported(int32_t slotId)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::SendApduData(
    int32_t slotId, const std::u16string &aid, const EsimApduData &apduData, ResponseEsimInnerResult &responseResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::PrepareDownload(int32_t slotId, const DownLoadConfigInfo &downLoadConfigInfo,
    ResponseEsimInnerResult &responseResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::LoadBoundProfilePackage(int32_t slotId, int32_t portIndex,
    const std::u16string &boundProfilePackage, ResponseEsimBppResult &responseResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::ListNotifications(
    int32_t slotId, int32_t portIndex, EsimEvent events, EuiccNotificationList &notificationList)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::RetrieveNotificationList(
    int32_t slotId, int32_t portIndex, EsimEvent events, EuiccNotificationList &notificationList)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::RetrieveNotification(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::RemoveNotificationFromList(
    int32_t slotId, int32_t portIndex, int32_t seqNumber, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::DeleteProfile(int32_t slotId, const std::u16string &iccId, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::SwitchToProfile(
    int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool forceDisableProfile, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::SetProfileNickname(
    int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, int32_t &enumResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetEuiccInfo2(int32_t slotId, int32_t portIndex, EuiccInfo2 &euiccInfo2)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::AuthenticateServer(
    int32_t slotId, const AuthenticateConfigInfo &authenticateConfigInfo, ResponseEsimInnerResult &responseResult)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

int32_t EsimManager::GetContractInfo(
    int32_t slotId, const GetContractInfoRequest &getContractInfoRequest, std::string& response)
{
    return TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM;
}

} // namespace Telephony
} // namespace OHOS
#endif
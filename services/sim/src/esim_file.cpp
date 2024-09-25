std::string EsimFile::ObtainDefaultSmdpAddress()
{
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventSmdpAddress = BuildCallerInfo(MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE);
    if (!ProcessObtainDefaultSmdpAddress(slotId_, eventSmdpAddress)) {
        TELEPHONY_LOGE("ProcessObtainDefaultSmdpAddress encode failed");
        return "";
    }
    areObtainDefaultSmdpAddressReady_ = false;
    std::unique_lock<std::mutex> lock(obtainDefaultSmdpAddressMutex_);
    if (!obtainDefaultSmdpAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areObtainDefaultSmdpAddressReady_; })) {
        SyncCloseChannel();
        return "";
    }
    SyncCloseChannel();
    return defaultDpAddress_;
}

ResponseEsimResult EsimFile::CancelSession(const std::u16string &transactionId, CancelReason cancelReason)
{
    esimProfile_.transactionId = transactionId;
    esimProfile_.cancelReason = cancelReason;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventCancelSession = BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    if (!ProcessCancelSession(slotId_, eventCancelSession)) {
        TELEPHONY_LOGE("ProcessCancelSession encode failed");
        return ResponseEsimResult();
    }
    areCancelSessionReady_ = false;
    std::unique_lock<std::mutex> lock(cancelSessionMutex_);
    if (!cancelSessionCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areCancelSessionReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return cancelSessionResult_;
}

EuiccProfile EsimFile::ObtainProfile(int32_t portIndex, const std::u16string &iccId)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventGetProfile = BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    if (!ProcessGetProfile(slotId_, eventGetProfile)) {
        TELEPHONY_LOGE("ProcessGetProfile encode failed");
        return EuiccProfile();
    }
    areObtainProfileReady_ = false;
    std::unique_lock<std::mutex> lock(obtainProfileMutex_);
    if (!obtainProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areObtainProfileReady_; })) {
        SyncCloseChannel();
        return EuiccProfile();
    }
    SyncCloseChannel();
    return eUiccProfile_;
}

bool EsimFile::ProcessObtainDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_CONFIGURED_ADDRESSES);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t transApduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (transApduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessGetProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_PROFILES);
        std::shared_ptr<Asn1Builder> subBuilder = std::make_shared<Asn1Builder>(TAG_ESIM_CTX_COMP_0);
        if (builder == nullptr || subBuilder == nullptr) {
            TELEPHONY_LOGE("get builder failed");
            return false;
        }
        std::string iccidBytes;
        std::string str = OHOS::Telephony::ToUtf8(profile->iccId);
        Asn1Utils::BcdToBytes(str, iccidBytes);
        subBuilder->Asn1AddChildAsBytes(TAG_ESIM_ICCID, iccidBytes, iccidBytes.length());
        std::shared_ptr<Asn1Node> subNode = subBuilder->Asn1Build();
        builder->Asn1AddChild(subNode);
        unsigned char EUICC_PROFILE_TAGS[] = {
            (unsigned char) TAG_ESIM_ICCID,
            (unsigned char) TAG_ESIM_NICKNAME,
            (unsigned char) TAG_ESIM_OBTAIN_OPERATOR_NAME,
            (unsigned char) TAG_ESIM_PROFILE_NAME,
            (unsigned char) TAG_ESIM_OPERATOR_ID,
            (unsigned char) (TAG_ESIM_PROFILE_STATE / 256),
            (unsigned char) (TAG_ESIM_PROFILE_STATE % 256),
            (unsigned char) TAG_ESIM_PROFILE_CLASS,
            (unsigned char) TAG_ESIM_PROFILE_POLICY_RULE,
            (unsigned char) (TAG_ESIM_CARRIER_PRIVILEGE_RULES / 256),
            (unsigned char) (TAG_ESIM_CARRIER_PRIVILEGE_RULES % 256),
        };
        std::string getProfileTags;
        for (unsigned char tag : EUICC_PROFILE_TAGS) {
            getProfileTags += tag;
        }
        builder->Asn1AddChildAsBytes(TAG_ESIM_TAG_LIST, getProfileTags, getProfileTags.length());
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t transApduResult == telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (transApduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessCancelSession(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_CANCEL_SESSION);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        std::string transactionIdStr = Str16ToStr8(profile->transactionId);
        std::string transactionIdByte = Asn1Utils::HexStrToBytes(transactionIdStr);
        builder->Asn1AddChildAsBytes(TAG_ESIM_CTX_0, transactionIdByte, transactionIdByte.length());
        builder->Asn1AddChildAsInteger(TAG_ESIM_CTX_1, (uint)profile->cancelReason);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t transApduResult == telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (transApduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessObtainDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, responseByte.length());
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    std::string outPutBytes;
    int32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if(byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero!");
        return false;
    }
    std::string strResult = Asn1Utils::BytesToHexStr(outPutBytes);
    defaultDpAddress_ = strResult;
    return isFileHandleResponse;
}

bool EsimFile::ProcessCancelSessionDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, responseByte.length());
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    if (root->Asn1HasChild(TAG_ESIM_CTX_1)) {
        std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_1);
        if (pAsn1Node == nullptr) {
            TELEPHONY_LOGE("pAsn1Node is nullptr");
            return false;
        }
        int32_t asn1ToInt = pAsn1Node->Asn1AsInteger();
        return false;
    }
    std::string strResult;
    int32_t byteLen = root->Asn1AsBytes(strResult);
    cancelSessionResult_.resultCode = ResultState::RESULT_OK;
    cancelSessionResult_.response = OHOS::Telephony::ToUtf16(strResult);
    {
        std::lock_guard<std::mutex> lock(cancelSessionMutex_);
        areCancelSessionReady_ = true;
    }
    cancelSessionCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessGetProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::string responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, responseByte.length());
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    if (!GetProfileDoneParseProfileInfo(root)) {
        TELEPHONY_LOGE("GetProfileDoneParseProfileInfo error!");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(obtainProfileMutex_);
        areObtainProfileReady_ = true;
    }
    obtainProfileCv_.notify_one();
    return isFileHandleResponse;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainDefaultSmdpAddressDone(event); };
    memberFuncMap_[MSG_ESIM_CANCEL_SESSION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessCancelSessionDone(event); };
    memberFuncMap_[MSG_ESIM_GET_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessGetProfileDone(event); };
}
} // namespace Telephony
} // namespace OHOS
ResultState EsimFile::DisableProfile(int32_t portIndex, std::u16string &iccId)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.iccId = iccId;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventDisableProfile = BuildCallerInfo(MSG_ESIM_DISABLE_PROFILE);
    if (!ProcessDisableProfile(slotId_, eventDisableProfile)) {
        TELEPHONY_LOGE("ProcessDisableProfile encode failed");
        return ResultState();
    }
    areDisableProfileReady_ = false;
    std::unique_lock<std::mutex> lock(disableProfileMutex_);
    if (!disableProfileCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areDisableProfileReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return disableProfileResult_;
}

std::string EsimFile::ObtainSmdsAddress(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventObtainSmdsAddress = BuildCallerInfo(MSG_ESIM_OBTAIN_SMDS_ADDRESS);
    if (!ProcessObtainSmdsAddress(slotId_, eventObtainSmdsAddress)) {
        TELEPHONY_LOGE("ProcessObtainSmdsAddress encode failed");
        return "";
    }
    areSmdsAddressReady_ = false;
    std::unique_lock<std::mutex> lock(smdsAddressMutex_);
    if (!smdsAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areSmdsAddressReady_; })) {
        SyncCloseChannel();
        return "";
    }
    SyncCloseChannel();
    return smdsAddress_;
}

EuiccRulesAuthTable EsimFile::ObtainRulesAuthTable(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable = BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    if (!ProcessRequestRulesAuthTable(slotId_, eventRequestRulesAuthTable)) {
        TELEPHONY_LOGE("ProcessRequestRulesAuthTable encode failed");
        return EuiccRulesAuthTable();
    }
    areRulesAuthTableReady_ = false;
    std::unique_lock<std::mutex> lock(rulesAuthTableMutex_);
    if (!rulesAuthTableCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areRulesAuthTableReady_; })) {
        SyncCloseChannel();
        return EuiccRulesAuthTable();
    }
    SyncCloseChannel();
    return eUiccRulesAuthTable_;
}

ResponseEsimResult EsimFile::ObtainEuiccChallenge(int32_t portIndex)
{
    esimProfile_.portIndex = portIndex;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventEUICCChanllenge = BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE);
    if (!ProcessObtainEUICCChallenge(slotId_, eventEUICCChanllenge)) {
        TELEPHONY_LOGE("ProcessObtainEUICCChallenge encode failed");
        return ResponseEsimResult();
    }
    areEuiccChallengeReady_ = false;
    std::unique_lock<std::mutex> lock(euiccChallengeMutex_);
    if (!euiccChallengeCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areEuiccChallengeReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return responseChallengeResult_;
}

bool EsimFile::ProcessDisableProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_DISABLE_PROFILE);
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
        builder->Asn1AddChildAsBoolean(TAG_ESIM_CTX_1, true);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessObtainSmdsAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_CONFIGURED_ADDRESSES);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessRequestRulesAuthTable(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_RAT);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessObtainEUICCChallenge(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_EUICC_CHALLENGE);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        int32_t apduResult = telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        if (apduResult == TELEPHONY_ERR_FAIL) {
            return false;
        }
        return true;
    }
    return false;
}

bool EsimFile::ProcessDisableProfileDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    if (pAsn1Node == nullptr) {
        TELEPHONY_LOGE("pAsn1Node is nullptr");
        return false;
    }
    disableProfileResult_ = (ResultState)pAsn1Node->Asn1AsInteger();
    {
        std::lock_guard<std::mutex> lock(disableProfileMutex_);
        areDisableProfileReady_ = true;
    }
    disableProfileCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessObtainSmdsAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    if (profileRoot == nullptr) {
        TELEPHONY_LOGE("profileRoot is nullptr!");
        return false;
    }
    std::string outPutBytes;
    uint32_t byteLen = profileRoot->Asn1AsBytes(outPutBytes);
    if(byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero!");
        return false;
    }
    smdsAddress_ = outPutBytes;
    {
        std::lock_guard<std::mutex> lock(smdsAddressMutex_);
        areSmdsAddressReady_ = true;
    }
    smdsAddressCv_.notify_one();
    return isFileHandleResponse;
}

struct CarrierIdentifier CarrierIdentifiers(const std::string mccMncData, int mccMncLen,
    const std::u16string& gid1, const std::u16string& gid2)
{
    std::string strResult;
    strResult = Asn1Utils::BytesToHexStr(mccMncData);

    std::string mMcc(NUMBER_THREE, '\0');
    mMcc[NUMBER_ZERO] = strResult[NUMBER_ONE];
    mMcc[NUMBER_ONE] = strResult[NUMBER_ZERO];
    mMcc[NUMBER_TWO] = strResult[NUMBER_THREE];

    std::string mMnc(NUMBER_THREE, '\0');
    if (strResult[NUMBER_TWO] == 'F') {
        mMnc[NUMBER_ZERO] = strResult[NUMBER_FIVE];
        mMnc[NUMBER_ONE] = strResult[NUMBER_FOUR];
    } else {
        mMnc[NUMBER_ZERO] = strResult[NUMBER_FIVE];
        mMnc[NUMBER_ONE] = strResult[NUMBER_FOUR];
        mMnc[NUMBER_TWO] = strResult[NUMBER_TWO];
    }

    struct CarrierIdentifier carrierId;
    carrierId.mcc = OHOS::Telephony::ToUtf16(mMcc);
    carrierId.mnc = OHOS::Telephony::ToUtf16(mMnc);
    carrierId.gid1 = gid1;
    carrierId.gid2 = gid2;
    return carrierId;
}

struct CarrierIdentifier buildCarrierIdentifiers(std::shared_ptr<Asn1Node> &root)
{
    std::u16string gid1;
    std::u16string gid2;
    std::string gid1Byte;
    std::string gid2Byte;
    std::string strResult;
    if (root->Asn1HasChild(TAG_ESIM_CTX_1)) {
        std::shared_ptr<Asn1Node> node = root->Asn1GetChild(TAG_ESIM_CTX_1);
        node->Asn1AsBytes(gid1Byte);
        strResult = Asn1Utils::BytesToHexStr(gid1Byte);
        gid1 = OHOS::Telephony::ToUtf16(strResult);
    }
    if (root->Asn1HasChild(TAG_ESIM_CTX_2)) {
        std::shared_ptr<Asn1Node> node = root->Asn1GetChild(TAG_ESIM_CTX_2);
        node->Asn1AsBytes(gid2Byte);
        strResult = Asn1Utils::BytesToHexStr(gid2Byte);
        gid2 = OHOS::Telephony::ToUtf16(strResult);
    }

    std::string mccMnc;
    std::shared_ptr<Asn1Node> pAsn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    int mccMncLen = pAsn1Node->Asn1AsBytes(mccMnc);
    CarrierIdentifier myCarrier = CarrierIdentifiers(mccMnc, mccMncLen, gid1, gid2);
    return myCarrier;
}

bool EsimFile::RequestRulesAuthTableParseTagCtxComp0(std::shared_ptr<Asn1Node> &root)
{
    const int TAG_NUM = 2;
    bool isFileHandleResponse = true;
    std::list<std::shared_ptr<Asn1Node>> Nodes;
    std::list<std::shared_ptr<Asn1Node>> opIdNodes;
    root->Asn1GetChildren(TAG_ESIM_CTX_COMP_0, Nodes);
    for(auto it = Nodes.begin(); it != Nodes.end(); ++it)
    {
        std::shared_ptr<Asn1Node> pNode = *it;
        std::shared_ptr<Asn1Node> pAGetChildChild = pNode->Asn1GetChildChild(TAG_NUM,
            TAG_ESIM_SEQUENCE, TAG_ESIM_CTX_COMP_1);
        if (pAGetChildChild == nullptr) {
            return false;
        }
        int opIdNodesRes = pAGetChildChild->Asn1GetChildren(TAG_ESIM_OPERATOR_ID, opIdNodes);
        if (opIdNodesRes != 0 ) {
            return isFileHandleResponse;
        }
        for(auto iter = opIdNodes.begin(); iter != opIdNodes.end(); ++iter)
        {
            std::shared_ptr<Asn1Node> curNode = nullptr;
            curNode = *iter;
            if (curNode == nullptr) {
                return false;
            }
            eUiccRulesAuthTable_.carrierIds.push_back(buildCarrierIdentifiers(curNode));
        }
        pAGetChildChild = pNode->Asn1GetChildChild(TAG_NUM, TAG_ESIM_SEQUENCE, TAG_ESIM_CTX_0);
        int policyRules = pAGetChildChild->Asn1AsInteger();
        pAGetChildChild = pNode->Asn1GetChildChild(TAG_NUM, TAG_ESIM_SEQUENCE, TAG_ESIM_CTX_2);
        int policyRuleFlags = pAGetChildChild->Asn1AsInteger();
        eUiccRulesAuthTable_.policyRules.push_back(policyRules);
        eUiccRulesAuthTable_.policyRuleFlags.push_back(policyRuleFlags);
    }
    return isFileHandleResponse;
}

bool EsimFile::ProcessRequestRulesAuthTableDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    uint32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    if (!RequestRulesAuthTableParseTagCtxComp0(root)) {
        TELEPHONY_LOGE("RequestRulesAuthTableParseTagCtxComp0 error");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(rulesAuthTableMutex_);
        areRulesAuthTableReady_ = true;
    }
    rulesAuthTableCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessObtainEUICCChallengeDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    responseChallengeResult_.resultCode = ResultState::RESULT_UNDEFINED_ERROR;
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
    uint32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("Asn1ParseResponse failed");
        return false;
    }
    std::shared_ptr<Asn1Node> profileRoot = root->Asn1GetChild(TAG_ESIM_CTX_0);
    std::string profileResponseByte;
    byteLen = profileRoot->Asn1AsBytes(profileResponseByte);
    if (byteLen == 0) {
        return isFileHandleResponse;
    }
    std::string strResult = Asn1Utils::BytesToHexStr(profileResponseByte);
    responseChallengeResult_.resultCode = ResultState::RESULT_OK;
    responseChallengeResult_.response = OHOS::Telephony::ToUtf16(strResult);
    {
        std::lock_guard<std::mutex> lock(euiccChallengeMutex_);
        areEuiccChallengeReady_ = true;
    }
    euiccChallengeCv_.notify_one();
    return isFileHandleResponse;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEUICCChallengeDone(event); };
    memberFuncMap_[MSG_ESIM_REQUEST_RULES_AUTH_TABLE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessRequestRulesAuthTableDone(event); };
    memberFuncMap_[MSG_ESIM_OBTAIN_SMDS_ADDRESS] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainSmdsAddressDone(event); };
    memberFuncMap_[MSG_ESIM_DISABLE_PROFILE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessDisableProfileDone(event); };
}
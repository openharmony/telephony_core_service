ResponseEsimResult EsimFile::ObtainPrepareDownload(int32_t portIndex, std::u16string hashCc,
    std::u16string smdpSigned2, std::u16string smdpSignature2, std::u16string smdpCertificate)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.hashCc = hashCc;
    esimProfile_.smdpSigned2 = smdpSigned2;
    esimProfile_.smdpSignature2 = smdpSignature2;
    esimProfile_.smdpCertificate = smdpCertificate;
    SyncOpenChannel();
    recvCombineStr_ = "";
    if (!ProcessPrepareDownload(slotId_)) {
        TELEPHONY_LOGE("ProcessPrepareDownload encode failed");
        return ResponseEsimResult();
    }
    arePrepareDownloadReady_ = false;
    std::unique_lock<std::mutex> lock(prepareDownloadMutex_);
    if (!prepareDownloadCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return arePrepareDownloadReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return preDownloadResult_;
}

ResponseEsimBppResult EsimFile::ObtainLoadBoundProfilePackage(int32_t portIndex, std::u16string boundProfilePackage)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.boundProfilePackage = boundProfilePackage;
    SyncOpenChannel();
    recvCombineStr_ = "";
    areLoadBppReady_ = false;
    if (!ProcessLoadBoundProfilePackage(slotId_)) {
        TELEPHONY_LOGE("ProcessLoadBoundProfilePackage encode failed");
        return ResponseEsimBppResult();
    }
    std::unique_lock<std::mutex> lock(loadBppMutex_);
    if (!loadBppCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areLoadBppReady_; })) {
        SyncCloseChannel();
        return ResponseEsimBppResult();
    }
    SyncCloseChannel();
    return loadBPPResult_;
}

EuiccNotificationList EsimFile::ListNotifications(int32_t portIndex, Event events)
{
    esimProfile_.portIndex = portIndex;
    esimProfile_.events = events;
    AppExecFwk::InnerEvent::Pointer eventListNotif = BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    SyncOpenChannel();
    if (!ProcessListNotifications(slotId_, Event::EVENT_ENABLE, eventListNotif)) {
        TELEPHONY_LOGE("ProcessListNotifications encode failed");
        return EuiccNotificationList();
    }
    areListNotificationsReady_ = false;
    std::unique_lock<std::mutex> lock(listNotificationsMutex_);
    if (!listNotificationsCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return areListNotificationsReady_; })) {
        SyncCloseChannel();
        return EuiccNotificationList();
    }
    SyncCloseChannel();
    return eUiccNotificationList_;
}

bool EsimFile::ProcessPrepareDownload(int32_t slotId)
{
    if (IsLogicChannelOpen()) {
        PrepareDownloadResp dst;
        ConvertPreDownloadParaFromApiStru(dst, esimProfile_);
        EsimProfile *profile = &esimProfile_;
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_PREPARE_DOWNLOAD);
        Asn1AddChildAsBase64(builder, dst.smdpSigned2);
        Asn1AddChildAsBase64(builder, dst.smdpSignature2);
        if (dst.hashCc.size() != 0) {
            std::string bytes = VCardUtils::DecodeBase64(dst.hashCc);
            int32_t byteLen = bytes.length();
            builder->Asn1AddChildAsBytes(TAG_ESIM_OCTET_STRING_TYPE, bytes, byteLen);
        }
        Asn1AddChildAsBase64(builder, dst.smdpCertificate);
        int hexStrLen = 0;
        std::string hexStr;
        hexStrLen = builder->Asn1BuilderToHexStr(hexStr);
        SplitSendLongData(slotId, hexStr);
        return true;
    }
    return false;
}

bool EsimFile::ProcessPrepareDownloadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        return false;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return false;
    }
    IccFileData &iccFileData = rcvMsg->fileData;
    if(!MergeRecvLongDataComplete(iccFileData))
    {
        return true;
    }
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(recvCombineStr_);
    int32_t byteLen = responseByte.length();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    std::shared_ptr<Asn1Node> childNode = root->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    if (childNode != nullptr) {
        std::shared_ptr<Asn1Node> errCodeNode = childNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
        if (errCodeNode != nullptr) {
            int protocolErr = errCodeNode->Asn1AsInteger();
            if (protocolErr != TELEPHONY_ERR_ARGUMENT_INVALID) {
                TELEPHONY_LOGE("Prepare download error, es10x errcode: %d", protocolErr);
                return false;
            }
        }
    }
    preDownloadResult_.resultCode = ResultState::RESULT_OK;
    std::string destString = VCardUtils::EncodeBase64(responseByte);
    preDownloadResult_.response = OHOS::Telephony::ToUtf16(destString);
    {
        std::lock_guard<std::mutex> lock(prepareDownloadMutex_);
        arePrepareDownloadReady_ = true;
    }
    prepareDownloadCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::DecodeBoundProfilePackage(const std::string& boundProfilePackageStr, std::shared_ptr<Asn1Node> &bppNode)
{
    int32_t byteLen = 0;
    std::string destString = VCardUtils::DecodeBase64(boundProfilePackageStr);
    byteLen = destString.length();
    std::shared_ptr<Asn1Decoder> decoder = std::make_shared<Asn1Decoder>(destString, 0, byteLen);
    if (decoder == nullptr) {
        TELEPHONY_LOGE("decoder is nullptr");
        return false;
    }
    bppNode = decoder->Asn1NextNode();
    if (bppNode == nullptr) {
        TELEPHONY_LOGE("bppNode is nullptr");
        return false;
    }
    return true;
}

void EsimFile::BuildApduForInitSecureChannel(
    RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &initSecureChannelReq)
{
    std::string hexStr;
    std::string destStr;
    int cursorLen = 0;
    cursorLen = bppNode->Asn1GetHeadAsHexStr(hexStr);
    cursorLen += initSecureChannelReq->Asn1NodeToHexStr(destStr);
    hexStr += destStr;
    codec.BuildStoreData(hexStr);
}

void EsimFile::BuildApduForFirstSequenceOf87(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &firstSequenceOf87)
{
    int cursorLen = 0;
    std::string hexStr;
    cursorLen = firstSequenceOf87->Asn1NodeToHexStr(hexStr);
    codec.BuildStoreData(hexStr);
}

void EsimFile::BuildApduForSequenceOf88(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &sequenceOf88)
{
    int cursorLen = 0;
    std::list<std::shared_ptr<Asn1Node>> metaDataSeqs;
    int metaDataRes = sequenceOf88->Asn1GetChildren(TAG_ESIM_CTX_8, metaDataSeqs);
    if (metaDataRes != 0) {
        return;
    }
    std::string hexStr;
    cursorLen = sequenceOf88->Asn1GetHeadAsHexStr(hexStr);
    codec.BuildStoreData(hexStr);
    std::shared_ptr<Asn1Node> curNode = nullptr;
    for(auto it = metaDataSeqs.begin(); it != metaDataSeqs.end(); ++it)
    {
        curNode = *it;
        curNode->Asn1NodeToHexStr(hexStr);
        codec.BuildStoreData(hexStr);
    }
}

void EsimFile::BuildApduForSequenceOf86(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &sequenceOf86)
{
    int cursorLen = 0;
    std::string hexStr;
    std::list<std::shared_ptr<Asn1Node>> elementSeqs;
    int elementRes = sequenceOf86->Asn1GetChildren(TAG_ESIM_CTX_6, elementSeqs);
    if (elementRes != 0) {
        TELEPHONY_LOGE("sequenceOf86 encode error");
        return;
    }
    bool isHasChild = bppNode->Asn1HasChild(TAG_ESIM_CTX_COMP_2);
    if (isHasChild) {
        std::shared_ptr<Asn1Node> pGetChild = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_2);
        if (pGetChild == nullptr) {
            TELEPHONY_LOGE("pGetChild is nullptr");
            return;
        }
        pGetChild->Asn1NodeToHexStr(hexStr);
        codec.BuildStoreData(hexStr);
    }
    cursorLen = sequenceOf86->Asn1GetHeadAsHexStr(hexStr);
    codec.BuildStoreData(hexStr);
    std::shared_ptr<Asn1Node> curNode = nullptr;
    for(auto it = elementSeqs.begin(); it != elementSeqs.end(); ++it)
    {
        curNode = *it;
        curNode->Asn1NodeToHexStr(hexStr);
        codec.BuildStoreData(hexStr);
    }
}

bool EsimFile::ProcessLoadBoundProfilePackage(int32_t slotId)
{
    if (!IsLogicChannelOpen()) {
        TELEPHONY_LOGE("open channel is failed");
        return false;
    }
    std::string boundProfilePackage = OHOS::Telephony::ToUtf8(esimProfile_.boundProfilePackage);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    if (!DecodeBoundProfilePackage(boundProfilePackage, bppNode)) {
        TELEPHONY_LOGE("DecodeBoundProfilePackage failed");
        return false;
    }
    RequestApduBuild codec(currentChannelId);
    std::shared_ptr<Asn1Node> initSecureChannelReq = bppNode->Asn1GetChild(TAG_ESIM_INITIALISE_SECURE_CHANNEL);
    if (initSecureChannelReq != nullptr) {
        BuildApduForInitSecureChannel(codec, bppNode, initSecureChannelReq);
    }
    std::shared_ptr<Asn1Node> firstSequenceOf87 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (firstSequenceOf87 != nullptr) {
        BuildApduForFirstSequenceOf87(codec, firstSequenceOf87);
    }
    std::shared_ptr<Asn1Node> sequenceOf88 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    if (sequenceOf88 != nullptr) {
        BuildApduForSequenceOf88(codec, sequenceOf88);
    }
    std::shared_ptr<Asn1Node> sequenceOf86 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_3);
    if (sequenceOf86 != nullptr) {
        BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
    }
    std::list<std::unique_ptr<ApduCommand>> apduCommandList = codec.getCommands();
    for (const auto &cmd : apduCommandList) {
        ApduSimIORequestInfo reqInfo;
        CopyApdCmdToReqInfo(&reqInfo, cmd.get());
        AppExecFwk::InnerEvent::Pointer responseEvent = BuildCallerInfo(MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
    }
    return true;
}

bool EsimFile::ProcessLoadBoundProfilePackageDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    IccFileData &iccFileData = rcvMsg->fileData;
    if(!MergeRecvLongDataComplete(iccFileData))
    {
        return true;
    }
    return RealProcessLoadBoundProfilePackageDone(recvCombineStr_);
}

bool EsimFile::RealProcessLoadBoundProfilePackageDone(std::string combineHexStr)
{
    std::string responseByte = Asn1Utils::HexStrToBytes(combineHexStr);
    int32_t byteLen = responseByte.length();
    loadBPPResult_.response = OHOS::Telephony::ToUtf16(combineHexStr);
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return false;
    }
    std::shared_ptr<Asn1Node> nodeNotificationMetadata = LoadBoundProfilePackageParseProfileInstallResult(root);
    if (nodeNotificationMetadata == nullptr) {
        {
            std::lock_guard<std::mutex> lock(loadBppMutex_);
            areLoadBppReady_ = true; 
        }
        loadBppCv_.notify_one();
        return false;
    }
    if (!LoadBoundProfilePackageParseNotificationMetadata(nodeNotificationMetadata)) {
        {
            std::lock_guard<std::mutex> lock(loadBppMutex_);
            areLoadBppReady_ = true; 
        }
        loadBppCv_.notify_one();
        return false;
    }
    loadBPPResult_.resultCode = 0;
    {
        std::lock_guard<std::mutex> lock(loadBppMutex_);
        areLoadBppReady_ = true; 
    }
    loadBppCv_.notify_one();
    return true;
}

bool EsimFile::LoadBoundProfilePackageParseNotificationMetadata(std::shared_ptr<Asn1Node> &notificationMetadata)
{
    if (notificationMetadata == nullptr) {
        TELEPHONY_LOGE("notification metadata is empty");
        return false;
    }
    std::shared_ptr<Asn1Node> sequenceNumberAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_CTX_0);
    if (sequenceNumberAsn != NULL) {
        loadBPPResult_.seqNumber = sequenceNumberAsn->Asn1AsInteger();
    } else {
        TELEPHONY_LOGE("sequenceNumber tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> profileManagementOpAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_CTX_1);
    if (profileManagementOpAsn != NULL) {
        loadBPPResult_.profileManagementOperation = EVENT_INSTALL;
    } else {
        TELEPHONY_LOGE("profileManagementOperation tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> addressAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_TARGET_ADDR);
    if (addressAsn != NULL) {
        std::string hexString;
        int len = addressAsn->Asn1AsString(hexString);
        std::string address = Asn1Utils::HexStrToString(hexString);
        loadBPPResult_.notificationAddress = OHOS::Telephony::ToUtf16(address);
    } else {
        TELEPHONY_LOGE("notificationAddress tag missing");
        return false;
    }
    std::shared_ptr<Asn1Node> iccidAsn = notificationMetadata->Asn1GetChild(TAG_ESIM_EID);
    if (iccidAsn == nullptr) {
        TELEPHONY_LOGE("iccidAsn is nullptr");
        return false;
    }
    std::string iccid;
    std::string iccString;
    int iccidLen = iccidAsn->Asn1AsBytes(iccid);
    Asn1Utils::BchToString(iccid, iccString);
    loadBPPResult_.iccId = OHOS::Telephony::ToUtf16(iccString);
    return true;
}

std::shared_ptr<Asn1Node> EsimFile::LoadBoundProfilePackageParseProfileInstallResult(std::shared_ptr<Asn1Node> &root)
{
    if (root == nullptr) {
        TELEPHONY_LOGE("failed to parse load BPP file response");
        return NULL;
    }
    std::shared_ptr<Asn1Node> resultData = root->Asn1GetChild(TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA);
    if (resultData == nullptr) {
        TELEPHONY_LOGE("failed to find ProfileInstallationResult tag");
        return NULL;
    }
    std::shared_ptr<Asn1Node> errNode = resultData->Asn1GetChildChild(3, TAG_ESIM_CTX_COMP_2, TAG_ESIM_CTX_COMP_1, TAG_ESIM_CTX_1);
    if (errNode != nullptr) {
        int errCode = errNode->Asn1AsInteger();
        loadBPPResult_.resultCode = errCode;
        return NULL;
    }
    std::shared_ptr<Asn1Node> notificationMetadataAsn = resultData->Asn1GetChild(TAG_ESIM_NOTIFICATION_METADATA);
    if (notificationMetadataAsn == nullptr) {
        TELEPHONY_LOGE("extProfileInstallRsp: failed to find finalResult tag");
        return NULL;
    }
    return notificationMetadataAsn;
}

bool EsimFile::ProcessListNotifications(
    int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_LIST_NOTIFICATION);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        builder->Asn1AddChildAsBits(TAG_ESIM_CTX_1, (int)events);
        ApduSimIORequestInfo reqInfo;
        CommBuildOneApduReqInfo(reqInfo, builder);
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        return true;
    }
    return false;
}

void EsimFile::createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification& euicc)
{
    if (node == nullptr) {
        TELEPHONY_LOGE("createNotification node is nullptr");
        return;
    }
    std::shared_ptr<Asn1Node> metadataNode;
    if (node->GetNodeTag() == TAG_ESIM_NOTIFICATION_METADATA) {
        metadataNode = node;
    } else if (node->GetNodeTag() == TAG_ESIM_PROFILE_INSTALLATION_RESULT) {
        std::shared_ptr<Asn1Node> findNode = node->Asn1GetChildChild(2, TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA, TAG_ESIM_NOTIFICATION_METADATA);
        metadataNode = findNode;
    } else {
        // Other signed notification
        std::shared_ptr<Asn1Node> findNode = node->Asn1GetChild(TAG_ESIM_NOTIFICATION_METADATA);
        metadataNode = findNode;
    }
    if (metadataNode == nullptr) {
        TELEPHONY_LOGE("metadataNode is nullptr");
        return;
    }
    std::shared_ptr<Asn1Node> nodeSeq = metadataNode->Asn1GetChild(TAG_ESIM_SEQ);
    if (nodeSeq == nullptr) {
        TELEPHONY_LOGE("nodeSeq is nullptr");
        return;
    }
    euicc.seq = nodeSeq->Asn1AsInteger();

    std::shared_ptr<Asn1Node> nodeTargetAddr = metadataNode->Asn1GetChild(TAG_ESIM_TARGET_ADDR);
    if (nodeTargetAddr == nullptr) {
        TELEPHONY_LOGE("nodeTargetAddr is nullptr");
        return;
    }
    std::string strResult;
    nodeTargetAddr->Asn1AsBytes(strResult);
    euicc.targetAddr = OHOS::Telephony::ToUtf16(strResult);

    std::shared_ptr<Asn1Node> nodeEvent = metadataNode->Asn1GetChild(TAG_ESIM_EVENT);
    if (nodeEvent == nullptr) {
        TELEPHONY_LOGE("nodeEvent is nullptr");
        return;
    }
    euicc.event = nodeEvent->Asn1AsBits();

    std::string strmData;
    node->Asn1NodeToHexStr(strmData);
    euicc.data = node->GetNodeTag() == TAG_ESIM_NOTIFICATION_METADATA ? u"" : OHOS::Telephony::ToUtf16(strmData);
}

bool EsimFile::ProcessListNotificationsAsn1Response(std::shared_ptr<Asn1Node> root, bool &isFileHandleResponse)
{
    if (root->Asn1HasChild(TAG_ESIM_CTX_1)) {
        TELEPHONY_LOGE("child is nullptr");
        return isFileHandleResponse;
    }
    std::list<std::shared_ptr<Asn1Node>> ls;
    std::shared_ptr<Asn1Node> compTag = root->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    if (compTag == nullptr) {
        TELEPHONY_LOGE("compTag is nullptr");
        return isFileHandleResponse;
    }
    int metaDataRes = compTag->Asn1GetChildren(TAG_ESIM_NOTIFICATION_METADATA, ls);
    if (metaDataRes != 0) {
        TELEPHONY_LOGE("metaDataTag is zero");
        return isFileHandleResponse;
    }
    std::shared_ptr<Asn1Node> curNode = NULL;
    EuiccNotificationList euiccList;
    for(auto it = ls.begin(); it != ls.end(); ++it)
    {
        curNode = *it;
        EuiccNotification euicc;
        createNotification(curNode, euicc);
        euiccList.euiccNotification.push_back(euicc);
    }
    eUiccNotificationList_ = euiccList;
    {
        std::lock_guard<std::mutex> lock(listNotificationsMutex_);
        areListNotificationsReady_ = true;
    }
    listNotificationsCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessListNotificationsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = false;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr");
        return isFileHandleResponse;
    }
    std::unique_ptr<IccFromRilMsg> rcvMsg = event->GetUniqueObject<IccFromRilMsg>();
    if (rcvMsg == nullptr) {
        TELEPHONY_LOGE("rcvMsg is nullptr");
        return isFileHandleResponse;
    }
    IccFileData *result = &(rcvMsg->fileData);
    std::string responseByte;
    responseByte = Asn1Utils::HexStrToBytes(result->resultData);
    int32_t byteLen = responseByte.length();
    if (byteLen == 0) {
        TELEPHONY_LOGE("byteLen is zero");
        return isFileHandleResponse;
    }
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        TELEPHONY_LOGE("root is nullptr");
        return isFileHandleResponse;
    }

    if (!ProcessListNotificationsAsn1Response(root, isFileHandleResponse)) {
        return isFileHandleResponse;
    }
    return true;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_LIST_NOTIFICATION] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessListNotificationsDone(event); };
    memberFuncMap_[MSG_ESIM_LOAD_BOUND_PROFILE_PACKAGE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessLoadBoundProfilePackageDone(event); };
    memberFuncMap_[MSG_ESIM_PREPARE_DOWNLOAD_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessPrepareDownloadDone(event); };
}

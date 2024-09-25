

ResultState EsimFile::ResetMemory(ResetOption resetOption)
{
    esimProfile_.option = resetOption;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventResetMemory = BuildCallerInfo(MSG_ESIM_RESET_MEMORY);
    if (!ProcessResetMemory(slotId_, eventResetMemory)) {
        TELEPHONY_LOGE("ProcessResetMemory encode failed");
        return ResultState();
    }
    isResetMemoryReady_ = false;
    std::unique_lock<std::mutex> lock(resetMemoryMutex_);
    if (!resetMemoryCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isResetMemoryReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return resetResult_;
}

ResultState EsimFile::SetDefaultSmdpAddress(std::u16string defaultSmdpAddress)
{
    esimProfile_.defaultSmdpAddress = defaultSmdpAddress;
    SyncOpenChannel();
    AppExecFwk::InnerEvent::Pointer eventSetSmdpAddress = BuildCallerInfo(MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE);
    if (!ProcessEstablishDefaultSmdpAddress(slotId_, eventSetSmdpAddress)) {
        TELEPHONY_LOGE("ProcessEstablishDefaultSmdpAddress encode failed!!");
        return ResultState();
    }
    isSetDefaultSmdpAddressReady_ = false;
    std::unique_lock<std::mutex> lock(setDefaultSmdpAddressMutex_);
    if (!setDefaultSmdpAddressCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSetDefaultSmdpAddressReady_; })) {
        SyncCloseChannel();
        return ResultState();
    }
    SyncCloseChannel();
    return setDpAddressResult_;
}

bool EsimFile::IsEsimSupported()
{
    char buf[ATR_LENGTH + 1] = {0};
    const std::string ATR_PROP = "gsm.sim.hw_atr";
    GetParameter(ATR_PROP.c_str(), "", buf, ATR_LENGTH);
    ResetResponse resetResponse;
    std::string atr(buf);
    resetResponse.AnalysisAtrData(atr);
    isSupported_ = resetResponse.IsEuiccAvailable();
    return isSupported_;
}

ResponseEsimResult EsimFile::SendApduData(std::u16string aid, std::u16string apduData)
{
    esimProfile_.aid = aid;
    esimProfile_.apduData = apduData;
    SyncOpenChannel(aid);
    AppExecFwk::InnerEvent::Pointer eventSendApduData = BuildCallerInfo(MSG_ESIM_SEND_APUD_DATA);
    if (!ProcessSendApduData(slotId_, eventSendApduData)) {
        TELEPHONY_LOGE("ProcessSendApduData encode failed");
        return ResponseEsimResult();
    }
    std::unique_lock<std::mutex> lock(SendApduDataMutex_);
    if (!SendApduDataCv_.wait_for(lock, std::chrono::seconds(WAIT_TIME_LONG_SECOND_FOR_ESIM),
        [this]() { return isSendApduDataReady_; })) {
        SyncCloseChannel();
        return ResponseEsimResult();
    }
    SyncCloseChannel();
    return transApduDataResponse_;
}

bool EsimFile::ProcessResetMemory(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_EUICC_MEMORY_RESET);
        if (builder == nullptr) {
            TELEPHONY_LOGE("get builder failed");
            return false;
        }
        std::string resetMemoryTags;
        resetMemoryTags += (unsigned char)EUICC_MEMORY_RESET_BIT_STR_FILL_LEN;
        resetMemoryTags += (unsigned char)EUICC_MEMORY_RESET_BIT_STR_VALUE;
        builder->Asn1AddChildAsBytes(TAG_ESIM_CTX_2, resetMemoryTags, resetMemoryTags.length());
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

bool EsimFile::ProcessResetMemoryDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    resetResult_ = (ResultState)pAsn1Node->Asn1AsInteger();
    {
        std::lock_guard<std::mutex> lock(resetMemoryMutex_);
        isResetMemoryReady_ = true;
    }
    resetMemoryCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::setDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_SET_DEFAULT_SMDP_ADDRESS);
        if (builder == nullptr) {
            TELEPHONY_LOGE("builder is nullptr");
            return false;
        }
        builder->Asn1AddChildAsString(TAG_ESIM_TARGET_ADDR, defaultDpAddress_);
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

bool EsimFile::setDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    setDpAddressResult_ = (ResultState)pAsn1Node->Asn1AsInteger();
    {
        std::lock_guard<std::mutex> lock(setDefaultSmdpAddressMutex_);
        isSetDefaultSmdpAddressReady_ = true;
    }
    setDefaultSmdpAddressCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessSendApduData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent)
{
    if (IsLogicChannelOpen()) {
        EsimProfile *profile = &esimProfile_;
        std::string hexStr = OHOS::Telephony::ToUtf8(profile->toBeSendApduDataHexStr);
        RequestApduBuild codec(currentChannelId);
        codec.BuildStoreData(hexStr);
        std::list<std::unique_ptr<ApduCommand>> lst = codec.getCommands();
        std::unique_ptr<ApduCommand> apdCmd = std::move(lst.front());
        ApduSimIORequestInfo reqInfo;
        CopyApdCmdToReqInfo(&reqInfo, apdCmd.get());
        if (telRilManager_ == nullptr) {
            return false;
        }
        telRilManager_->SimTransmitApduLogicalChannel(slotId, reqInfo, responseEvent);
        return true;
    }
    return false;
}

bool EsimFile::ProcessSendApduDataDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    IccFileData *result = &(rcvMsg->fileData);
    transApduDataResponse_.resultCode = ResultState::RESULT_OK;
    transApduDataResponse_.response = OHOS::Telephony::ToUtf16(rcvMsg->fileData.resultData);

    {
        std::lock_guard<std::mutex> lock(SendApduDataMutex_);
        isSendApduDataReady_ = true;
    }
    SendApduDataCv_.notify_one();
    return isFileHandleResponse;
}

bool EsimFile::ProcessObtainEUICCSupportDone(const AppExecFwk::InnerEvent::Pointer &event)
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
    return isFileHandleResponse;
}

void EsimFile::InitMemberFunc()
{
    memberFuncMap_[MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessEstablishDefaultSmdpAddressDone(event); };
    memberFuncMap_[MSG_ESIM_RESET_MEMORY] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessResetMemoryDone(event); };
    memberFuncMap_[MSG_ESIM_SEND_APUD_DATA] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessSendApduDataDone(event); };
    memberFuncMap_[MSG_ESIM_IS_ESIM_SUPPORT] =
        [this](const AppExecFwk::InnerEvent::Pointer &event) { return ProcessObtainEUICCSupportDone(event); };  
}
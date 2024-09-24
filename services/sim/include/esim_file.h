    std::string ObtainDefaultSmdpAddress();
    ResponseEsimResult CancelSession(const std::u16string &transactionId, CancelReason cancelReason);
    EuiccProfile ObtainProfile(int32_t portIndex, const std::u16string &iccId);

private:
    bool ProcessObtainDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessCancelSession(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessCancelSessionDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessGetProfileDone(const AppExecFwk::InnerEvent::Pointer &event);

    EsimProfile esimProfile_;
    std::string defaultDpAddress_ = "";
    EuiccProfile euiccProfile_;
    ResponseEsimResult cancelSessionResult_;

    std::mutex obtainDefaultSmdpAddressMutex_;
    std::condition_variable obtainDefaultSmdpAddressCv_;
    bool areObtainDefaultSmdpAddressReady_ = false;
    
    std::mutex cancelSessionMutex_;
    std::condition_variable cancelSessionCv_;
    bool areCancelSessionReady_ = false;

    std::mutex obtainProfileMutex_;
    std::condition_variable obtainProfileCv_;
    bool areObtainProfileReady_ = false;

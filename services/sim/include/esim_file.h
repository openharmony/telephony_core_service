ResultState DisableProfile(int32_t portIndex, std::u16string iccId);
std::string ObtainSmdsAddress(int32_t portIndex);
EuiccRulesAuthTable ObtainRulesAuthTable(int32_t portIndex);
ResponseEsimResult ObtainEuiccChallenge(int32_t portIndex);
bool ProcessObtainEUICCChallenge(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessObtainEUICCChallengeDone(const AppExecFwk::InnerEvent::Pointer &event);
bool ProcessDisableProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessDisableProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
bool ProcessObtainSmdsAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessObtainSmdsAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
bool ProcessRequestRulesAuthTable(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessRequestRulesAuthTableDone(const AppExecFwk::InnerEvent::Pointer &event);
bool RequestRulesAuthTableParseTagCtxComp0(std::shared_ptr<Asn1Node> &root);

protected:
    std::string smdsAddress_ = "";
    EuiccRulesAuthTable eUiccRulesAuthTable_;
    ResultState disableProfileResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResponseEsimResult responseChallengeResult_;

private:
    std::mutex disableProfileMutex_;
    std::condition_variable disableProfileCv_;
    bool areDisableProfileReady_ = false;

    std::mutex smdsAddressMutex_;
    std::condition_variable smdsAddressCv_;
    bool areSmdsAddressReady_ = false;

    std::mutex rulesAuthTableMutex_;
    std::condition_variable rulesAuthTableCv_;
    bool areRulesAuthTableReady_ = false;

    std::mutex euiccChallengeMutex_;
    std::condition_variable euiccChallengeCv_;
    bool areEuiccChallengeReady_ = false;
ResponseEsimResult ObtainPrepareDownload(int32_t portIndex, std::u16string hashCc,
    std::u16string smdpSigned2, std::u16string smdpSignature2, std::u16string smdpCertificate);
ResponseEsimBppResult ObtainLoadBoundProfilePackage(int32_t portIndex, std::u16string boundProfilePackage);
EuiccNotificationList ListNotifications(int32_t portIndex, Event events);
bool ProcessPrepareDownload(int32_t slotId);
bool ProcessPrepareDownloadDone(const AppExecFwk::InnerEvent::Pointer &event);
bool DecodeBoundProfilePackage(const std::string& boundProfilePackageStr, std::shared_ptr<Asn1Node> &bppNode);
void BuildApduForInitSecureChannel(
    RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &initSecureChannelReq);
void BuildApduForFirstSequenceOf87(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &firstSequenceOf87);
void BuildApduForSequenceOf88(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &sequenceOf88);
void BuildApduForSequenceOf86(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &sequenceOf86);
bool ProcessLoadBoundProfilePackage(int32_t slotId);
bool ProcessLoadBoundProfilePackageDone(const AppExecFwk::InnerEvent::Pointer &event);
std::shared_ptr<Asn1Node> LoadBoundProfilePackageParseProfileInstallResult(std::shared_ptr<Asn1Node> &root);
bool LoadBoundProfilePackageParseNotificationMetadata(std::shared_ptr<Asn1Node> &notificationMetadata);
bool RealProcessLoadBoundProfilePackageDone(std::string combineHexStr);
bool ProcessListNotifications(
    int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessListNotificationsDone(const AppExecFwk::InnerEvent::Pointer &event);
void createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification& euicc);
bool ProcessListNotificationsAsn1Response(std::shared_ptr<Asn1Node> root, bool &isFileHandleResponse);

protected:
    ResponseEsimResult preDownloadResult_;
    ResponseEsimBppResult loadBPPResult_;
    EuiccNotificationList eUiccNotificationList_;

private:
    std::mutex prepareDownloadMutex_;
    std::condition_variable prepareDownloadCv_;
    bool arePrepareDownloadReady_ = false;

    std::mutex loadBppMutex_;
    std::condition_variable loadBppCv_;
    bool areLoadBppReady_ = false;

    std::mutex listNotificationsMutex_;
    std::condition_variable listNotificationsCv_;
    bool areListNotificationsReady_ = false;
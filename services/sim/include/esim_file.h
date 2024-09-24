void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
EuiccNotificationList RetrieveNotificationList(int32_t portIndex, Event events);
EuiccNotification ObtainRetrieveNotification(int32_t portIndex, int32_t seqNumber);
ResultState RemoveNotificationFromList(int32_t portIndex, int32_t seqNumber);
bool ProcessRetrieveNotificationList(
    int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessRetrieveNotificationListDone(const AppExecFwk::InnerEvent::Pointer &event);
bool RetrieveNotificationParseCompTag(std::shared_ptr<Asn1Node> &root);
bool ProcessRetrieveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessRetrieveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event);
bool RetrieveNotificatioParseTagCtxComp0(std::shared_ptr<Asn1Node> &root);
bool ProcessRemoveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessRemoveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event);

ResultState removeNotifResult_ = ResultState::RESULT_UNDEFINED_ERROR;
EuiccNotificationList eUiccNotificationList_;
EuiccNotificationList retrieveNotificationList_;

std::mutex retrieveNotificationListMutex_;
std::condition_variable retrieveNotificationListCv_;
bool areRetrieveNotificationListReady_ = false;

std::mutex retrieveNotificationMutex_;
std::condition_variable retrieveNotificationCv_;
bool areRetrieveNotificationReady_ = false;

std::mutex removeNotificationMutex_;
std::condition_variable removeNotificationCv_;
bool areRemoveNotificationReady_ = false;
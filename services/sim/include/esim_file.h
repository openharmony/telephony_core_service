constexpr static const int32_t ATR_LENGTH = 47;

ResultState ResetMemory(ResetOption resetOption);
ResultState SetDefaultSmdpAddress(std::u16string defaultSmdpAddress);
bool IsEsimSupported();
ResponseEsimResult SendApduData(std::u16string aid, std::u16string apduData);
bool ProcessResetMemory(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessResetMemoryDone(const AppExecFwk::InnerEvent::Pointer &event);
bool setDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool setDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
bool ProcessSendApduData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
bool ProcessSendApduDataDone(const AppExecFwk::InnerEvent::Pointer &event);
bool ProcessObtainEUICCSupportDone(const AppExecFwk::InnerEvent::Pointer &event);

ResultState resetResult_ = ResultState::RESULT_UNDEFINED_ERROR;
ResultState setDpAddressResult_ = ResultState::RESULT_UNDEFINED_ERROR;
ResponseEsimResult transApduDataResponse_;
bool isSupported_ = false;

std::mutex resetMemoryMutex_;
std::condition_variable resetMemoryCv_;
bool isResetMemoryReady_ = false;

std::mutex setDefaultSmdpAddressMutex_;
std::condition_variable setDefaultSmdpAddressCv_;
bool isSetDefaultSmdpAddressReady_ = false;

std::mutex SendApduDataMutex_;
std::condition_variable SendApduDataCv_;
bool isSendApduDataReady_ = false;
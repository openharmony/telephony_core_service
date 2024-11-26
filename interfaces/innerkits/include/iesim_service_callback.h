#ifndef IESIM_SERVICE_CALLBACK_H
#define IESIM_SERVICE_CALLBACK_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Telephony {
class IEsimServiceCallback : public IRemoteBroker {
public:
    virtual ~IEsimServiceCallback() = default;
	enum class EsimServiceCallback {
        GET_EUICCINFO_RESULT = 0,
		GET_DOWNLOADABLE_PROFILE_METADATA_RESULT,
		GET_DOWNLOADABLE_PROFILES_RESULT,
		GET_EUICC_PROFILE_INFO_LIST_RESULT,
		GET_DEFAULT_SMDP_ADDRESS_RESULT,
		SET_DEFAULT_SMDP_ADDRESS_RESULT,
		SET_PROFILE_NICKNAME_RESULT,
		CANCEL_SESSION_CALLBACK_RESULT,
		DOWNLOAD_PROFILE_RESULT,
		DELETE_PROFILE_RESULT,
		START_OSU_RESULT,
		SWITCH_PROFILE_RESULT,
		RESET_MEMORY_RESULT,
    };
    virtual int32_t OnEsimServiceCallback(EsimServiceCallback requestId, MessageParcel &data) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.IEsimServiceCallback");
};
}
}
#endif
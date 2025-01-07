# Telephony Core Service<a name="EN-US_TOPIC_0000001152064913"></a>

-   [Introduction](#section117mcpsimp)
-   [Directory Structure](#section129mcpsimp)
-   [Constraints](#section133mcpsimp)
-   [Available APIs](#section139mcpsimp)
    -   [SimManager APIs](#section142mcpsimp)
    -   [NetworkSearchManager APIs](#section198mcpsimp)

-   [Usage Guidelines](#section370mcpsimp)
    -   [Network Search](#section393mcpsimp)
    -   [SIM Card Management](#section402mcpsimp)

-   [Repositories Involved](#section409mcpsimp)
a
## Introduction<a name="section117mcpsimp"></a>

The telephony core service initializes the SimManager, NetworkSearchManager, and TelRilManager modules, and provides access to the RIL Adapter service.

You can implement communication with the RIL Adapter by registering the callback service and implement communication between modules by subscribing to callbacks.

**Figure  1**  Architecture of the telephony core service<a name="fig5700192716219"></a>


 ![](figures/en-us_architecture-of-the-core_service-module.png)

As shown in the preceding figure, the telephony core service consists of the following:

-   SimManager: provides services including SIM card initialization, file read/write, loading status notification, and single-SIM/dual-SIM control. These services implement functions such as SIM card status query, SIM card management, SIM card control, STK, contact storage, and SMS storage.
-   NetworkSearchManager: provides services including network registration and network status acquisition. These services offer functions such as network registration, network mode query, IMS network status reporting, radio service status query, radio service management, signal strength query, cell management, registration status management, and time and time zone setting.
-   TelRilManager: provides the proactive callback service and query result callback service.

## Directory Structure<a name="section129mcpsimp"></a>

```sh
/base/telphony/core_service
├── figures                       # Figures of readme files
├── frameworks                    # Framework layer
│   ├── js
│   └── native
├── interfaces                    # APIs
│   ├── innerkits                 # Internal APIs
|   |    ├── ims                  # IMS network status reporting APIs
│   └── kits                      # External APIs \(such as JS APIs\)
├── sa_profile                    # SA profile
├── services                      # Implementation of the telephony core service
│   ├── etc                       # Telephony core service driver scripts
|   ├── ims_service_interaction   # IMS service interaction (for status reporting)
│   ├── include
│   ├── network_search            # Network search service
│   ├── sim                       # SIM card service
│   ├── src
│   └── tel_ril                   # Telephony core service and RIL Adapter communication
├─ test                            # Test code
│   └── unittest
└── utils
    ├── common                    # Telephony core service log
    ├── log
    └── preferences
```

## Constraints<a name="section133mcpsimp"></a>

-   Programming language: C++ and JavaScript.
-   Software constraints: This module must work with the HDF (drivers\_interface and drivers\_peripheral), RIL Adapter service \(ril\_adapter\), and state registry service \(state\_registry\).
-   Hardware constraints: The accommodating device must be equipped with a modem and a SIM card capable of independent cellular communication.

## Available APIs<a name="section139mcpsimp"></a>

The telephony core service module needs to provide APIs for related modules, including the SIM card and radio modules.

###  SimManager APIs<a name="section142mcpsimp"></a>

| Name                                                    | Description                                                   | Required Permission                           |
| ------------------------------------------------------------ | ----------------------------------------------------------- | ----------------------------------- |
| function getSimState(slotId: number, callback: AsyncCallback\<SimState>): void; | Obtains the state of the SIM card in a specified slot.                                    | –                                 |
| function getSimGid1(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the group identifier level 1 \(GID1\) of the SIM card in the specified slot.          | ohos.permission.GET_TELEPHONY_STATE |
| function getSimIccId(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the integrated circuit card identity \(ICCID\) of the SIM card in the specified slot.| ohos.permission.GET_TELEPHONY_STATE |
| function getISOCountryCodeForSim(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the ISO country code of the SIM card in the specified slot.                               | –                                 |
| function getSimOperatorNumeric(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the public land mobile network \(PLMN\) ID of the SIM card in the specified slot. | –                                 |
| function getSimSpn(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the service provider name \(SPN\) of the SIM card in the specified slot.      | –                                 |
| function getDefaultVoiceSlotId(callback: AsyncCallback\<number>): void; | Obtains the slot of the default SIM card that provides the voice service.                                   | –                                 |
| function getDefaultVoiceSimId(callback: AsyncCallback\<number>): void; | Obtains the sim id of the default SIM card that provides the voice service.                                   | –                                 |
| function isSimActive(slotId: number, callback: AsyncCallback\<boolean>): void | Checks whether the SIM card in the specified slot is activated.                          | –                                 |
| function hasSimCard(slotId: number, callback: AsyncCallback\<boolean>): void  | Checks whether the specified slot is populated with a SIM card.                            | –                                 |
| function getSimTelephoneNumber(slotId: number, callback: AsyncCallback\<string>): void | Obtains the mobile station integrated services digital network (MSISDN) of the SIM card in the specified slot.|ohos.permission.GET_PHONE_NUMBERS |
| function getVoiceMailIdentifier(slotId: number, callback: AsyncCallback\<string>): void | Obtains the voice mailbox identifier of the SIM card in the specified slot.| ohos.permission.GET_TELEPHONY_STATE |
| function getVoiceMailNumber(slotId: number, callback: AsyncCallback\<string>): void | Obtains the voice mailbox number of the SIM card in the specified slot.| ohos.permission.GET_TELEPHONY_STATE |
| function getCardType(slotId: number, callback: AsyncCallback\<CardType>): void | Obtains the type of the SIM card in the specified slot. | –|
| function hasOperatorPrivileges(slotId: number, callback: AsyncCallback\<boolean>): void | Checks whether the application (caller) has been granted the operator permission.| –|
| function getMaxSimCount(): number | Obtains the maximum number of SIM cards, that is, the maximum number of SIM card slots, available on the device.| –|

For details about the complete description of JavaScript APIs and sample code, see [SIM Card Management](https://gitee.com/openharmony/docs/blob/master/en/application-dev/reference/apis/js-apis-sim.md).

### NetworkSearchManager APIs<a name="section198mcpsimp"></a>

| Name                                                    | Description                     | Required Permission                           |
| ------------------------------------------------------------ | ----------------------------- | ----------------------------------- |
| function getRadioTech(slotId: number, callback: AsyncCallback\<{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}>): void; | Obtains the current radio access technology of the SIM card in the specified slot.   | ohos.permission.GET_NETWORK_INFO    |
| function getSignalInformation(slotId: number, callback: AsyncCallback\<Array\<SignalInformation>>): void; | Obtains the signal information of the SIM card in the specified slot.       | –                                 |
| function getNetworkState(slotId: number, callback: AsyncCallback\<NetworkState>): void; | Obtains the network status of the SIM card in the specified slot.       | ohos.permission.GET_NETWORK_INFO    |
| function getISOCountryCodeForNetwork(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the ISO country code of the SIM card in the specified slot.     | –                                 |
| function getNetworkSearchInformation(slotId: number, callback: AsyncCallback\<NetworkSearchResult>): void; | Obtains the manual network search result of the SIM card in the specified slot.   | ohos.permission.GET_TELEPHONY_STATE |
| function getNetworkSelectionMode(slotId: number, callback: AsyncCallback\<NetworkSelectionMode>): void; | Obtains the network selection mode of the SIM card in the specified slot.       | –                                 |
| function setNetworkSelectionMode(options: NetworkSelectionModeOptions, callback: AsyncCallback\<void>): void; | Sets the network selection mode of the SIM card in the specified slot.       | ohos.permission.SET_TELEPHONY_STATE |
| function isRadioOn(callback: AsyncCallback\<boolean>): void; | Checks whether the radio service is enabled on the primary SIM card.         | ohos.permission.GET_NETWORK_INFO    |
| function isRadioOn(slotId: number, callback: AsyncCallback\<boolean>): void; | Checks whether the radio service is enabled on the SIM card in the specified slot.| ohos.permission.GET_NETWORK_INFO    |
| function turnOnRadio(callback: AsyncCallback\<void>): void;  | Enables the radio service on the primary SIM card.                 | ohos.permission.SET_TELEPHONY_STATE |
| function turnOnRadio(slotId: number, callback: AsyncCallback\<void>): void; | Enables the radio service on the SIM card in the specified slot.        | ohos.permission.SET_TELEPHONY_STATE |
| function turnOffRadio(callback: AsyncCallback\<void>): void; | Disables the radio service on the primary SIM card.                 | ohos.permission.SET_TELEPHONY_STATE |
| function turnOffRadio(slotId: number, callback: AsyncCallback\<void>): void; | Disables the radio service on the SIM card in the specified slot.        | ohos.permission.SET_TELEPHONY_STATE |
| function getOperatorName(slotId: number, callback: AsyncCallback\<string>): void; | Obtains the carrier name of the SIM card in the specified slot.      | –                                 |
| function setPreferredNetwork(slotId: number, networkMode: PreferredNetworkMode, callback: AsyncCallback\<void>): void; | Sets the preferred network of the SIM card in the specified slot.   | ohos.permission.SET_TELEPHONY_STATE                                 |
| function getPreferredNetwork(slotId: number, callback: AsyncCallback\<PreferredNetworkMode>): void; | Obtains the preferred network of the SIM card in the specified slot.   | ohos.permission.GET_TELEPHONY_STATE                                 |
| function getCellInformation(slotId: number, callback: AsyncCallback<Array\<CellInformation>>) | Obtains the cell information list.             | ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION         |
| function sendUpdateCellLocationRequest(slotId: number, callback: AsyncCallback\<void>) | Requests for a cell location update.                 | ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION            |
| function getIMEI(slotId: number, callback: AsyncCallback\<string>) | Obtains the international mobile equipment identity (IMEI).                     | ohos.permission.GET_TELEPHONY_STATE |
| function getMEID(slotId: number, callback: AsyncCallback\<string>)| Obtains the mobile equipment identifier (MEID).                     | ohos.permission.GET_TELEPHONY_STATE |
| function getUniqueDeviceId(slotId: number, callback: AsyncCallback\<string>)| Obtains the unique ID of a device.           | ohos.permission.GET_TELEPHONY_STATE |
| function getNrOptionMode(slotId: number, callback: AsyncCallback\<NrOptionMode>)| Obtains the 5G mode.                   | – |
| function isNrSupported: boolean;                             | Checks whether 5G is supported.               | –                                 |
| function getImsRegInfo(slotId: number, imsType: ImsServiceType, callback: AsyncCallback\<ImsRegInfo>): void; | Gets IMS register status info  | ohos.permission.GET_TELEPHONY_STATE                     |
| function on(type: 'imsRegStateChange', slotId: number, imsType: ImsServiceType, callback: Callback\<ImsRegInfo>): void; | Registers IMS network status callback  | ohos.permission.GET_TELEPHONY_STATE     |
| function off(type: 'imsRegStateChange', slotId: number, imsType: ImsServiceType, callback?: Callback\<ImsRegInfo>): void; | Unregisters IMS network status callback  | ohos.permission.GET_TELEPHONY_STATE  |


For details about the complete description of JavaScript APIs and sample code, see [Radio](https://gitee.com/openharmony/docs/blob/master/en/application-dev/reference/apis/js-apis-radio.md).

**NOTE**

>The RIL Manager does not provide external APIs. It can only be called by modules of the Telephony subsystem.

## Usage Guidelines<a name="section370mcpsimp"></a>

### Network Search<a name="section393mcpsimp"></a> 

The function of obtaining the network status is used as an example. The process is as follows:

1.  Query the SIM card in the slot specified by **slotId**. If **slotId** is not set, information about the primary card is queried by default.
2.  Call the **getNetworkState** method in callback or promise mode to obtain the network status.
3.  Obtain the SIM card status information. The **getNetworkState** method works in asynchronous mode. The execution result is returned through the callback.

    ```js
    import radio from "@ohos.telephony.radio";

    // Set the value of slotId.
    let slotId = 0;

    // Call the API in callback mode.
    radio.getNetworkState(slotId, (err, value) => {
      if (err) {
        // If the API call fails, err is not empty.
        console.error(`failed to getNetworkState because ${err.message}`);
        return;
      }
      // If the API call is successful, err is empty.
      console.log(`success to getNetworkState: ${value}`);
    });

    // Call the API in promise mode.
    let promise = radio.getNetworkState(slotId);
    promise.then((value) => {
      // The API call is successful.
      console.log(`success to getNetworkState: ${value}`);
    }).catch((err) => {
      // The API call fails.
      console.error(`failed to getNetworkState because ${err.message}`);
    });
    ```


### SIM Card Management<a name="section402mcpsimp"></a>

The function of querying the status of a specified SIM card is used as an example. The process is as follows:

1.  Set the value of **slotId**.
2.  Call the **getSimState** method in callback or promise mode to obtain the SIM card status.
3.  Obtain the SIM card status information. The **getSimState** method works in asynchronous mode. The execution result is returned through the callback.

    ```js
    import sim from "@ohos.telephony.sim";

    // Set the value of slotId.
    let slotId = 0;

    // Call the API in callback mode.
    sim.getSimState(slotId, (err, value) => {
      if (err) {
        // If the API call fails, err is not empty.
        console.error(`failed to getSimState because ${err.message}`);
        return;
      }
      // If the API call is successful, err is empty.
      console.log(`success to getSimState: ${value}`);
    });

    // Call the API in promise mode.
    let promise = sim.getSimState(slotId);
    promise.then((value) => {
      // The API call is successful.
      console.log(`success to getSimState: ${value}`);
    }).catch((err) => {
      // The API call fails.
      console.error(`failed to getSimState because ${err.message}`);
    });
    ```


## Repositories Involved<a name="section409mcpsimp"></a>

[Telephony Subsystem](https://gitee.com/openharmony/docs/blob/master/en/readme/telephony.md)

**telephony\_core\_service**

[telephony\_sms\_mms](https://gitee.com/openharmony/telephony_sms_mms/blob/master/README.md)

[drivers_interface](https://gitee.com/openharmony/drivers_interface)

[drivers_peripheral](https://gitee.com/openharmony/drivers_peripheral)

[telephony\_ril\_adapter](https://gitee.com/openharmony/telephony_ril_adapter/blob/master/README.md)

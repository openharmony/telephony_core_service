# Telephony Core Service<a name="EN-US_TOPIC_0000001152064913"></a>

-   [Introduction](#section117mcpsimp)
-   [Directory Structure](#section129mcpsimp)
-   [Constraints](#section133mcpsimp)
-   [Available APIs](#section139mcpsimp)
    -   [APIs for the SIM Card Service](#section142mcpsimp)
    -   [APIs for the Network Search Service](#section198mcpsimp)

-   [Usage Guidelines](#section370mcpsimp)
    -   [Network Search](#section393mcpsimp)
    -   [SIM Card](#section402mcpsimp)

-   [Repositories Involved](#section409mcpsimp)

## Introduction<a name="section117mcpsimp"></a>

The telephony core service initializes the RIL Manager, SIM card module, and network search module, and provides access to the RIL Adapter service.

You can implement communication with the RIL Adapter by registering the callback service and implement communication between modules by subscribing to callbacks.

**Figure  1**  Architecture of the telephony core service<a name="fig5700192716219"></a>


 ![](figures/en-us_architecture-of-the-core_service-module.png)

As shown in the preceding figure, the telephony core service consists of the SIM card service, network search service, and RIL Manager service.

-   SIM card service: Provides services including SIM card initialization, file read/write, loading status notification, and single-SIM/dual-SIM control. These services implement functions such as SIM card status query, SIM card management, SIM card control, STK, contact storage, and SMS storage.
-   Network search service: Provides services including network registration and network status acquisition. These services offer functions such as network registration, network mode query, radio status query, network search management, signal strength query, cell management, registration status management, and time and time zone setting.
-   RIL Manager service: Provides the proactive callback service and query result callback service.

## Directory Structure<a name="section129mcpsimp"></a>

```shell
/base/telphony/core_service
├── figures                # Resource of Readme
├── frameworks             # Framework Level Directory
│   ├── js
│   └── native
├── interfaces             # APIs
│   ├── innerkits          # Internal APIs
│   └── kits               # External APIs (such as JS APIs)
├── sa_profile             # Core service startup file directory
├── services               # Implementation of the telephony core service
│   ├── etc                # Driver script directory for core services
│   ├── include
│   ├── network_search     # Search Network Service Code Directory
│   ├── sim                # SIM card service code directory
│   ├── src
│   └── tel_ril            # Core service and RIL Adapter communication code directory
├── test                   # Unit test related code
│   └── unittest
└── utils
    ├── common             # Core service log print directory
    ├── log
    └── preferences
```

## Constraints<a name="section133mcpsimp"></a>

-   Programming language: C++、JavaScript
-   In terms of software, this module needs to work with the RIL adapter service \(ril\_adapter\) and status registration service \(state\_registry\).
-   In terms of hardware, the accommodating device must be equipped with a modem and a SIM card capable of independent cellular communication.

## Available APIs<a name="section139mcpsimp"></a>

The telephony core service module needs to provide APIs for related modules, including the SIM card, network search modules.

### APIs for the SIM Card Service<a name="section142mcpsimp"></a>

| Interface name                                                     | Interface description                                                    | Required permissions                            |
| ------------------------------------------------------------ | ----------------------------------------------------------- | ----------------------------------- |
| function getSimState(slotId: number, callback: AsyncCallback\<SimState>): void; | Get the SIM card status of the specified slot                                     | None                                  |
| function getSimGid1(slotId: number, callback: AsyncCallback\<string>): void; | Get the GID1 of the SIM card in the specified slot (Group Identifier Level 1)           | ohos.permission.GET_TELEPHONY_STATE |
| function getSimIccId(slotId: number, callback: AsyncCallback\<string>): void; | Get the ICCID (Integrate Circuit Card Identity) of the SIM card in the specified slot | ohos.permission.GET_TELEPHONY_STATE |
| function getISOCountryCodeForSim(slotId: number, callback: AsyncCallback\<string>): void; | Get the ISO country code of the SIM card in the specified slot                                | None                                  |
| function getSimOperatorNumeric(slotId: number, callback: AsyncCallback\<string>): void; | Get the PLMN (Public Land Mobile Network) number of the SIM card in the specified slot | None                                  |
| function getSimSpn(slotId: number, callback: AsyncCallback\<string>): void; | Get the SPN (Service Provider Name) of the SIM card of the specified slot       | None                                  |
| function getDefaultVoiceSlotId(callback: AsyncCallback\<number>): void; | Get the default card slot of the voice service                                    | None                                  |
| function isSimActive(slotId: number, callback: AsyncCallback\<boolean>): void | Check whether the SIM card in the specified slot is activated                           | None                                  |
| function hasSimCard(slotId: number, callback: AsyncCallback\<boolean>): void  | Check whether the SIM card is inserted into the specified card slot                             | None                                  |
| function getSimTelephoneNumber(slotId: number, callback: AsyncCallback\<string>): void | Get the MSISDN (Mobile Station Integrated Services Digital Network) of the SIM card in the specified slot|ohos.permission.GET_TELEPHONY_STATE |
| function getVoiceMailIdentifier(slotId: number, callback: AsyncCallback\<string>): void | Get the voicemail identification of the SIM card in the specified slot | ohos.permission.GET_TELEPHONY_STATE | ohos.permission.GET_TELEPHONY_STATE |
| function getVoiceMailNumber(slotId: number, callback: AsyncCallback\<string>): void | Get the voice mailbox number of the SIM card in the specified slot | ohos.permission.GET_TELEPHONY_STATE |
| function getCardType(slotId: number, callback: AsyncCallback\<CardType>): void | Check whether the application (caller) has been granted operator privileges | None |
| function hasOperatorPrivileges(slotId: number, callback: AsyncCallback\<boolean>): void | Get the type of SIM card in the specified slot | None |
| function getMaxSimCount(): number | Get the maximum number of SIM cards that can be used simultaneously on the device, that is, the maximum number of SIM card slots. | None |
| function getPrimarySlotId(callback: AsyncCallback\<number>): void | Get the default primary slot ID | None |


### APIs for the Network Search Service<a name="section198mcpsimp"></a>

| Interface name                                                     | Interface description                                                    | Required permissions                            |
| ------------------------------------------------------------ | ----------------------------------------------------------- | ----------------------------------- |
| function getRadioTech(slotId: number, callback: AsyncCallback\<{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}>): void; | Get the current access technology of the specified card slot | ohos.permission.GET_NETWORK_INFO    |
| function getSignalInformation(slotId: number, callback: AsyncCallback\<Array\<SignalInformation>>): void; | Get the signal list of the specified card slot     | None                                  |
| function getNetworkState(slotId: number, callback: AsyncCallback\<NetworkState>): void; | Get the network status of the specified card slot     | ohos.permission.GET_NETWORK_INFO    |
| function getISOCountryCodeForNetwork(slotId: number, callback: AsyncCallback\<string>): void; | Get the network country code of the specified card slot   | None                                  |
| function getNetworkSearchInformation(slotId: number, callback: AsyncCallback\<NetworkSearchResult>): void; | Get the manual search results of the specified card slot | ohos.permission.GET_TELEPHONY_STATE |
| function getNetworkSelectionMode(slotId: number, callback: AsyncCallback\<NetworkSelectionMode>): void; | Get the network selection mode of the specified card slot     | None                                  |
| function setNetworkSelectionMode(options: NetworkSelectionModeOptions, callback: AsyncCallback\<void>): void; | Set the network selection mode of the specified card slot     | ohos.permission.SET_TELEPHONY_STATE |
| function isRadioOn(callback: AsyncCallback\<boolean>): void; | Determine whether Radio is turned on          | ohos.permission.GET_NETWORK_INFO    |
| function turnOnRadio(callback: AsyncCallback\<void>): void;  | Turn on Radio                  | ohos.permission.SET_TELEPHONY_STATE |
| function turnOffRadio(callback: AsyncCallback\<void>): void; | Turn off Radio                  | ohos.permission.SET_TELEPHONY_STATE |
| function getOperatorName(slotId: number, callback: AsyncCallback\<string>): void; | Get the operator name of the specified card slot   | None                                  |
| function setPreferredNetwork(slotId: number, networkMode: PreferredNetworkMode, callback: AsyncCallback\<void>): void; | Set the preferred network mode of the specified card slot | None                                  |
| function getPreferredNetwork(slotId: number, callback: AsyncCallback\<PreferredNetworkMode>): void; | Get the preferred network mode of the specified card slot | None                                  |
| function getCellInformation(slotId: number, callback: AsyncCallback<Array\<CellInformation>>) | Get cell information list           | ohos.permission.LOCATION            |
| function sendUpdateCellLocationRequest(callback: AsyncCallback\<void>) | Request cell location               | ohos.permission.LOCATION            |
| function getIMEI(slotId: number, callback: AsyncCallback\<string>) | Get Imei                   | ohos.permission.GET_TELEPHONY_STATE |
| function getMeId(slotId: number, callback: AsyncCallback\<string>） | Get Meid                   | ohos.permission.GET_TELEPHONY_STATE |
| function getUniqueDeviceId(slotId: number, callback: AsyncCallback\<string>） | Get the unique identification code of the device         | ohos.permission.GET_TELEPHONY_STATE |
| function getNrOptionMode(slotId: number, callback: AsyncCallback\<NrOptionMode>） | Get 5G mode                 | ohos.permission.GET_TELEPHONY_STATE |
| function isNrSupported: boolean;                             | Whether to support 5g network             | None                                  |

>**NOTE:**
>The RIL Manager does not provide external APIs and can only be called by modules of the Telephony subsystem.

## Usage Guidelines<a name="section370mcpsimp"></a>

### Network Search<a name="section393mcpsimp"></a>

The function of obtaining the network status is used as an example. The process is as follows:

1.  Query the SIM card in the slot specified by  **slotId**. If  **slotId**  is not set, information about the primary card is queried by default.
2.  Call the  **GetNetworkStatus**  method in callback or Promise mode.
3.  Obtain the network status information. The  **GetNetworkStatus**  method works in asynchronous mode. The execution result is returned through the callback.

    ```js
    import radio from "@ohos.telephony.radio";

    // Set the value of slotId.
    let slotId = 0;

    // Call the API in callback mode.
    radio.GetNetworkStatus(slotId, (err, value) => {
      if (err) {
        // If the API call failed, err is not empty.
        console.error(`failed to GetNetworkStatus because ${err.message}`);
        return;
      }
      // If the API call succeeded, err is empty.
      console.log(`success to GetNetworkStatus: ${value}`);
    });

    // Call the API in Promise mode.
    let promise = radio.GetNetworkStatus(slotId);
    promise.then((value) => {
      // The API call succeeded.
      console.log(`success to GetNetworkStatus: ${value}`);
    }).catch((err) => {
      // The API call failed.
      console.error(`failed to GetNetworkStatus because ${err.message}`);
    });
    ```


### SIM Card<a name="section402mcpsimp"></a>

The function of querying the status of a specified SIM card is used as an example. The process is as follows:

1.  Set the value of  **slotId**.
2.  Call the  **getSimState**  method in callback or Promise mode to obtain the SIM card status information.
3.  This method works in asynchronous mode. The execution result is returned through the callback.

    ```js
    import sim from "@ohos.telephony.sim";

    // Set the value of slotId.
    let slotId = 0;

    // Call the API in callback mode.
    sim.getSimState(slotId, (err, value) => {
      if (err) {
        // If the API call failed, err is not empty.
        console.error(`failed to getSimState because ${err.message}`);
        return;
      }
      // If the API call succeeded, err is empty.
      console.log(`success to getSimState: ${value}`);
    });

    // Call the API in Promise mode.
    let promise = sim.getSimState(slotId);
    promise.then((value) => {
      // The API call succeeded.
      console.log(`success to getSimState: ${value}`);
    }).catch((err) => {
      // The API call failed.
      console.error(`failed to getSimState because ${err.message}`);
    });
    ```


## Repositories Involved<a name="section409mcpsimp"></a>

[Telephony](https://gitee.com/openharmony/docs/blob/master/en/readme/telephony.md)

**telephony_core_service**

[telephony_sms_mms](https://gitee.com/openharmony/telephony_sms_mms/blob/master/README.md)
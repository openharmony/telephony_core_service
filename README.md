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

```
/OpenHarmony_Standard_System/base/telphony/core_service
├── interfaces             # APIs
│   ├── innerkits          # Internal APIs
│   └── kits               # External APIs (such as JS APIs)
├── services               # Implementation of the telephony core service
├── etc                    # Telephony core service driver scripts
├── sa_profile             # SA profile
├── tel_ril                # RIL Manager service code
├── network_search         # Network search service code
├── sim                    # SIM card service code
└── common
```

## Constraints<a name="section133mcpsimp"></a>

-   Programming language: JavaScript
-   In terms of software, this module needs to work with the RIL adapter service \(ril\_adapter\) and status registration service \(state\_registry\).
-   In terms of hardware, the accommodating device must be equipped with a modem and a SIM card capable of independent cellular communication.

## Available APIs<a name="section139mcpsimp"></a>

The telephony core service module needs to provide APIs for related modules, including the SIM card, network search modules.

### APIs for the SIM Card Service<a name="section142mcpsimp"></a>

<a name="table144mcpsimp"></a>
<table><thead align="left"><tr id="row150mcpsimp"><th class="cellrowborder" valign="top" width="33.406659334066596%" id="mcps1.1.4.1.1"><p id="entry151mcpsimpp0"><a name="entry151mcpsimpp0"></a><a name="entry151mcpsimpp0"></a>API</p>
</th>
<th class="cellrowborder" valign="top" width="33.266673332666734%" id="mcps1.1.4.1.2"><p id="entry152mcpsimpp0"><a name="entry152mcpsimpp0"></a><a name="entry152mcpsimpp0"></a>Description</p>
</th>
<th class="cellrowborder" valign="top" width="33.32666733326668%" id="mcps1.1.4.1.3"><p id="entry153mcpsimpp0"><a name="entry153mcpsimpp0"></a><a name="entry153mcpsimpp0"></a>Required Permission</p>
</th>
</tr>
</thead>
<tbody><tr id="row162mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p109592823314"><a name="p109592823314"></a><a name="p109592823314"></a>function getSimState(slotId: number, callback: AsyncCallback&lt;SimState&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="entry164mcpsimpp0"><a name="entry164mcpsimpp0"></a><a name="entry164mcpsimpp0"></a>Obtains the SIM card status.</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry165mcpsimpp0"><a name="entry165mcpsimpp0"></a><a name="entry165mcpsimpp0"></a>None</p>
</td>
</tr>
<tr id="row178mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="entry179mcpsimpp0"><a name="entry179mcpsimpp0"></a><a name="entry179mcpsimpp0"></a>function getISOCountryCodeForSim(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="entry180mcpsimpp0"><a name="entry180mcpsimpp0"></a><a name="entry180mcpsimpp0"></a>Obtains the country code.</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry181mcpsimpp0"><a name="entry181mcpsimpp0"></a><a name="entry181mcpsimpp0"></a>None</p>
</td>
</tr>
<tr id="row182mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p1441115133518"><a name="p1441115133518"></a><a name="p1441115133518"></a>function getSimOperatorNumeric(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="entry184mcpsimpp0"><a name="entry184mcpsimpp0"></a><a name="entry184mcpsimpp0"></a>Obtains the carrier code.</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry185mcpsimpp0"><a name="entry185mcpsimpp0"></a><a name="entry185mcpsimpp0"></a>None</p>
</td>
</tr>
<tr id="row186mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p1818291010352"><a name="p1818291010352"></a><a name="p1818291010352"></a>function getSimSpn(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="entry188mcpsimpp0"><a name="entry188mcpsimpp0"></a><a name="entry188mcpsimpp0"></a>Obtains the SPN information.</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry189mcpsimpp0"><a name="entry189mcpsimpp0"></a><a name="entry189mcpsimpp0"></a>None</p>
</td>
</tr>
</tbody>
</table>

### APIs for the Network Search Service<a name="section198mcpsimp"></a>

<a name="table200mcpsimp"></a>
<table><thead align="left"><tr id="row206mcpsimp"><th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.1.4.1.1"><p id="entry207mcpsimpp0"><a name="entry207mcpsimpp0"></a><a name="entry207mcpsimpp0"></a>API</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.1.4.1.2"><p id="entry208mcpsimpp0"><a name="entry208mcpsimpp0"></a><a name="entry208mcpsimpp0"></a>Description</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.1.4.1.3"><p id="entry209mcpsimpp0"><a name="entry209mcpsimpp0"></a><a name="entry209mcpsimpp0"></a>Required Permission</p>
</th>
</tr>
</thead>
<tbody><tr id="row210mcpsimp"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p611934143612"><a name="p611934143612"></a><a name="p611934143612"></a>function getRadioTech(slotId: number, callback: AsyncCallback&lt;{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="entry212mcpsimpp0"><a name="entry212mcpsimpp0"></a><a name="entry212mcpsimpp0"></a>Obtains the current radio access technology.</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="entry213mcpsimpp0"><a name="entry213mcpsimpp0"></a><a name="entry213mcpsimpp0"></a>ohos.permission.GET_NETWORK_INFO</p>
</td>
</tr>
<tr id="row226mcpsimp"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p924781783614"><a name="p924781783614"></a><a name="p924781783614"></a>function getSignalInformation(slotId: number, callback: AsyncCallback&lt;Array&lt;SignalInformation&gt;&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="entry228mcpsimpp0"><a name="entry228mcpsimpp0"></a><a name="entry228mcpsimpp0"></a>Obtains the signal information.</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="entry229mcpsimpp0"><a name="entry229mcpsimpp0"></a><a name="entry229mcpsimpp0"></a>None</p>
</td>
</tr>
<tr id="row230mcpsimp"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p22372373611"><a name="p22372373611"></a><a name="p22372373611"></a>function getNetworkState(slotId: number, callback: AsyncCallback&lt;NetworkState&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="entry232mcpsimpp0"><a name="entry232mcpsimpp0"></a><a name="entry232mcpsimpp0"></a>Obtains the network status.</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="entry233mcpsimpp0"><a name="entry233mcpsimpp0"></a><a name="entry233mcpsimpp0"></a>ohos.permission.GET_NETWORK_INFO</p>
</td>
</tr>
</tbody>
</table>

>**NOTE:**
>The RIL Manager does not provide external APIs and can only be called by modules of the Telephony subsystem.

## Usage Guidelines<a name="section370mcpsimp"></a>

### Network Search<a name="section393mcpsimp"></a>

The function of obtaining the network status is used as an example. The process is as follows:

1.  Query the SIM card in the slot specified by  **slotId**. If  **slotId**  is not set, information about the primary card is queried by default.
2.  Call the  **getNetworkState**  method in callback or Promise mode.
3.  Obtain the network status information. The  **getNetworkState**  method works in asynchronous mode. The execution result is returned through the callback.

    ```
    import radio from "@ohos.telephony.radio";

    // Set the value of slotId.
    let slotId = 1;

    // Call the API in callback mode.
    radio.getNetworkState(slotId, (err, value) => {
      if (err) {
        // If the API call failed, err is not empty.
        console.error(`failed to getNetworkState because ${err.message}`);
        return;
      }
      // If the API call succeeded, err is empty.
      console.log(`success to getNetworkState: ${value}`);
    });

    // Call the API in Promise mode.
    let promise = radio.getNetworkState(slotId);
    promise.then((value) => {
      // The API call succeeded.
      console.log(`success to getNetworkState: ${value}`);
    }).catch((err) => {
      // The API call failed.
      console.error(`failed to getNetworkState because ${err.message}`);
    });
    ```


### SIM Card<a name="section402mcpsimp"></a>

The function of querying the status of a specified SIM card is used as an example. The process is as follows:

1.  Set the value of  **slotId**.
2.  Call the  **getSimState**  method in callback or Promise mode to obtain the SIM card status information.
3.  This method works in asynchronous mode. The execution result is returned through the callback.

    ```
    import sim from "@ohos.telephony.sim";

    // Set the value of slotId.
    let slotId = 1;

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
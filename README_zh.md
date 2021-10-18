# 核心服务<a name="ZH-CN_TOPIC_0000001152064913"></a>

-   [简介](#section117mcpsimp)
-   [目录](#section129mcpsimp)
-   [约束](#section133mcpsimp)
-   [接口说明](#section139mcpsimp)
    -   [SIM卡对外提供的接口](#section142mcpsimp)
    -   [搜网服务对外提供的接口](#section198mcpsimp)

-   [使用说明](#section370mcpsimp)
    -   [搜网](#section393mcpsimp)
    -   [SIM卡](#section402mcpsimp)

-   [相关仓](#section409mcpsimp)

## 简介<a name="section117mcpsimp"></a>

核心服务模块主要功能是初始化SIM卡服务、搜网服务和RIL管理，以及获取RIL Adapter服务。

通过注册回调服务，实现与RIL Adapter进行通信；通过发布订阅，来实现与各功能模块的通信。

**图 1**  核心服务架构图<a name="fig5700192716219"></a>


![](figures/zh-cn_architecture-of-the-core_service-module.png)

上图示中核心服务关联的业务服务包括SIM卡服务、搜网服务、RIL通信管理。

-   SIM卡服务：主要是SIM卡初始化，文件读写，加载状态通知，单双卡控制，包括SIM卡状态查询、SIM卡管理、SIM卡控制、STK、联系人存储、短信存储。
-   搜网服务：主要是网络注册，网络状态获取，包括网络注册、网络模式查询、Radio状态查询、搜网管理、信号强度查询、小区管理、驻网管理、时间时区更新。
-   RIL管理：提供主动回调服务，查询结果回调服务等。

## 目录<a name="section129mcpsimp"></a>

```
/base/telphony/core_service
├── interfaces             # 接口目录
│   ├── innerkits          # 部件间的内部接口
│   └── kits               # 对应用提供的接口（例如JS接口）
├── services               # 核心服务实现代码目录
│   ├── include
│   └── src
├── etc                    # 核心服务的驱动脚本目录
│   └── init
├── sa_profile             # 核心服务的启动文件目录
├── tel_ril                # 核心服务与RIL Adapter通信代码目录
│   ├── include
│   ├── src
├── network_search         # 搜网服务代码目录
│   ├── include
│   ├── src
├── sim                    # SIM卡服务代码目录
│   ├── include
│   ├── src
├── common
│   ├── log                # 核心服务日志打印目录
│   ├── preferences
│   ├── utils
└── test                   # 单元测试相关代码
    └── unittest
```

## 约束<a name="section133mcpsimp"></a>

-   开发语言：C++ 、Java Script。
-   软件约束：需要与以下服务配合使用：RIL适配（ril\_adapter），状态注册服务（state\_registry）。
-   硬件约束：需要搭载的设备支持以下硬件：可以进行独立蜂窝通信的Modem以及SIM卡。

## 接口说明<a name="section139mcpsimp"></a>

核心服务模块需要提供SIM卡，搜网相关模块的接口。

### SIM卡对外提供的接口<a name="section142mcpsimp"></a>

<a name="table144mcpsimp"></a>
<table><thead align="left"><tr id="row150mcpsimp"><th class="cellrowborder" valign="top" width="33.406659334066596%" id="mcps1.1.4.1.1"><p id="entry151mcpsimpp0"><a name="entry151mcpsimpp0"></a><a name="entry151mcpsimpp0"></a>接口名称</p>
</th>
<th class="cellrowborder" valign="top" width="33.266673332666734%" id="mcps1.1.4.1.2"><p id="entry152mcpsimpp0"><a name="entry152mcpsimpp0"></a><a name="entry152mcpsimpp0"></a>接口描述</p>
</th>
<th class="cellrowborder" valign="top" width="33.32666733326668%" id="mcps1.1.4.1.3"><p id="entry153mcpsimpp0"><a name="entry153mcpsimpp0"></a><a name="entry153mcpsimpp0"></a>所需权限</p>
</th>
</tr>
</thead>
<tbody><tr id="row162mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p109592823314"><a name="p109592823314"></a><a name="p109592823314"></a>function getSimState(slotId: number, callback: AsyncCallback&lt;SimState&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p6465112873313"><a name="p6465112873313"></a><a name="p6465112873313"></a>获取指定卡槽的SIM卡状态</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry165mcpsimpp0"><a name="entry165mcpsimpp0"></a><a name="entry165mcpsimpp0"></a>无</p>
</td>
</tr>
<tr id="row112142420336"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p321517423338"><a name="p321517423338"></a><a name="p321517423338"></a>function getSimGid1(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p1321515422336"><a name="p1321515422336"></a><a name="p1321515422336"></a>获取指定卡槽SIM卡的GID1(Group Identifier Level 1)</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="p1321519421336"><a name="p1321519421336"></a><a name="p1321519421336"></a>ohos.permission.GET_TELEPHONY_STATE</p>
</td>
</tr>
<tr id="row179361554173312"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p1829010144347"><a name="p1829010144347"></a><a name="p1829010144347"></a>function getSimIccId(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p1283325183420"><a name="p1283325183420"></a><a name="p1283325183420"></a>获取指定卡槽SIM卡的ICCID（Integrate Circuit Card Identity）</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry177mcpsimpp0"><a name="entry177mcpsimpp0"></a><a name="entry177mcpsimpp0"></a>ohos.permission.GET_TELEPHONY_STATE</p>
</td>
</tr>
<tr id="row178mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="entry179mcpsimpp0"><a name="entry179mcpsimpp0"></a><a name="entry179mcpsimpp0"></a>function getISOCountryCodeForSim(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p3912143793414"><a name="p3912143793414"></a><a name="p3912143793414"></a>获取指定卡槽SIM卡的ISO国家码</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry181mcpsimpp0"><a name="entry181mcpsimpp0"></a><a name="entry181mcpsimpp0"></a>无</p>
</td>
</tr>
<tr id="row182mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p1441115133518"><a name="p1441115133518"></a><a name="p1441115133518"></a>function getSimOperatorNumeric(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p20213343133418"><a name="p20213343133418"></a><a name="p20213343133418"></a>获取指定卡槽SIM卡的归属PLMN（Public Land Mobile Network）号</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry185mcpsimpp0"><a name="entry185mcpsimpp0"></a><a name="entry185mcpsimpp0"></a>无</p>
</td>
</tr>
<tr id="row186mcpsimp"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p1818291010352"><a name="p1818291010352"></a><a name="p1818291010352"></a>function getSimSpn(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p10817104713416"><a name="p10817104713416"></a><a name="p10817104713416"></a>获取指定卡槽SIM卡的运营商SPN（Service Provider Name）</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="entry189mcpsimpp0"><a name="entry189mcpsimpp0"></a><a name="entry189mcpsimpp0"></a>无</p>
</td>
</tr>
<tr id="row86173529343"><td class="cellrowborder" valign="top" width="33.406659334066596%" headers="mcps1.1.4.1.1 "><p id="p76171552183413"><a name="p76171552183413"></a><a name="p76171552183413"></a>function getDefaultVoiceSlotId(callback: AsyncCallback&lt;number&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.266673332666734%" headers="mcps1.1.4.1.2 "><p id="p10617125210345"><a name="p10617125210345"></a><a name="p10617125210345"></a>获取语音业务的默认卡卡槽</p>
</td>
<td class="cellrowborder" valign="top" width="33.32666733326668%" headers="mcps1.1.4.1.3 "><p id="p0826218351"><a name="p0826218351"></a><a name="p0826218351"></a>无</p>
</td>
</tr>
</tbody>
</table>

完整的JS API说明以及实例代码请参考：[SIM卡管理](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/js-reference/SIM%E5%8D%A1%E7%AE%A1%E7%90%86.md)。

### 搜网服务对外提供的接口<a name="section198mcpsimp"></a>

<a name="table200mcpsimp"></a>
<table><thead align="left"><tr id="row206mcpsimp"><th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.1.4.1.1"><p id="entry207mcpsimpp0"><a name="entry207mcpsimpp0"></a><a name="entry207mcpsimpp0"></a>接口名称</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.1.4.1.2"><p id="entry208mcpsimpp0"><a name="entry208mcpsimpp0"></a><a name="entry208mcpsimpp0"></a>接口描述</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.1.4.1.3"><p id="entry209mcpsimpp0"><a name="entry209mcpsimpp0"></a><a name="entry209mcpsimpp0"></a>所需权限</p>
</th>
</tr>
</thead>
<tbody><tr id="row210mcpsimp"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p611934143612"><a name="p611934143612"></a><a name="p611934143612"></a>function getRadioTech(slotId: number, callback: AsyncCallback&lt;{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="entry212mcpsimpp0"><a name="entry212mcpsimpp0"></a><a name="entry212mcpsimpp0"></a>获取指定卡槽的当前接入技术</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="entry213mcpsimpp0"><a name="entry213mcpsimpp0"></a><a name="entry213mcpsimpp0"></a>ohos.permission.GET_NETWORK_INFO</p>
</td>
</tr>
<tr id="row226mcpsimp"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p924781783614"><a name="p924781783614"></a><a name="p924781783614"></a>function getSignalInformation(slotId: number, callback: AsyncCallback&lt;Array&lt;SignalInformation&gt;&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p12171627113811"><a name="p12171627113811"></a><a name="p12171627113811"></a>获取指定卡槽的信号列表</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="entry229mcpsimpp0"><a name="entry229mcpsimpp0"></a><a name="entry229mcpsimpp0"></a>无</p>
</td>
</tr>
<tr id="row230mcpsimp"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p22372373611"><a name="p22372373611"></a><a name="p22372373611"></a>function getNetworkState(slotId: number, callback: AsyncCallback&lt;NetworkState&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p23981325384"><a name="p23981325384"></a><a name="p23981325384"></a>获取指定卡槽的网络状态</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="entry233mcpsimpp0"><a name="entry233mcpsimpp0"></a><a name="entry233mcpsimpp0"></a>ohos.permission.GET_NETWORK_INFO</p>
</td>
</tr>
<tr id="row17188184311384"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p31882434382"><a name="p31882434382"></a><a name="p31882434382"></a>function getISOCountryCodeForNetwork(slotId: number, callback: AsyncCallback&lt;string&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p1918815434388"><a name="p1918815434388"></a><a name="p1918815434388"></a>获取指定卡槽的网络国家码</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p1818894323813"><a name="p1818894323813"></a><a name="p1818894323813"></a>无</p>
</td>
</tr>
<tr id="row927264911384"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p227294913819"><a name="p227294913819"></a><a name="p227294913819"></a>function getNetworkSearchInformation(slotId: number, callback: AsyncCallback&lt;NetworkSearchResult&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p162721149183812"><a name="p162721149183812"></a><a name="p162721149183812"></a>获取指定卡槽的手动搜网结果</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p1327216495382"><a name="p1327216495382"></a><a name="p1327216495382"></a>ohos.permission.GET_TELEPHONY_STATE</p>
</td>
</tr>
<tr id="row350525373816"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p15055539387"><a name="p15055539387"></a><a name="p15055539387"></a>function getNetworkSelectionMode(slotId: number, callback: AsyncCallback&lt;NetworkSelectionMode&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p55051532387"><a name="p55051532387"></a><a name="p55051532387"></a>获取指定卡槽的选网模式</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p7505155363815"><a name="p7505155363815"></a><a name="p7505155363815"></a>无</p>
</td>
</tr>
<tr id="row10262135216383"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p0263452143810"><a name="p0263452143810"></a><a name="p0263452143810"></a>function setNetworkSelectionMode(options: NetworkSelectionModeOptions, callback: AsyncCallback&lt;void&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p11263052113811"><a name="p11263052113811"></a><a name="p11263052113811"></a>设置指定卡槽的选网模式</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p32637527381"><a name="p32637527381"></a><a name="p32637527381"></a>ohos.permission.SET_TELEPHONY_STATE</p>
</td>
</tr>
<tr id="row1096475063810"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p99648502381"><a name="p99648502381"></a><a name="p99648502381"></a>function isRadioOn(callback: AsyncCallback&lt;boolean&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p296455083811"><a name="p296455083811"></a><a name="p296455083811"></a>判断Radio是否打开</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p14964135012383"><a name="p14964135012383"></a><a name="p14964135012383"></a>ohos.permission.GET_NETWORK_INFO</p>
</td>
</tr>
<tr id="row2851134633813"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p17588523164312"><a name="p17588523164312"></a><a name="p17588523164312"></a>function turnOnRadio(callback: AsyncCallback&lt;void&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p685115467386"><a name="p685115467386"></a><a name="p685115467386"></a>开启Radio</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p223815324217"><a name="p223815324217"></a><a name="p223815324217"></a>ohos.permission.SET_TELEPHONY_STATE</p>
</td>
</tr>
<tr id="row317374511384"><td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.1 "><p id="p4173174515380"><a name="p4173174515380"></a><a name="p4173174515380"></a>function turnOffRadio(callback: AsyncCallback&lt;void&gt;): void;</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.2 "><p id="p817364513385"><a name="p817364513385"></a><a name="p817364513385"></a>关闭Radio</p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.1.4.1.3 "><p id="p13558115384210"><a name="p13558115384210"></a><a name="p13558115384210"></a>ohos.permission.SET_TELEPHONY_STATE</p>
</td>
</tr>
</tbody>
</table>

完整的JS API说明以及实例代码请参考：[网络搜索](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/js-reference/%E7%BD%91%E7%BB%9C%E6%90%9C%E7%B4%A2.md)。

**说明：**

>RIL管理不对外暴露接口，由电话服务子系统其他各个模块调用。

## 使用说明<a name="section370mcpsimp"></a>

### 搜网<a name="section393mcpsimp"></a>

获取网络状态接口调用流程及示例代码：

1.  指定查询的slotId，若不指定默认查询主卡信息。
2.  可以通过callback或者Promise的方式调用getNetworkState方法，返回网络状态信息。
3.  该接口为异步接口，相关执行结果会从callback中返回。

    ```
    import radio from "@ohos.telephony.radio";

    // 参数赋值
    let slotId = 0;

    // 调用接口【callback方式】
    radio.getNetworkState(slotId, (err, value) => {
      if (err) {
        // 接口调用失败，err非空
        console.error(`failed to getNetworkState because ${err.message}`);
        return;
      }
      // 接口调用成功，err为空
      console.log(`success to getNetworkState: ${value}`);
    });

    // 调用接口【Promise方式】
    let promise = radio.getNetworkState(slotId);
    promise.then((value) => {
      // 接口调用成功，此处可以实现成功场景分支代码。
      console.log(`success to getNetworkState: ${value}`);
    }).catch((err) => {
      // 接口调用失败，此处可以实现失败场景分支代码。
      console.error(`failed to getNetworkState because ${err.message}`);
    });
    ```


### SIM卡<a name="section402mcpsimp"></a>

查询指定SIM卡的状态接口调用流程及示例代码：

1.  指定查询的slotId。
2.  可以通过callback或者Promise的方式调用getSimState方法，返回卡状态信息。
3.  该接口为异步接口，相关执行结果会从callback中返回。

    ```
    import sim from "@ohos.telephony.sim";

    // 参数赋值
    let slotId = 0;

    // 调用接口【callback方式】
    sim.getSimState(slotId, (err, value) => {
      if (err) {
        // 接口调用失败，err非空
        console.error(`failed to getSimState because ${err.message}`);
        return;
      }
      // 接口调用成功，err为空
      console.log(`success to getSimState: ${value}`);
    });

    // 调用接口【Promise方式】
    let promise = sim.getSimState(slotId);
    promise.then((value) => {
      // 接口调用成功，此处可以实现成功场景分支代码。
      console.log(`success to getSimState: ${value}`);
    }).catch((err) => {
      // 接口调用失败，此处可以实现失败场景分支代码。
      console.error(`failed to getSimState because ${err.message}`);
    });
    ```


## 相关仓<a name="section409mcpsimp"></a>

[电话服务子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E7%94%B5%E8%AF%9D%E6%9C%8D%E5%8A%A1%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

**telephony\_core\_service**

[telephony\_sms\_mms](https://gitee.com/openharmony/telephony_sms_mms/blob/master/README_zh.md)

[telephony\_ril\_adapter](https://gitee.com/openharmony/telephony_ril_adapter/blob/master/README_zh.md)


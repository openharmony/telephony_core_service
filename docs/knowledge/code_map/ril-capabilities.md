# 代码地图：RIL 层既有能力盘点

用途：接到 RIL 相关 SR 时，先对照本表判断是"**新增**能力"还是"**贯通**既有能力"（RIL 层命令齐全，但部分未上行到 IPC/NAPI）。

## 六业务命令分布（services/tel_ril/src/）

| 业务 | 文件 | 典型命令 |
|---|---|---|
| Call | tel_ril_call.cpp | Dial / Answer / Hangup / HoldCall / SwitchCall / GetCallList / SetCallTransfer |
| Data | tel_ril_data.cpp | SetupDataCall / DeactivateDataCall / GetDataCallList |
| Modem | tel_ril_modem.cpp | SendRadioPower / SendSimPower / GetBasebandVersion / SetModemRadio |
| Network | tel_ril_network.cpp | GetSignalStrength / GetPhysicalChannelConfig / GetCellInfoList / GetOperatorName / GetNrOptionMode / GetPreferredNetwork / GetNitzTime / SetPreferredNetwork |
| Sim | tel_ril_sim.cpp | GetSimStatus / SendSimMatchedOperatorInfo / GetSimPhonebook / RadioProtocolController |
| Sms | tel_ril_sms.cpp | SendGsmSms / SendCdmaSms / SendSmsAck / GetSmsSegmentsInfo |

## 查询链路范式（以 GetSignalInfoList / GetCellInfoList 为例）

```
NAPI (frameworks/js/network_search/src/napi_radio.cpp)
  → CoreServiceClient / CoreManagerInner (frameworks/native/src/)
    → CoreService IPC (services/core/src/core_service.cpp + core_service_stub.cpp case)
      → NetworkSearchManager (services/network_search/src/network_search_manager.cpp)
        → NetworkSearchHandler → 读缓存对象（signal_info.cpp / cell_info.cpp）
```
- 查询走**内存缓存**（由 unsol 事件更新，如 RADIO_SIGNAL_STRENGTH_UPDATE、RADIO_CHANNEL_CONFIG_UPDATE）
- RIL 层也有主动查询应答路径（如 tel_ril_network.cpp:417 GetPhysicalChannelConfigResponse），但上层默认读缓存（对齐 GetCellInfoList 语义）

## 已知"RIL 有、上层未暴露"的示例

| 能力 | RIL 层位置 | 上层现状 |
|---|---|---|
| GetPhysicalChannelConfig | tel_ril_network.cpp:94（命令）、:417（应答）、:192（unsol 上报）；缓存 network_register.cpp:193 → channelConfigInfos_（network_register.h:102） | NetworkSearch/CoreService/NAPI 均未暴露（截至 2026-09） |
| GetNeighboringCellInfoList | RIL 命令存在 | 仅 CoreService 层暴露，NAPI 无 |

注意：该列表会随版本变化，动手前用 grep 核实（`rg "GetPhysicalChannelConfig" services/ frameworks/ interfaces/`）。

## 上报（unsol）链路

```
RIL Adapter → HDI V1_5 IRilCallback → tel_ril_callback.cpp（按业务分发）
  → TelRilXxx::NetworkXxxUpdated（如 NetworkPhyChnlCfgUpdated tel_ril_network.cpp:192）
    → Notify<Type>(eventId, ...) → EventRunner 投递
      → network_search_handler.cpp 事件注册表（如 :154 RADIO_CHANNEL_CONFIG_UPDATE）
        → 模块处理器（如 NetworkRegister::ProcessChannelConfigInfo）更新缓存 + 通知
```
- 事件 ID 定义：interfaces/innerkits/include/radio_event.h
- 状态机常驻注册/注销在 handler 的 Init/DeInit（如 network_search_handler.cpp:417/:517 UnRegisterCoreNotify）

# 代码地图：模块与目录职责

## 一级目录职责

| 目录/文件 | 职责 |
|---|---|
| `services/core/` | CoreService 主 SA（SAID 4010）入口与 IPC：core_service.cpp（OnStart/Init 组装）、core_service_stub.cpp（2122 行分发 ~172 接口码）、core_service_sim.cpp、core_service_hisysevent.cpp |
| `services/sim/` | SIM 卡服务：SimManager 聚合状态机/文件/账户/eSIM/STK/短信存储（约 3.4 万行，本仓最大模块） |
| `services/network_search/` | 搜网服务：注册/选网/状态机、信号小区、运营商名、NITZ、EMC 救援、IMS 注册上报 |
| `services/tel_ril/` | RIL 通信层：TelRilManager + Call/Data/Modem/Network/Sim/Sms 六业务，HDI V1_5 IRil，TaskSchedule 调度 |
| `services/ims_service_interaction/` | IMS 服务跨 SA 客户端（订阅 TELEPHONY_IMS_SYS_ABILITY_ID） |
| `services/satellite_service_interaction/` | 卫星服务交互（CORE_SERVICE_SATELLITE 条件编译） |
| `services/telephony_ext_wrapper/` | 电话扩展封装（OHOS_BUILD_ENABLE_TELEPHONY_EXT 条件编译） |
| `services/etc/` | 配置：init/telephony.cfg、telephony_trust.json（telephony 进程 SAID 集合）、carrier/operator_config.json、operator_name.json、param/telephony.para |
| `frameworks/native/` | 客户端框架：core_service_client/proxy、core_manager_inner（内部单例）、esim_service_client |
| `frameworks/js/` | NAPI：sim / radio / esim / vcard 四个模块 + napi 公共工具 |
| `frameworks/cj/` | Cangjie FFI：telephony_radio / telephony_sim |
| `frameworks/ets/ani/` | Rust ANI 层：radio / sim / esim / vcard 四个 crate（cxx 绑定） |
| `interfaces/innerkits/` | 部件内接口：i_core_service.h、i_sim_manager.h、i_network_search.h、i_tel_ril_manager.h、core_service_ipc_interface_code.h、parcel 类型、IEsimService.idl |
| `interfaces/kits/` | 对外 API：c/telephony_radio（C API）+ js/*.d.ts |
| `common/capability_mgr/` | 多卡能力管控（slot3 仅系统应用/原生调用） |
| `utils/` | common（事件/权限/AES/配置）、log、preferences、vcard（2.1/3.0/4.0）、codec（ASN.1，仅 eSIM） |
| `test/` | unittest（15 gtest 工程，聚合 target）、fuzztest（41 fuzzer）、mock（ffrt 等）、guard |
| `sa_profile/` | 4010.json（SAID 4010、libpath libtel_core_service.z.so） |
| `telephonyres/` | 资源 HAP TelephonyResources |
| 根文件 | BUILD.gn（聚合 .so）、bundle.json（部件元数据）、hisysevent.yaml（TELEPHONY 事件）、telephony_core_service.gni（构建宏） |

## 关键文件索引

| 文件 | 职责 |
|---|---|
| services/core/src/core_service.cpp:62 | OnStart，Init 组装四模块 |
| services/core/src/core_service_stub.cpp | IPC 分发（172 接口码，手写巨型 case） |
| interfaces/innerkits/include/core_service_ipc_interface_code.h:22 | IPC 接口码枚举（只追加） |
| services/sim/src/sim_manager.cpp | SIM 聚合入口 |
| services/sim/src/sim_state_handle.cpp | SIM 状态机（ffrt 锁） |
| services/network_search/src/network_search_manager.cpp | 搜网聚合入口 |
| services/network_search/src/network_search_handler.cpp:154 | RIL unsol 事件注册表 |
| services/tel_ril/src/tel_ril_manager.cpp:61 | HDI V1_5 IRil 获取、TaskSchedule |
| services/tel_ril/src/tel_ril_network.cpp | 搜网相关 RIL 命令/上报 |
| frameworks/native/src/core_manager_inner.cpp | 客户端内部单例（RIL 直达口） |
| frameworks/js/network_search/src/napi_radio.cpp | radio NAPI 主实现（约 4100 行） |

# 路由：本仓边界

判断任务归属本仓还是独立仓，先看本表。

## 本仓范围（SAID 4010 电话核心服务）

- CoreService 主 SA 组装与 IPC 分发（services/core/）
- SIM 卡服务（状态/文件/账户/eSIM/STK/PIN、SIM 短信存储）
- 搜网服务（注册/选网/状态机/信号小区/运营商名/NITZ/EMC 救援）
- RIL 通信层（六业务信令）
- IMS / 卫星 / telephony_ext 跨 SA 交互
- vCard 编解码、ASN.1 codec、事件/权限工具
- JS（NAPI）/ Cangjie（FFI）/ Rust（ANI）绑定层

## 独立仓（⚠️ 本仓只有 RIL 信令层 + HISYSEVENT 上报，业务逻辑不在此）

| 领域 | 独立仓 | 本仓对应物 |
|---|---|---|
| 通话状态机/呼叫控制 | telephony_call_manager | tel_ril_call.cpp、hisysevent.yaml CALL_* 事件 |
| 短信业务 | telephony_sms_mms | tel_ril_sms.cpp、sim_sms_manager.cpp |
| 数据连接 | telephony_cellular_data | tel_ril_data.cpp、pdp_profile_rdb_helper.cpp |
| 数据存储/联系人/通话记录 | telephony_data_storage | utils/vcard/、sim_rdb_helper.cpp |

## 判断方法

1. 任务涉及"状态机决策/业务规则/数据库表"→ 先怀疑独立仓
2. 任务涉及"RIL 命令收发/unsol 上报/hisysevent 埋点/SIM 文件/搜网状态"→ 本仓
3. 不确定时 `git remote -v`+ 查 bundle.json part_name=core_service

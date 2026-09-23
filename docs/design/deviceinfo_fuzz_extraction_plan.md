# DeviceInfo fuzz 提取施工图（CVE 挖掘 P0-2 第四靶）

状态：方案论证完成，待施工（2026-09-23 记录，GLM；侦察基于与第三靶同一检出
`D:/cve_data/oh_dsoftbus`，DSoftBus 4.0.2）
目标：对 DeviceInfo 消息（认证三段握手的第二段大消息）做结构感知 fuzz——
定长字段数量远超 DeviceId，是 auth 模块最大的纯解析攻击面。
预计工时 2-4 小时（A/C/D 级直接复用第三靶资产，边际成本低）。

## 1. 数据入口（已侦察确认）

```
网络 → auth_manager → auth_session_message.c:291 ProcessDeviceIdMessage 的姊妹:
  ProcessDeviceInfoMessage(authSeq, info, data, len)
    ├─ DecryptInner（会话密钥解密——生产上 DeviceInfo 是密文，harness 跳过：
    │   靶定解密后的纯解析层，与第三靶同一取舍）
    ├─ DataDecompress（compress 分支，非 WIFI/USB 且 isSupportCompress 时）
    └─ auth_session_json.c:3388 UnpackDeviceInfoMessage(devInfo, nodeInfo, isMetaAuth, info) ← 本靶
         ├─ UnpackDeviceInfoMsgInner(3296)：按 linkType/version 三路分发
         │    ├─ WIFI/SESSION_KEY/USB → UnpackWiFi(2922, ifIdx∈{WLAN_IF=0,USB_IF=1})
         │    │    └─ CheckBusVersion(2903) + 端口/IP/offlineCode + UnpackCommon(2735)
         │    ├─ version==V1 → UnpackDeviceInfoBtV1(3009)
         │    └─ 其余(BT系) → UnpackBt(2856) + UnpackCommon
         ├─ UnpackWifiDirectInfo(2614)：staticCap/serviceFindCap/PTK(base64)
         ├─ UnpackCertificateInfo(3088)：证书链（stub 关闭，保形）
         ├─ UnpackUserIdCheckSum(3281)
         ├─ IsInvalidDeviceInfo(3352) → IsInvalidExternalAuthInfo(3312) /
         │    OldVersionInvalidExternalAuthInfo(3335)（hash/ACL 校验）
         └─ UpdatePeerDeviceName(3235) + LnnGetLocalNumInfo + 时间戳
```

## 2. 靶函数：UnpackDeviceInfoMessage（auth_session_json.c:3388）

输入 `(const DevInfoData*, NodeInfo*, bool, const AuthSessionInfo*)`，
其中 `DevInfoData = {msg, len, linkType, version}`
（interfaces/kits/adapter/auth_session_message_struct.h:30-34）——
msg/len 纯数据，linkType/version/isMetaAuth 由 harness 轮换，纯解析形态。

## 3. 依赖图（提取分级）

**A. 基础层（= 第三靶成品 `D:/cve_data/fuzz_authdev/` 整包，原地扩展）**：
- nlohmann 真 adapter（softbus_adapter_json.cpp + json.hpp v3.11.3）
- cJSON + softbus_json_utils（cJSON 面）
- anonymizer 真提取包；securec 语义 stub；error_code/mem stub
- extracted.c 已含：Opt 家族（需补 OptInt64:275）、GenerateUdidShortHash(323)、
  hexconv 三件套、SoftBusGenerateStrHash stub、AuthSessionInfo/枚举/常量
- **升级动作**：auth_framework.h 的裁剪版 NodeInfo → **全量 NodeInfo**
  （本靶几十个字段被写，不能裁）。第三靶提取链只按名访问 feature/aclState，
  全量版同名兼容，extracted.c 无需改动（审计注记一条即可）。

**B. 浅依赖（直接拷贝，标注 file:line）**：
- 同文件：UnpackDeviceInfoMsgInner(3296)、UnpackWiFi(2922)、CheckBusVersion(2903)、
  UnpackBt(2856)、SetDiscType(2847)、UnpackDeviceInfoBtV1(3009)、
  UnpackCommon(2735)、ParseCommonJsonInfo(2689)、ParseCommonJsonOptInfo(2655)、
  ParseDeviceName(2647)、UnpackWifiDirectInfo(2614)、UnpackMetaPtk(2582)、
  UnpackPtk(2598)、UnpackCipherRpaInfo(2403)、UnpackSparkCheck(2717)、
  UnpackCertificateInfo(3088，stub 关闭路径保形)、UnpackUserIdCheckSum(3281)、
  IsInvalidDeviceInfo(3352)、IsInvalidExternalAuthInfo(3312)、
  OldVersionInvalidExternalAuthInfo(3335)、UpdatePeerDeviceName(3235)、
  GenerateAccountHash(338，需补 sprintf_s 到 securec stub)、OptInt64(275)
- 跨文件纯函数：StrCmpIgnoreCase（core/common/utils/softbus_utils.c:521）、
  LnnConvertDeviceTypeToId 一族
  （core/bus_center/lnn/net_ledger/common/src/lnn_device_info.c:133-178
  + g_typeToIdMap 表 + ConvertStringToInt/InterceptTypeId/g_stringTypeId，整段拷）

**C. 深依赖（stub，取向注明）**：
- ProcessCipherKeySyncInfoPacked → no-op（enhance 框架）
- IsSupportUDIDAbatementPacked / IsNeedUDIDAbatementPacked → false
  （证书链关闭——UnpackCertificateInfo 走"不支持降 UDID"早退，VerifyCertificate 不可达）
- IsSKIdFindAclInfo → SOFTBUS_ERR（OldVersionInvalidExternalAuthInfo 走"无 ACL"）
- LnnGetLocalNumInfo → err（localStateVersion 不写，无分支影响）
- SoftBusGetSysTimeMs → 固定值（updateTimestamp 语义无害）
- LnnDumpRemotePtk / LnnDumpSparkCheck → no-op（dump 日志）
- LnnGetDeviceDisplayName → 拷贝 defaultName 出参（UpdatePeerDeviceName
  else 分支可达性）
- LnnGetLocalNodeInfo → 静态全量节点，accountId=0（使 nickName 分支可驱动）
- SoftBusBase64Decode/Encode → **真 mbedtls base64**（adapter 是
  mbedtls_base64_decode 薄壳；mbedtls 不在检出内，经 jsDelivr 取
  library/base64.c 三件套，版本记录进 README；若不可得则忠实重实现并显式声明
  偏差——base64 是 PTK 路径的解析器，不宜 stub 恒错）

**D. 结构定义（三头整拷，共约 370 行纯数据）**：
- interfaces/kits/lnn/lnn_node_info_struct.h（258 行，NodeInfo 全量 + 13 个常量）
- interfaces/kits/lnn/lnn_device_info_struct.h（59 行，DeviceBasicInfo）
- interfaces/kits/lnn/lnn_connect_info_struct.h（54 行，IfInfo/ConnectInfo，
  `ifInfo[MAX_IF+1]` 即 ifInfo[2]，WLAN_IF=0/USB_IF=1）
- DevInfoData（如上）
- 常量批：bus_center_info_key_struct.h（OH_OS_TYPE/VERSION_MAX_LEN/MAC_LEN/
  ID_MAX_LEN/WLAN_IF/USB_IF/MAX_IF）、softbus_def.h:95 NODE_ADDR_LOOPBACK、
  softbus_protocol_def.h LNN_PROTOCOL_*、lnn_device_info_recovery_struct.h:94
  IS_SUPPORT_IPV6、auth_session_json.c 文件头 JSON tag 批（第三靶已拷大半，
  补 DeviceInfo 段 tag：DEVICE_NAME/DEVICE_TYPE/…/STATIC_CAP/PTK/BROADCAST_*）
- 错误码补：SOFTBUS_INVALID_NUM、SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL、
  SOFTBUS_NETWORK_INVALID_DEV_INFO 等

## 4. 施工步骤（fuzz_authdev 原地扩展，产出第二 fuzzer）

1. 拷 B 级到 `extracted_devinfo.c`（逐字原样 + file:line 标注；与 extracted.c
   同 TU 策略，static 冲突无）
2. D 级三头拷入 `stub/lnn_structs.h`，auth_framework.h 的 NodeInfo 定义切换为
   include 该头（记审计注：第三靶裁剪版→全量版的兼容性说明）
3. C 级 stub 补入 auth_framework.h；securec 补 sprintf_s（vsnprintf 限长语义）
4. `deviceinfo_harness.c`：
   ```
   输入头 6 字节轮换: linkType(9 值表) × version{V1,V2,NEW_V1,NEW_V2}
     × isMetaAuth × AuthSessionInfo 预置(authVersion 0-3, deviceKeyId 有/无,
     udid/udidShortHash/accountHash 由种子驱动或预填定值)
   NodeInfo *node = SoftBusCalloc(sizeof(NodeInfo))
   UnpackDeviceInfoMessage(&devInfo, node, isMetaAuth, &info)
   ```
   注意 IsInvalidDeviceInfo 用 info->udid 与 nodeInfo->deviceInfo.deviceUdid
   逐字比对——**info.udid 必须预置非空**（否则全输入都 early-fail），
   种子里 DEVICE_UDID 要与预置值一致才能过校验进深路径。
5. WSL 编译第二个目标 `fuzz_authdeinfo`（build.sh 加 target；与第三靶共 A 层）
6. 快测 120s → 长跑排队：第三靶 12h 跑完后接续（或 -jobs 并行第二 worker）
7. 崩溃分诊同第三靶流程（README 已有命令）

## 5. 判读注意（本靶特有）

- **头号嫌疑族**：`OptInt64(json, NEW_CONN_CAP, (int64_t*)&info->netCapacity, -1)`
  （UnpackDeviceInfoBtV1:3040 区域）——8 字节写进 4 字节 uint32 字段，
  覆写相邻 heartbeatCapacity/netCapacity 等内存（struct 内越界，ASan 不抓，
  靠 UBSan alignment/典型值异常分诊）。同形态还有 CONN_CAP、
  ParseCommonJsonOptInfo 的 netCapacity。**种子优先构造 NEW_CONN_CAP 路径**。
- 定长数组面（ASan 直接抓）：deviceName/unifiedName/nickName[65]、
  staticCapability[100]+staticCapLen、offlineCode[4]、remotePtk[32]（base64 后
  len!=32 有检）、userIdCheckSum[4]、cipherInfo.key/iv、rpaInfo.peerIrk/publicAddress、
  ifInfo[idx].deviceIp[46]、wifiCfg[512]、chanList5g[256]
- UBSan 原码类型双关噪音预期（int64*/uint32* 互 cast）：分诊时按"原码形态"
  记录归因，不直接当 harness 假阳性删除，也不直接当新洞——走 2×2 验证线判
- CheckBusVersion 决定 WIFI 路径 early-fail（maxVersion<-1 时）——种子必须带
  BUS_MAX_VERSION/BUS_MIN_VERSION 合法值
- compress 分支（DataDecompress）不在靶内（解密层取舍），isSupportCompress
  维仅影响 ProcessDeviceInfoMessage 外层，harness 直调 UnpackDeviceInfoMessage
  不涉及

## 6. 素材位置速查

- 一切 A/C/D 资产：`D:/cve_data/fuzz_authdev/`（WSL 镜像 ~/fa，第三靶成品）
- 源检出：`D:/cve_data/oh_dsoftbus`（同第三靶）
- mbedtls base64：jsDelivr `gh/ARMmbed/mbedtls@<tag>/library/base64.c`
  （tag 与 OH 5.x third_party 对齐，取头时记录；不可得则走声明式重实现）
- 第三靶施工图/施工记录：`docs/design/auth_fuzz_extraction_plan.md`（§7）

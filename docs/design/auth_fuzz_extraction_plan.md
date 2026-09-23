# auth fuzz 提取施工图（CVE 挖掘 P0-2 第三靶）

状态：**施工完成，长跑挂机中**（2026-09-23，GLM；实施记录见 §7 与
`D:/cve_data/fuzz_authdev/README.md`）
目标：对 authentication 模块的网络消息解析做结构感知 fuzz——
dsoftbus 最大的纯解析攻击面。预计工时 2-4 小时（含调试）。

## 1. 数据入口（已侦察确认）

```
网络(BT/WiFi) → auth_connection HandleDataReceived
  → auth_manager HandleAuthData（按 type 分发）
  → auth_session_message.c:151 ProcessDeviceIdMessage(info, data, len, authSeq)
       ├─ V1: BT 链路 && len==64 && isServer → UnPackBtDeviceIdV1
       │    （memcpy_s 64→udid[65]，SoftBusCalloc 清零兜底——已审计排除）
       └─ V2: UnpackDeviceIdJson(msg, len, info, authSeq)   ← 本靶
```

## 2. 靶函数：UnpackDeviceIdJson（auth_session_json.c:2107）

主体 = JSON_Parse + 15 个字段读取 + 8 个子 Unpack。输入
`(const char *msg, uint32_t len, AuthSessionInfo *info, int64_t authSeq)`
——纯解析形态，fuzz 友好。

## 3. 依赖图（提取分级）

**A. 基础层（已有资产，直接复用）**：
- `D:/cve_data/fuzz_jsonutils/` 整包：softbus_json_utils.c + cJSON.c
  （OH 1.7.19）+ stub 四件套（comm_log/softbus_error_code/securec/
  softbus_adapter_mem）——已编译验证过（75s 独立复现 CVE-2026-87933
  的那个 harness 就跑在这套依赖上）
- 注意：cJSON.c 建议先用 87933 补丁版（排除已知 UAF 噪音），原版
  留作灵敏度对照

**B. 浅依赖（同文件直接拷贝，无框架调用）**：
- IsCmdMatchByDeviceId（cmd 匹配）
- UnPackVersionByDeviceId（2046 行）
- SetExchangeIdTypeAndValue
- UnpackSKId（793 行）
- OptString / OptInt / OptBool（auth_session_json.c 自己的 JSON 辅助，
  266-290 行区域）
- SetCompressFlag / OptString 相关辅助

**C. 深依赖（需 stub 框架调用，约 8 处）**：
- UnpackFastAuth → GetFastAuthKey/GetEnhancedP2pAuthKey → stub 成
  返回固定 SOFTBUS_ERR（走"无快密钥"路径）
- UnpackNormalizedKey → TryGetDmSessionKeyForUnpack → stub 同上
- UnpackExternalAuthInfo / UnpackExternalUserId → 外部认证路径 stub
- UnPackAuthPreLinkNode → 简单字段读取（可能属 B 级，拷时确认）
- GetLocalUdidShortHash / GetLocalDeviceId 类（GetLocal* 全家）→
  stub 返回固定串
- Anonymize 调用（日志路径）→ 已有 anonymizer 提取包可一并带上，
  或 stub 空实现

**D. 结构定义**：
- AuthSessionInfo（core/authentication/include/auth_session_key.h 或
  auth_manager.h 内，嵌套 SessionKey/SessionKeyList/AuthConnInfo）——
  拷贝整结构定义链；若嵌套过深，做字段裁剪版（保留 Unpack 路径
  触碰的字段 + connInfo.type/isServer/version/udid/uuid），**裁剪版
  必须在 harness 注释里声明与原结构的差异**（审计可追溯）
- 常量：UDID_BUF_LEN=65、UUID_BUF_LEN、DEVICE_ID_STR_LEN=64、
  SOFTBUS_OLD_V1、AUTH_LINK_TYPE_* 枚举

## 4. 施工步骤

1. `mkdir D:/cve_data/fuzz_authdev && cp -r fuzz_jsonutils/* .`（复用 A 层）
2. 从 oh_dsoftbus 拷 auth_session_json.c 的 B 级函数 + C 级函数源码
   到 `extracted.c`（每函数标注原文件:行号）
3. 写 stub 头 `stub/auth_framework.h`（C 级 8 处 + AUTH_LOG* 宏）
4. 写 harness.c：
   ```
   LLVMFuzzerTestOneInput:
     构造 AuthSessionInfo（calloc，connInfo.type 轮换 BT/WIFI/USB，
     isServer 轮换——覆盖两个分支）
     buf 拷贝输入+NUL 终止
     UnpackDeviceIdJson(buf, len, &info, 42)
     （V1 路径顺带：len==64 时直调 ProcessDeviceIdMessage 逻辑）
   ```
5. WSL 编译：`clang -fsanitize=fuzzer,address,undefined -I. -Istub
   harness.c extracted.c softbus_json_utils.c cJSON.c cJSON_Utils.c`（注意
   gnu11——strnlen）
6. 快测 120s → 修编译错/误崩 → 长跑（-max_total_time=3600 起，
   后台过夜）
7. 崩溃分诊：栈哈希去重 → 先对照已知 CVE 家族 → 真候选走
   2×2 验证线

## 5. 判读注意

- AuthSessionInfo 的字段写越界（本靶最可能的洞形态：定长数组被
  JSON 长串灌入）——ASan 直接抓
- connInfo.type 轮换覆盖分支（compress 分支只在非 WIFI/SESSION_KEY/
  USB 走）
- 已知噪音：cJSON 87933（用补丁版 cJSON 规避）

## 6. 素材位置速查

- oh_dsoftbus 检出：`D:/cve_data/oh_dsoftbus`（auth 源在
  core/authentication/src|include）
- A 层复用包：`D:/cve_data/fuzz_jsonutils/`（WSL 镜像 ~/fj）
- anonymizer 提取包（可选）：`D:/cve_data/fuzz_anonymizer/`
- WSL 工具链：clang 18.1.3（~/fv 的 ffmpeg 构建可作编译环境参照）
- 侦察记录：本文件 + 对话 2026-09-23（函数依赖扫描脚本输出）

## 7. 施工记录（2026-09-23）

成品：`D:/cve_data/fuzz_authdev/`（WSL 镜像 ~/fa，build.sh 一键重建）。
种子 6 枚零崩溃；120s 快测 1,494,196 runs 无崩溃（cov 2602 / ft 9879）；
12h 长跑（-max_total_time=43200）挂机中，~12.5k exec/s。

### 7.1 方案级偏差（影响 §3 依赖图，已按实况修正实施）

1. **JSON_*（JsonObj API）底层是 nlohmann::json（C++），不是 cJSON。**
   DSoftBus 4.0.2 的 `adapter/common/json/nlohmann/softbus_adapter_json.cpp`
   为唯一实现。§3.A"复用 fuzz_jsonutils 当 JSON 后端"的假设不成立——
   用 cJSON 复刻会把靶面换成自写 shim，证据链作废。实际做法：
   引入该 cpp 原文件 + nlohmann v3.11.3 单头（jsDelivr 取得，检出内无
   third_party），与 C 主体经 extern "C" 边界混编（clang/clang++ 18.1.3）。
   cJSON 保留真实现——凭证协商子链（CreateJsonObjectFromString/
   cJSON_Duplicate/GetJsonObjectNumberItem）生产上就是 cJSON 面。
   **生产双解析器形态完整落地**。
2. cJSON_Utils.c 不需要（A 层包本就没有，提取链不触 MergePatch）→
   §5"已知噪音 cJSON 87933"被结构性排除，无需换补丁版 cJSON。
3. §4.5 编译行更正：实际为 harness/extracted/softbus_json_utils/cJSON/
   anonymizer（gnu11 C）+ softbus_adapter_json.cpp（c++17）六单元，
   clang++ -fsanitize=fuzzer,address,undefined 链接。
4. 轮换维在施工图基础上增加两维：isConnectServer（IsCmdMatchByDeviceId
   分支）与初始 idType（SetExchangeIdTypeAndValue 客户端 NETWORKID 分支），
   连同 connInfo.type×isServer 共 4 维，取自输入前 4 字节。

### 7.2 C 级 stub 落地差异（相对 §3.C 预案）

- SoftBusGenerateStrHash 未走"真 crypto"也未走恒错，用确定性 FNV 变体：
  只替换 hash 值不替换长度/边界行为（提取链对 hash 值无分支判断）
- GetFd/SoftBusSocketGetPeerName 给固定 127.0.0.1 而非恒错：
  使 DevIpHash→hex→strcmp 深路径可达（该分支否则死码）
- LnnGetLocalNodeInfo 返回 feature 含 BIT_INFO_COMPRESS 的静态节点：
  compress 协商分支由远端 JSON 字段驱动（本靶输入面）
- Anonymize 家族按 §3.C 备选带上了真提取包（fuzz_anonymizer）
- securec stub 的 strcpy_s/memset_s 补齐**真实边界语义**——
  JSON_GetStringFromObject 的定长缓冲防护就在这层，语义弱化会吞洞/造假阳性

### 7.3 结构裁剪明细（§3.D）

AuthConnInfo（仅 type）、NodeInfo（feature/aclState）、AuthManager（占位）
三处裁剪，均已在 stub/auth_framework.h 逐条声明差异并核对"提取链不触碰
被裁字段"；AuthSessionInfo 字段与原结构一致（nodeInfo 类型为裁剪版）。


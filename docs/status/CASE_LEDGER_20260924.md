# 单一案例台账（2026-09-24）

对应：比赛审计 2026-09-23 P0.2（"建立单一案例台账：每例区分候选、源码核验、等价
harness、真实库复现、产品影响、已提交、官方接受；分别记录，允许未知。把人工发现、
已知漏洞回验和自动检出分开"）。

数据源：本机 `cases/*/case.json`（13 例，HEAD `12ba819`）为准；文档/CHANGELOG 与
case.json 冲突处逐条标注（见 §3 漂移记录）。产品可达性全部未建立，确认产品漏洞数 0。

## 1. 台账主表

所有 13 例均为**已知漏洞回验**（new_discovery=false：公开 CVE 在 OH 检出的修复缺口
案例）；无人工新发现；自动检出来自 auth fuzz 线（见 §2，目前 0）。

| 案例 id | CVE | CWE | 组件 | 源码核验(L4) | 真实库复现 | 产品影响 | 提交材料 | 已提交工单 | 官方接受 |
|---|---|---|---|---|---|---|---|---|---|
| cjson-merge-nonobject-alias | CVE-2026-87933 | CWE-416 | cJSON | ✅ 人工源审 | ✅ 库级复现+第二人（CHANGELOG 09-16；case.json runtime_status=not_run，见漂移#2） | not_established | —（演示用途） | 未提交 | 未知 |
| curl-native-ca-reuse-mismatch | CVE-2026-80231 | CWE-488 | curl | ✅ 中间形态探针+源级 | not_run | not_established（字段缺省） | — | OHSA26-092209031（09-21） | 未知 |
| curl-psl-supercookie-tailmatch | CVE-2026-82209 | CWE-201 | curl | ✅ 同上 | not_run | not_established | — | OHSA26-092226014（09-21） | 未知 |
| ffmpeg-nvdec-sep-ref-doublefree | CVE-2026-64832 | CWE-415 | ffmpeg | ✅ 四信号+L4 | not_run（需 NVDEC GPU） | 未记录 | ✅ | OHSA26-092224773（09-21，见漂移#1） | 未知 |
| ffmpeg-hqdn3d-dynamic-size-oob | CVE-2026-66036 | CWE-122 | ffmpeg | ✅ 批量+人工 L4 | ✅ WSL 运行时对照通过（P0_EXECUTION 09-22；case.json 无 runtime 字段，漂移#3 同类） | 未记录 | ✅ | 未提交 | — |
| ffmpeg-quirc-resize-oob | CVE-2026-66041 | CWE-787 | ffmpeg | ✅ 四信号+L4 | ✅ WSL 运行时对照通过（同上） | 未记录 | ❌（审计机已有嵌套提交记录，见漂移#3） | 未提交（本机记录） | — |
| ffmpeg-lcldec-zlib-tail-disclosure | CVE-2026-66038 | CWE-908 | ffmpeg | ✅ 批量+人工 L4 | not_run | 未记录 | ✅ | 未提交 | — |
| ffmpeg-dvbsub-parser-capacity-overflow | CVE-2026-70628 | CWE-190→787 | ffmpeg | ✅（含参考提交勘误） | not_run | 未记录 | ✅ | 未提交 | — |
| ffmpeg-ty-ac3-trim-underflow | CVE-2026-65704 | CWE-191→787 | ffmpeg | ✅ | not_run | 未记录 | ✅ | 未提交 | — |
| ffmpeg-wmaenc-extradata-padding | CVE-2026-52296 | CWE-125 | ffmpeg | ✅ | not_run | 未记录 | ✅ | 未提交 | — |
| ffmpeg-floodfill-point-stack-oob | CVE-2026-65705 | CWE-787 | ffmpeg | ✅（含参考提交勘误） | not_run | 未记录 | ✅ | 未提交 | — |
| ffmpeg-swaprect-temp-row-oob | CVE-2026-65706 | CWE-787 | ffmpeg | ✅ | not_run | 未记录 | ✅ | 未提交 | — |
| openssl-ocb-oneshot-iv-discard | CVE-2026-45445 | CWE-325 | openssl | ✅ | not_run | 未记录 | ✅ | 未提交 | — |

材料位置：提交工单材料在 `D:/cve_data/submission_*`（审计 P0.5 已指出绝对路径依赖
需整理为可迁移交付包，未做）。

## 2. 新发现线（自动检出 pipeline，与上表分开计数）

- **auth T3（DeviceId 链 harness）**：`D:/cve_data/fuzz_authdev`。截至 09-24 上午：
  累计 1.223 亿次执行（宿主机隔夜休眠中断一次，有效约 3.3h）、cov 2993/ft 13542、
  corpus 1925、**零崩溃零泄漏**；白班 8h 复跑进行中（旧语料热启动）。
- **auth T4（DeviceInfo 链）**：施工图已论证（`docs/design/deviceinfo_fuzz_extraction_plan.md`），
  待施工。头号嫌疑族：BtV1 的 `OptInt64` 8 字节写 32 位 netCapacity（struct 内越界）。
- 当前新发现数：**0**（无崩溃即无候选）。

## 3. 记录漂移（台账与既有文档不一致处，需回填修正）

1. **nvdec 提交状态**：case.json 记 OHSA26-092224773 已于 09-21 提交；PROJECT_STATE
   09-22 与 P0_EXECUTION 09-22 仍列为"待提交 5 案"之一。以 case.json 为准（3 提交 +
   材料就绪待提交），PROJECT_STATE 下次更新时修正口径。
2. **cjson 运行时状态**：case.json `runtime_status: not_run`；CHANGELOG 09-16 记
   bubblewrap 运行矩阵 26/26 + 第二人复现通过。case.json 漏回填，应更新为已复现并
   链接运行记录。
3. **双机工作集分叉**：审计机（2026-09-23 审计）另有未提交的 FFI/triage 代码与
   IPC/KV 两候选、quirc 嵌套提交记录；本机无。github 443 不通期间无法对齐，台账
   仅覆盖本机 HEAD。审计机工作落 PR 后需并入本表。

## 4. 按证据完整度的优先序（对应审计 P0.3）

1. **运行时已验证 3 例**（cjson / hqdn3d / quirc）——最有条件闭合成"完整案例闭环"
   （补安全影响论证 + 修复对照 + 分支矩阵），cjson 另作工具复现能力演示（不宣传新发现）。
2. **已提交待审 3 例**（curl×2 / nvdec）——跟踪工单回执，官方接受状态保持"未知"。
3. **材料就绪待提交 8 例**——按审计建议由所有者逐例提交（其中 lcldec/dvbsub 为
   P0_EXECUTION 已人工 L4 核验的新成案）。
4. **产品可达性**：13 例全部未建立——审计 P1.6 纵向闭环的首要补齐项。

## 5. 口径声明

- 确认产品漏洞数：0（产品可达性未建立，不因提交动作改变）。
- 官方接受：3 张工单均处"已提交-未知"状态，无接受证据，不宣称。
- 本台账不改变任何 case.json；漂移修正应回填对应 case.json 与 PROJECT_STATE。

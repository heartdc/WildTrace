# 2026-10-07（影响矩阵 cJSON 基线回填：？ 18→12）

- **cJSON 各分支基线实测回填**（每分支 README.OpenSource，2026-10-07）：v4.1=1.7.16 / v5.0=v5.1=v6.0=1.7.17 /
  v7.0=1.7.19 / master=1.7.19。勘误两条：① 该仓 release 分支**无 v 前缀**（OpenHarmony-4.1-Release 等，
  gitee/gitcode 同 sha）；② **v7.0 分支仅存在于 gitcode 镜像**（388cfc96），gitee master 为停更镜像
  （1.7.17，2025-09），现行开发 master 在 gitcode（1.7.19，与 cjson 案 observed_version 一致）。
- `OH_BRANCHES` 补 cjson 列 + 测试钉死（基线存在性逐分支断言；kb 联接全分支判定回归）。矩阵重生成：
  **19 案 × 6 分支 = 🔴 96 / — 6 / ？ 12**（cjson_merge_alias 经 kb 联接 CVE-2026-87933 全六分支 affected，
  1.7.16–1.7.19 均在受影响列表内）。剩余 ？格均为 OH 原生案（hiappevent/ipc/kv）旧分支，待 affected_raw。

# 2026-10-07（平台 16 单再核验 + 催办材料 + 台账卫生）

- 补录当日事件：PR #99 落库（将 10-04 批次成果入库：hiappevent 建案文件、IMPACT_MATRIX/VULN_REPORT
  交付件重生成、impact_matrix `base/` 前缀映射与测试）；issue #100 创建（hiappevent 第 17 单提单所需
  两项构建溯源字段——官方完整树实际构建 commit 与 manifest 分支，等对侧回复；表单草稿与 PoC 已备
  `D:/cve_data/submission_hiappevent/`）。
- **平台 16 单再核验（2026-10-07 21:40，已登录逐单）**：全部"待受理"、有效性/等级均 "—"，与 09-30 实测
  零变化；09-22 批已 15 天、09-28/29 批已 9 天。催办邮件样本入库（`docs/status/URGE_MAIL_DRAFT_20261007.md`，
  按 0930 版 §5 模板：按批次、附最强三单），交所有者发送；核验记录 `docs/status/TICKET_FOLLOWUP_20261007.md`（PR #101）。
- 台账卫生：issue #24（clang_facts 括号声明符 size_of 误算）核实**已修复**（commit 0f4e229 落地
  `_POINTER_DECL` 路径 + counter-example 回归测试 `tests/test_clang_facts.py`，本次关单前本地复跑 37 项 OK），
  关闭；TECHNICAL_SPEC §7 诚实清单对齐现状（性能复测与干净环境复跑已完成、真库级证实 1→2 项、
  ？格 14→18 口径修正）。

# 2026-10-04（CJ FFI 真库验证批次收口：hiappevent 证实建案 + account 证伪入档）

- 合并 AerGap 两项成果（官方完整树真库验证批次，构建阻塞已解除——根因 git-lfs 缺失）：
  - **PR #97 hiappevent 真库级证实**：官方完整树（471+ 项目、官方构建链、零 FFI 源码改动）构建的
    `libcj_hiappevent_ffi.z.so` 上，对照不崩 / 候选（filters.head=NULL+size=1）SIGSEGV，崩溃帧归属库内 0x11c9a。
    建 `cases/hiappevent_ffi_watcher_null_filter/`（真库级口径，CWE-476，新发现）；
  - **PR #98 account 真库级证伪**：四组 malformed 全被 FFI 层参数检查拦截，Tier B 预测不成立，诚实关闭入档。
- `impact_matrix` 组件映射补 `base/` 前缀（hiappevent 判 oh_native；测试钉死）。交付件重生成：19 案 × 6 分支 =
  🔴 90 / — 6 / ？ 18。台账追记 2026-10-04 批次。真库级证实累计：IPC（已提交）+ hiappevent（待提交，第 17 张单）。

# 2026-09-30（性能实测落盘 + 管线性能修复 + 使用说明书 + 干净环境复跑）

- **性能交付件完成**（`docs/deliverables/PERFORMANCE.md`，现役口径实测）：dsoftbus 681,529 行 / 10 层管线
  **651.7s（~1,046 行/s）** / 3033 lead（高危 580）/ 管线峰值内存 176.4MB；CJ FFI 136 仓 173,901 行 / 272s / 380 lead（高危 84）/ 58.4MB。
  跨函数 UAF 去重后 60 条（历史未去重 889 的口径差已在交付件中声明）。
- **管线性能修复**（实测时发现的真实回退）：`_FUNC_RE` 惰性类型段回溯致大树解析灾难性变慢（2MB 文本 25s）——
  加 80 字符上界（26s→13s）；括号匹配改 `finditer` 括号位迭代；新增按累计字节数限界（220MB）的进程级解析缓存
  （P1-P9/CallGraph/cross_uaf 8 个消费者共享一次解析，热访问 0.002s）。行为不变，1058 项全量回归通过。
- `tools/perf_measure.py`：新增 autopilot 阶段（子进程自报峰值内存，POSIX getrusage / Windows GetProcessMemoryInfo 零依赖）、
  Windows 原生 RSS（ctypes 显式调用约定）、汇总取管线自身峰值、markdown 单行单元格修复。
- **使用说明书**（交付件 3 文档部分）：`docs/deliverables/USAGE.md`——依赖环境、五组主命令速查、覆盖率与粒度口径（评价备注 7 的显式回应）、常见问题。
- **干净环境复跑通过**：全新 venv `pip install -e . --no-deps` + 全量 1058 项 OK。
- IPC/KV 两案补 `l4_evidence`（L4 链路 + 真库级证实口径）——漏洞分析报告 18/18 案全带源码级证据引用。

# 2026-09-30（P0 落地 + 闭环复评：真值宏抑制与智能指针参数建模）

- 回放实验的两项 P0 修复落地（`scan_p6`）：
  - **真值宏抑制**（`_TRUTHY_MACRO_GUARD`）：识别 OH 的 `CHECK_AND_RETURN*(var, ...)` 真值形态守卫——
    消除回放实验中确认的 SocketUpdateCocConnectionParams 误报类；
  - **智能指针参数建模**（`_SMART_PTR_PARAM`）：`shared_ptr/unique_ptr` 参数（含 const&）进入 P6 可空指针模型——
    GT4（observer 修复×7）的形态缺口在机制层闭合。
- **闭环复评**（同一修复前 worktree）：13→12 条——消失的恰好是目标误报，其余 12 条全部保留、置信度无漂移（零误伤）；
  GT4 站点因解引用数 <3 未达发射阈值，阈值加权成为有 ground truth 的下一项（不盲调）。
- 新增 `tests/test_p6_smartptr_macros.py`（8 项：智能指针三形态发射/检查抑制/真值宏抑制/他变量宏不误抑制/比较形态不误抑制）。
  1058 项全量回归通过。

# 2026-09-30（已知答案反向评估：communication_bluetooth 回放实验）

- 首个 ground truth 回放实验（师兄意见的方向二验证策略）：以该仓 4 个已合并安全修复（2024-06/09/12、2025-08，全为空指针类）
  为已知答案，在修复前基线 `59cac79b` 回放 autopilot（173 cpp / 47.9K 行 / 1472s）。
- **正向 0/4**：四个盲点全部为非裸指针形态（局部 sptr / 成员 pimpl / shared_ptr 参数 / 宏展开取指针）——指针建模差距的定量证据；
- **反向**：13 条 P6 发现经严格函数体对比裁定——2 确认误报（真值宏检查不可见、过程间语义防护不可见，根因均已定位且可修）、
  0 社区直接证实（宽松窗口初判 4 被纠正，教训=必须函数体粒度）、11 至今开放（c_adapter 的 nativeScanFilter ×19 解引用系列，
  与 30 条候选的 bluetooth 验证执行件合流）；
- 产出六项 ground truth 支撑的 roadmap（shared_ptr 参数建模与真值宏抑制为 P0）。
  详见 `docs/analysis/RETROSPECTIVE_EVAL_BLUETOOTH_20260930.md`。

# 2026-09-30（合并 function-scope-rules：函数作用域规则引擎入册）

- 合入 2026-09-14 完成并经一轮 review 修复的 `glm/function-scope-rules` 分支（此前遗留在远端未合）：
  `ohvul/detect/function_rules.py`（整数溢出 / 空指针解引用 / 固定缓冲拷贝三条函数作用域规则）+ 34 项配对真假测试。
- 定位：内置正则粗筛之上的精度层——削减两类已知误报（every-deref CWE-476 泛报、sizeof-only CWE-190 泛报）；
  守卫精度（if 守卫抑制、解引用后检查仍报、分支内检查标注为已知漏报）；产出 schema 0.3 + EvidenceBundle，入证据链管线。
- `ohvul/benchmark.py` SCANNERS 注册 `function_rules`：配对基准可对比 builtin vs function_rules 的误报削减（评价维度"准确性"的可度量证据）。
- 兼容性验证：与当前 master 零冲突；合并树全量回归 1050 项 OK（5 skipped + 1 expected failure，即如实标注的已知漏报）。
- 分支清理：删除远端/本地纯残留分支（allow-gpt6-astra、execution-sandbox-design 等 12 个，均核实为 master 已有新版或逐字节一致）。

# 2026-09-29（追加二十：D 组基础设施清理——CPG 落盘位置 / 有界读取 / 宏误报钉死）

- `joern_bridge`（审计 D13）：CPG 二进制不再写入被审计树根（数百 MB 落在被审计目录：只读源根构建失败、污染证据树）——
  改写入分析环境 `/tmp/wildtrace-cpg/<源根哈希>.bin`（`cpg_dir` 可配置；按源根命名使跨运行复用一次构建，dsoftbus 级重建省 ~158s），
  新增 `remove_cpg()` 显式回收。
- `llm_poc`（审计 D14）：上下文/头文件读取改为 256 KiB 有界读取（`_read_head`）——特制多 GB"源文件"不再整读进内存后才切 3000 字符；
  截断显式标注；行号超出读取头时返回明确说明而非空上下文。
- 宏误报（审计 D15）：实证确认 dsoftbus `LIST_FOR_EACH_ENTRY_SAFE` 误报机制（`#define` 宏体被当函数解析、宏实参参与位置别名）
  已被追加十六的 define-skip 修复关闭——复现历史形状（宏体含 pos->member 解引用 + 调用方 free 后调用宏）零发现，
  回归测试钉死防止回退。
- 新增 `tests/test_infra_hardening.py`（9 项）。1016 项全量回归通过。

# 2026-09-29（追加十九：残余 B/C 组清理——检测引擎 P2 六项 + 报告生成器 P2 四项）

- 检测引擎（B 组）：
  - P6 补扫 `*.cpp`（旧版只扫 `*.c`，C++ 空指针不可见）；
  - autopilot `generate_poc` 文件名加 finding_id 哈希后缀（前 40 字符相同的长 ID 不再互相覆盖 PoC）；
  - P8 打分用与扫描器一致的 wrapper 感知正则定位释放点（`SoftBusFree`/`av_free` 释放的指针首次能触发 "-30 reassigned after free" / "-15 error-path free"）；
  - scan_p2 传行窗口而非 21 字符切片（潜伏雷排除）；
  - cross_uaf 新增 `freed_any` 追踪被释放的**局部变量**——`T *loc = malloc(..); free(loc); sink(loc);` 类局部 UAF 从全漏到可检出（模式 A/C 的 caller 侧判定改用 freed_any，callee 侧仍严格限参数避免同名局部误报）；
  - `run()` 用调用图回填 reachability（原所有正则层发现恒为 "n/a" 的死字段激活）。
- 报告生成器（C 组）：
  - `vuln_report.read_case` 边界防护：字符串型 evidence 列表、`component: null`、dict 型 cwe 不再崩溃；输出已存在时拒绝静默覆盖（`--force` 显式覆盖）；
  - 源码片段从纯指针升级为内容承载：案例目录 `source_snippet.txt/.c` 存在则嵌入；否则引用已记录的源码级证据（oh_source.l4_evidence / gap_evidence / 描述性 evidence_locations 值）——重生成后 18 案中 16 案带证据引用（赛题交付件 #1 "位置与内容"要求）；
  - `competition_report` 空 cases 目录大声失败（原产出 cases=0 的"成功"报告）；markdown 先于 JSON 发布（半程失败不再留下已发布的 JSON）；
  - markdown 表格转义（vuln_report 概览/详情 + impact_matrix 行，字段含 `|`/换行不再破表）。
- 新增 `tests/test_report_robustness.py`（13 项）。1007 项全量回归通过。

# 2026-09-29（追加十八：影响矩阵 kb 联接 + 性能测量修复——？格 75→14）

- `tools/perf_measure.py`（审计 A1）：`system_peak_rss_mb()` 修复 rss 双重除以 1024 的计算错误
  （旧表达式 KB→MB 后再 //1024，读数几乎恒 0——PERFORMANCE 交付件的内存列因此一直会是零）；无 getrusage 平台返回 0.0。
- 影响矩阵 kb 联接（审计 A2）：`ohvul.impact_matrix` 按 CVE 联接 `kb/third_party_targets/records.json`（源 cvelistV5，
  全部 16 个案例 CVE 在库）。判定新增首选规则 `kb_branch_verdict`：cvelist 边界语义——起点 ≤ 基线且跨度内无修复点即 affected，
  全部适用区间被修复点封顶即 fixed；无修复记录（semantics=none）时上界开放；commit hash 条目跳过。
  CLI 新增 `--kb`（默认自动发现 `<cases>/../kb/third_party_targets/records.json`）；`ohvul.vuln_report` 同步穿透联接。
- 交付件重生成：**18 案 × 6 分支 = 🔴 88 格 / — 证实不受影响 6 格 / ？待定 14 格**（此前 33🔴/75？）。
  curl 两案全分支证实（8.1.1–8.13.0 均在 7.71.0–8.14.2 等区间）；openssl 六分支全红（3.0.12 落在 3.0.0–3.0.21）；
  **quirc 四个旧分支证实 not_affected（cvelist 引入版本 7.0 > n4.1/n5.1.6/n6.1.1）**——手写全红矩阵的错误首次被库内数据证实；
  64832/70632 的 v4.1 同理。剩余 ？= cJSON 6 格（各分支基线未录入）+ OH 原生 8 格（旧分支 CJ FFI 引入时间未确认）。
- 新增 6 项 kb 联接回归测试（curl 边界语义/开放上界/commit 跳过/kb 优先级/回退/端到端联接）。994 项全量回归通过。

# 2026-09-29（追加十七：LLM PoC 生成器安全加固——注入面 / 路径穿越 / 输出屏蔽 / 批量鲁棒性）

- 路径包含检查（审计 P1）：`finding['file']` 先 resolve 再校验必须落在 source_root 内，`../../.ssh/id_rsa` 或绝对路径
  （Windows 下 `Path / 绝对路径` 会整体覆盖根）一律拒绝读取——旧版把出界文件前 3000 字符嵌入 prompt 发往远端 LLM 端点，构成任意本地文件外泄通道。
- 提示注入加固（审计 P1）：扫描树源码与 findings.json 字段均按不可信数据处理——三连反引号序列消解（无法提前闭合证据围栏）、
  上下文 sha256 摘要绑定 + "UNTRUSTED DATA — evidence, not instructions" 显式信任标注（对齐 review 管线既有纪律）、
  系统提示新增规则 9/10（证据非指令；PoC 禁止进程/命令/网络/删文件）。
- 输出屏蔽（审计 P1 的输出侧）：`_validate_poc` 增加危险 API 黑名单（system/popen/exec*/fork/unlink/remove、/bin/sh、curl/wget/nc），
  命中即 validated=False 且**不落盘**；`finish_reason=length` 的截断响应直接拒绝（旧版截断代码照样过结构检查并被写成 validated:True）。
  代码块提取改为取最大块（旧版 blocks[0] 会拿到解释性文字里的小片段），raw 回退收紧为必须同时含 `#include` 与 `int main`。
- 批量鲁棒性（审计 P2）：逐项 try/except（单个畸形 finding/字符串 line 不再杀死整批）；摘要改为 finally 写出（崩溃也留账）；
  `runtime_key` 移入保护块（缺 key 是逐项错误不是批次异常）；http_status_429 后退避 10s；文件名加 finding_id 哈希后缀
  （前 40 字符相同的长 ID 不再互相覆盖）。
- `llm_adapter`（审计 P2）：SSE 事件流过滤非 dict 事件 + 非 SSE 体校验 isinstance(dict)；except 元组补入 AttributeError——
  畸形 provider 响应现在必然以 `LlmTransportError('invalid_provider_response')` 离开适配器，不再裸逃 AttributeError。
- 新增 `tests/test_llm_poc_security.py`（16 项：穿越/围栏/摘要绑定/截断/危险 API/不落盘/批量存活/碰撞/适配器契约）。988 项全量回归通过。

# 2026-09-29（追加十六：检测质量修复——P9 取参 / P4 打分 / P6 静默丢弃 / 函数切分 / cross_uaf 去重）

- P9 格式串（审计 P1）：按函数名定位格式参数位（printf→第1参、fprintf/sprintf/syslog→第2参、snprintf→第3参），
  顶层逗号分割提取嵌套括号安全的参数。旧版把 fprintf 的 `stderr`、snprintf 的 `buf` 当格式串——字面量格式代码的系统性误报。
- P4 打分（审计 P1）：`struct_type` 改承载 size 变量（旧为函数名 "memcpy"），"+20 size 为直接参数 / -25 有边界检查 / -15 尺寸钳制"
  三个因子首次真正测试 size 变量；PoC 模板同步。
- P6 静默丢弃（审计 P1）：调用方对传入参数有空检查时**降 20 分保留发现**（新因子 "-20 (caller null-checks arg)"），
  旧版 `continue` 直接丢弃且 `is_pointer_checked_by_caller` 实为"调用方恰有同名参数"即 True——零分析的全量丢弃。
  CallGraph 构建时紧凑记录每函数 null_checked 变量集合（不存函数体）。
- 函数切分（审计 P1）：`_iter_functions` 先做长度保真的注释/字符串掩码再做括号匹配——注释里的撇号不再吞掉整个函数
  （742K 行级大面积 FN）、注释内 `}` 不再截断函数体、`// {` 不再吞并下一函数；`else if` / `#define` 宏不再被当成函数；
  cleaned 的块注释按换行数替换，行号偏移保真（cross_uaf 报告行号不再漂移）。
- cross_uaf 重复计数（审计 P1）：模式 A/B/C 均按 (callee, var) 去重——旧版每个调用点发一条，3000 次 `sink(a)` 调用产出 3000 条
  相同发现（"889 条"的主要水分来源），同时消除 O(调用点数×函数体长) 的重复正则扫描。
  模式 A 改为"free 之后任一调用点"（旧版只看首次出现，漏报先合法调用后 free 再传的场景）；
  模式 B 定位**传入该变量**的调用点取最后一次（旧版 len(post)>len(pre) 计数启发式同时产生漏报和误报），并遵循 NULL 重置豁免（与单函数 P8 一致）。
- cross_uaf facts 同名冲突（审计 P1）：同名多定义——事实完全相同则保留（归属无关），事实不同（static 同名不同实现）判歧义丢弃，
  旧版静默 last-writer-wins 造成跨文件张冠李戴。`_parse_params` 位置对齐：函数指针/数组/未命名参数保留空槽，
  后续参数不再错位一格（位置别名 off-by-one）。
- 新增 `tests/test_detection_quality.py`（17 项）。972 项全量回归通过。

# 2026-09-29（追加十五：审计修复——影响矩阵诚实化 + Joern 层接线 + 报告口径修正）

- 影响矩阵（审计 P0）：`ohvul.impact_matrix` 移除跨组件基线兜底——旧实现缺组件基线时回退用 ffmpeg 版本号判定 curl/openssl/cjson，
  78 格全红是数值巧合的伪造结论。补全 6 分支（v4.1–master）× ffmpeg/curl/openssl 基线；CVE 5.0 范围字段语义修正（version/lessThan 映射曾颠倒，多区间取最宽）。
  判定规则证据化：结构化受影响范围（`affected_raw`）> 版本等价传播（分支基线与实测验证基线同版本）> ？不推断。
  交付件重新生成：18 案 × 6 分支，🔴 证实 33 格 / ？待定 75 格；旧手写 13×6 全红版已归档 `docs/analysis/IMPACT_MATRIX_HANDAUTHORED_20260929.md`，其口径未经分支级验证。
- `ohvul.vuln_report`（审计 P1）：分支影响段复用 impact_matrix 判定引擎（旧版硬编码 6 分支列表、所有 third_party 组件无条件全红）；VULN_REPORT.md 已重新生成，33🔴/75？ 与矩阵一致。
- Joern 层接线（审计 P0："11 层"实为死代码）：autopilot 新增 `--joern` 显式启用第 11 层，J4/J6/J8 → Finding 转换（CWE/严重度/置信度保留）+ 报告新增 joern 统计块；默认 10 层不触碰 WSL，不可用时警告降级不崩溃。
  `ohvul.joern_bridge` 健壮性：is_available/subprocess 全异常安全（WSL 缺失返回 False 而非抛异常）；输出 UTF-8 errors=replace（cp936 主机不再 UnicodeDecodeError）；
  Scala 侧 esc() JSON 转义（含引号/反斜杠/换行的代码不再静默丢发现）；路径 shlex 引用（含空格路径可用）；CPG 失败只试一次（旧版每查询重试最长 33 分钟）。
- 报告口径（审计 P0/P2）：`summary.scanners` 如实列出执行过的层（旧版漏报 cross_uaf 层）；控制台 conf>=70 从"80+ 加 60-79 的一半"估计改为精确计数；
  cross_uaf 发现置信度不再全员 50（+5 跨函数别名证据、高危 +10——旧版 `--min-confidence 51` 会整层静默丢弃 889 条发现）。
- autopilot 崩溃修复（审计 P1）：total_lines 行数估计改为排序采样 + with 关闭句柄 + OSError 防护——树上出现名为 `*.c` 的目录不再在写报告前杀死整跑。
- 交付文档：VIDEO_SCRIPT 预检命令修正为 `python -m ohvul.toolchain --output`（旧 `ohvul.toolchain_preflight` 模块不存在，录制第 1 步必失败）。
- 新增 `tests/test_impact_matrix.py`（9 项：不跨组件兜底回归/版本等价/CVE5.0 语义/多区间合并/渲染总计）与 `tests/test_autopilot_joern.py`（5 项：默认不触碰桥接/不可用降级/发现转换往返/层级如实/跨函数置信度）。
  955 项全量回归通过。

# 2026-09-29（追加十四：LLM PoC 生成器——从模板升级到可编译代码）

- `ohvul.llm_poc`：读 autopilot lead JSON + 源码上下文（15 行前后 + includes），喂给 LLM（glm-5.3 via z.ai），生成完整可编译 C PoC。
  包含：prompt 构建（安全研究员角色 + 8 条代码规则）、代码块提取、4 层验证（长度/main/includes/目标函数引用）、批量生成、摘要报告。
  CLI 入口：`python -m ohvul.llm_poc findings.json <source_root> --output llm_pocs`。
- 15 项专项测试全过（prompt/提取/验证/上下文/mock 生成/错误处理），895 项全量回归通过。

# 2026-09-29（追加十三：cross_uaf 集成到 autopilot——dsoftbus 889 条跨函数发现）

- autopilot v3 集成 `ohvul.cross_uaf`：在 9 个正则模式族 + Joern CPG 之上新增跨函数 UAF/双重释放检测。
- dsoftbus 实测：**889 条跨函数发现**（746 P8_cross_uaf + 143 P8_double_free），全管线 2466 条 lead，217 秒。
- 880 项全量回归通过。已知宏误报（LIST_FOR_EACH_ENTRY_SAFE）待后续过滤。

# 2026-09-29（追加十二：跨函数 UAF / 双重释放检测——位置别名解析）

- `ohvul.cross_uaf`：轻量跨函数别名追踪，检测三种单函数 P8 无法看到的模式——
  A（Free→Pass）：caller free 后传给 callee deref；B（Callee-Frees）：callee free 后 caller 使用；C（Double-Free）：caller 和 callee 都 free。
- **位置别名解析**：caller 的 `ptr` 传给 callee 的 `p`（参数名不同），通过参数位置映射正确关联。
- 7 项专项测试全过（3 种模式 + 位置解析 + 安全用例不误报 + 元数据 + 置信度）。880 项全量回归通过。

# 2026-09-29（追加十一：Joern CPG 深度分析引擎集成）

- `ohvul.joern_bridge`：集成 Joern v4.0.640（Yamaguchi NDSS'14 代码属性图）作为深度分析后端，与正则模式族互补。提供 J4（无界拷贝）/ J6（空指针路径敏感）/ J8（UAF 跨定义分析）三个 CPG 查询。
- 实测 dsoftbus 742K 行：CPG 构建 158s + 查询 58s = **8153 条 lead（J6=8106 + J8=47）**。Joern 的路径敏感分析能过滤掉正则引擎无法排除的假阳性（如 `safe_check` 中有空指针检查的函数）。
- 873 项全量回归通过。Joern 安装于 WSL `/opt/joern`（OpenJDK 17 + joern-cli v4.0.640）。

# 2026-09-29（追加十：Autopilot v2——9 模式族覆盖任意 C/C++ 代码）

- `ohvul.autopilot` v2：在 CJ FFI P1-P3 基础上新增 **P4-P9 六个通用模式族**——P4 无界内存拷贝 / P5 栈缓冲溢出 / P6 空指针解引用 / P7 分配整数溢出 / P8 释放后使用 / P9 格式化字符串。**不再限于 CJ FFI 面，可扫描任意 C/C++ 代码**。
- 实测：dsoftbus 742K 行（无 CJ）→ **2756 lead（490 高危）+ 2756 PoC，139 秒**；CJ FFI 63 仓 → 210 lead + 210 PoC，54 秒。869 项全量回归通过。
- 每条 lead 自动生成对应模式族的可编译 PoC 模板（含触发提示/CWE/编译命令）。

# 2026-09-29（追加九：端到端自动化分析 + PoC 自动生成）

- `ohvul.autopilot`：一条命令 `python -m ohvul.autopilot <source_root> --output <dir>` 自动完成：面发现（CJ FFI 检测）→ 3 模式族扫描（P1 null_len / P2 truncation / P3 nested_deref）→ FFI 导出追踪 → **PoC 自动生成**（每条 high/medium lead 一个可编译 C 调用器）→ 统一报告（JSON+MD）。
- 实测：CJ FFI 63 仓 491 文件 240K 行 → **83 条 lead（40 high）+ 83 个 PoC 文件，耗时 26 秒**。868 项全量回归通过（4 环境跳过）。
- 赛题对齐：能力 #1 自动化分析 → **一条命令端到端**；能力 #3 PoC 产出 → **自动生成 C 调用器**（含 FFI 导出追踪 + 结构体桩 + dlopen 模板）。

# 2026-09-29（追加八：PoC 补全 + 影响矩阵 + 完整漏洞报告——赛题对齐）

- **PoC 覆盖 11/13**：补写 dvbsub/lcldec/ty/wmaenc/swaprect 五案可执行 PoC + 复制已有四案 → 11/13。curl_native_ca（需 curl 环境）和 nvdec（需 GPU）为源级对照。
- **版本分支影响矩阵**：13 案 × 6 分支（v4.1→master），78 格 affected。`ohvul/impact_matrix.py`。
- **完整漏洞报告**：13 案 × 5 段（源码/描述/PoC/影响/修复），`ohvul/vuln_report.py` + 1834 行 `VULN_REPORT.md`。case.json 补齐 source_file/trigger/attack_path。

# 2026-09-29（追加七：R2 候选调用器三件 + 任务书 H 节）

- `hiappevent_null_watcher.c`（AddWatcher 三重嵌套：外层 null + 内层 names.head null + eventTypes null/移位 UB）
- `netstack_neg_size.c`（证书验证 int64→uint32 截断→大循环）
- `bluetooth_neg_advert.c`（广播数据三重漏洞：外层 null + 内层 null + 负 size→size_t 下溢巨拷贝）
- 任务书追加 H 节。**对侧验证工具包现在含 E/F/G/H 四节 + 九个调用器**。

# 2026-09-29（追加六：第二轮模式扫描——4 模式族 73 lead，4 条新增候选）

- `cjffi_scan2.py`：F1 嵌套数组解引用 / F2 malloc 算术溢出 / F3 字符串无界 / F4 整数截断——491 文件 → 73 lead。
- **新增有效候选 4 条**：hiappevent AddWatcher（三重嵌套空指针+移位 UB ★★★）、netstack 证书验证（int64→uint32 截断→大循环 ×3 ★★★）、bluetooth ParseManufactureData（三重漏洞同函数 ★★★）、web_webview HTTP 头截断（★★）。
- bluetooth serviceData 空 vector 确认为逻辑 bug 非内存安全（降级）。**全项目累计 30 条候选**。详见 `docs/analysis/SWEEP2_20260929.md`。

# 2026-09-29（追加五：Tier C 畸形调用器 + 任务书 G 节）

- `hiappevent_null_params.c`（SetEventParam 路径，4 case 含 null head/size=0 控制）和 `bluetooth_null_filter.c`（StartBleScan 路径，4 case 含负 size→uint32 大循环变体），clang 语法通过。
- 任务书追加 G 节。**全项目 Tier A- + B + C 合计 26 条批量候选**，对侧验证执行件（E/F/G 三节 + 六个调用器）全部就绪。

# 2026-09-29（追加四：Tier C 逐条追链——11 条新增有效候选，全项目 26 条）

- Tier C 15 条 lead 追链：**6 条新增有效**（hiappevent head=null 最易 / bluetooth 负 size→uint32 大循环最危险 / webview/graphic/relational_store 各 1 条）+ **notification 5 条克隆族**（同 Tier B）。3 条输出方向判安全。
- **全项目批量候选累计 26 条**（Tier A- 6 + Tier B 9 + Tier C 11）。详见 `docs/analysis/L4_TIER_C_20260929.md`。

# 2026-09-29（追加三：Tier B 畸形调用器 + 任务书 F 节）

- `account_null_params.c`（VerifyCredential 路径，4 case 含 null head/负 size 变体）和 `udmf_null_extras.c`（SetProperties 路径，3 case 含 env_probe），clang 语法通过。
- 任务书追加 F 节：构建目标、验证命令、结果判读、提交策略。**Tier A- + B 合计 15 条批量候选**。

# 2026-09-29（追加二：Tier B 克隆族 L4——三仓批量候选 15 条）

- account_os_account（5 lead）和 udmf（4 lead）的 `SetDataParameters` **连顶层 `head` 都不查空**（比 av_session 浅一层的同型缺陷，更直接也更危险）；三仓函数为同一模板拷贝。
- FFI 入口无 AbilityRuntime 依赖，验证可行性同 av_session（高于 KV）。三仓合计潜在新发现 **15 条**。详见 `docs/analysis/L4_TIER_B_20260929.md`。

# 2026-09-29（追加：av_session 畸形调用器 + 任务书 E 节）

- `tools/validation_cases/avsession_null_param.c`：4 case 矩阵（有效 int32 控制 / null value + STR_PTR / I32_PTR / DOUBLE_PTR 变体），CParameters ABI 取自 account_os_account 的 appaccount_defination.h（跨组件共用形态），clang 语法通过。
- 任务书追加 E 节：av_session 构建目标、验证命令、结果判读、提交策略（6 条独立工单）。**无 AbilityRuntime 依赖**，验证可行性高于 KV。

# 2026-09-29（Tier A/A- L4 追链完成）

- av_session 9 条 lead 追链：**6 条有效**（SendCommonCommand→SetDataParameters→Inner*Array* 链上的嵌套 value 指针空检查缺失——比 IPC 深一层的同型缺陷）；3 条为控制器事件注册路径的扫描器误报（该路径有完整 null/valueType/size 三重防护）。FFI 入口 `SendCommonCommand` 无 Context 依赖，**验证可行性高于 KV**。
- kv_store 同文件 3 条同族转换确认（CArrStrToVectorKey/String ×3，FFI 层直传无校验），但与 KV 主案相同的隔离限制（AbilityRuntime Context），源级归档。
- 详见 `docs/analysis/L4_TIER_A_20260929.md`。

# 2026-09-29（IPC 真库证实 → 首个新发现工单）

- PR #63/64/65 合入（对侧）：IPC/KV 真库验证记录（IPC 证实：SIGSEGV 帧归属真库内；KV 隔离限制如实）、基线对比实验（OSV 版本匹配 0 条 / CPE 式 47 条过报 / 三层管线归零——方法护城河实测）、A-4 构建树授权登记。
- IPC 案升级 `real_library_reproduction_confirmed` 并以**新发现**提交工单 OHSA26-092953990（附件：畸形调用器 + 验证记录；口径红线三条在描述声明）。项目首个新发现工单。
- KV 维持源码等价级（AbilityRuntime Context 不可构造，纯 C 客户端不可达 store id——如实记录）。

# 2026-09-28（追加四：CJ FFI 数组转换族清扫——第一线）

- 新发现线开工：manifest 496 仓枚举 → 63 仓有 CJ 源面 → `tools/cjffi_scan.py`（类型自举 26 种 + 函数级模式匹配）扫 491 文件 → 37 条 lead（32 条 NULL+长度双缺）；扫描器独立复现已知 KV 候选作为内置验证。
- 分层：Tier A = kv_store 同文件 3 个同族转换；Tier A- = av_session 9 个 Inner* 转换（导出链 FfiMultimediaAVSessionController* 已闭合，含负 size 向量迭代器下溢 UB 形态）；Tier B = account_os_account/udmf/av_session 三仓同名克隆族；详见 `docs/analysis/CJFFI_SWEEP_20260928.md`。
- 下一步：Tier A/A- 人工 L4 补完 → 对侧真库验证 → 新发现工单。

# 2026-09-28（追加三：IPC/KV 真库验证调用器与任务书）

- `tools/validation_cases/` 新增 `ipc_null_bytearray.c` / `kv_null_entry.c`（ABI 取自 IPC edc6f3ab 头与 kv_store master FFI 头；调用器不含目标实现拷贝）与 `run_malformed.sh`（沿用 run_ipc_normal.sh 环境发现；运行退出码非零记录为观察而非失败）。
- `docs/status/TASK_IPC_KV_VALIDATION_20260928.md`：交原构建机执行的任务书——IPC 畸形矩阵（现成环境，约 30 分钟）、KV 真库构建+验证（0.5-2 天）、证据打包回传清单、口径红线；结果无论证实/证伪均如实升级或关闭候选。

# 2026-09-28（追加二：12 例缺口案例全部提交奖励计划）

- 经平台 web 表单逐例提交 12 例（含此前并行工作集已提交的 quirc）：平台现有 15 条工单全部待受理。工单号：52296→OHSA26-092819230（名称评论补正）、65704→OHSA26-092855121、65705→OHSA26-092800126、65706→OHSA26-092853125、66036→OHSA26-092848127、66037→OHSA26-092835171、66038→OHSA26-092831132、70628→OHSA26-092858135、70629→OHSA26-092850129、70632→OHSA26-092843135、45445→OHSA26-092837123（分类说明评论）。
- 全部工单号已回填 case.json submission 字段（含平台表单类型/附件清单）；提交队列单与案例台账同步更新。官方接受状态全部未知。

# 2026-09-28（追加：提交队列单与台账 18 例）

- `docs/status/SUBMISSION_QUEUE_20260928.md`：待提交 12 例（表单+补丁+对照+附件 zip 全部齐装）、已提交 3 例跟进清单、不提交项口径（cjson 演示用途、49795 残包、IPC/KV 待平台验证）。
- 案例台账更新至 18 例（并入 #51 的 gap-batch-2 三案）；quirc 案 case.json 回填 submission_materials。

# 2026-09-28（追加：工具链预检 + 比赛报告组装器）

- `ohvul/toolchain.py`：LLVM/semgrep 路径集中解析（`OHVUL_LLVM_BIN`/`OHVUL_LLVM_ROOT`/`OHVUL_SEMGREP_BIN` env 覆盖 → 内置默认，未设时行为不变），`python -m ohvul.toolchain_preflight` 以真实传输通道跑 `--version` 探针（required=clang/clang-tidy，optional=semgrep；WSL 桥条件化，修复审计 §89 的 `/home/airgap` 硬编码与 WSL 绑定）。compiler_analysis/engine_adapter/engine_shards/engine_cli 全部接线（None 哨兵解析）。测试 10 项。
- `ohvul/competition_report.py`（审计 P1.7）：15 案 case.json 的防御性投影 → 比赛报告 JSON+Markdown（证据完整度六维矩阵、缺失维度显式列出、confirmed 只投影不推断）。测试 6 项。`docs/deliverables/VIDEO_SCRIPT.md`：演示分镜与录制前预检清单（衔接 DEMO_RUNBOOK 与新预检命令）。
- 全量回归 864 项通过（4 项环境跳过）。

# Changelog

# 2026-09-28（auth fuzz 双靶收割 + PR 收敛）

- 双靶收割：T3 约 1.77 亿 / T4 约 2.71 亿执行零崩溃零泄漏（cov 3024/2676，语料 21800+16366 保留）。覆盖判读方法学发现：-O1 内联使外部链接单调用点函数在 `-print_coverage` 中假性 UNCOVERED（插针证伪尾段可达）；收割规范已写入 `docs/analysis/AUTH_FUZZ_HARVEST_20260928.md`，stage-2 暂缓、优先级转入 P1.6 案例闭环。
- PR #54/#55/#56/#53 合并（#55 经五项审计问题逐项核验评审；#56 经 Git Data API 构造——本机 github.com:443 仍不可达）；cjson 案 runtime_status 回填 library_level_reproduced。

# 2026-09-24（第四靶建成 + 案例台账）

## CVE 挖掘 P0-2 第四靶施工完成（dsoftbus auth DeviceInfo 链）

- `UnpackDeviceInfoMessage`（auth_session_json.c:3388）全链 harness `fuzz_authdeinfo`：约 25 函数逐字原样提取；D 级升级为全量 NodeInfo（lnn_node_info/device_info/connect_info 三头链）；设备类型转换族（lnn_device_info.c 表+ConvertStringToInt）与 StrCmpIgnoreCase 随链提取；base64 为 RFC4648 声明式重实现（mbedtls 3.x 依赖 constant-time 内部头链未引入，契约对齐点在 base64_ref.c 头注记）。
- 验证：6 枚结构化种子零崩溃（基线 cov 1422/ft 2496）；120s 快测 2,076,080 runs 零崩溃（约 17k exec/s）；8h 长跑与第三靶并行挂机。T3 隔夜被宿主机休眠中断（有效 3.3h/1.223 亿执行零崩溃），白班重启后继续。
- build.sh 双目标化 + rsync 运行时状态排除（挂机中重建安全）；T3/T4 共享 A 层与 stub 生态。

## 单一案例台账（审计 P0.2）

- `docs/status/CASE_LEDGER_20260924.md`：13 例逐案区分源码核验/真实库复现/产品影响/提交材料/工单/官方接受；发现并记录三处漂移（nvdec OHSA26-092224773 已提交 vs PROJECT_STATE"待提交"口径、cjson runtime_status=not_run vs CHANGELOG 09-16 运行矩阵通过、审计机另有 quirc 嵌套提交与 FFI/triage 未提交工作集）。

# 2026-09-23（追加：整树快照修复——审计 P1-1）

## source_snapshot / engine_shards 有界化（审计 2026-09-23 P1-1）

- `ohvul/source_snapshot.py`：新增 `files=` 限范围模式（先验清单——缺失输入在校验阶段即报错，不触发树遍历）与文件数/字节/时间三重预算；legacy 全树模式保留（checkpoint 绑定口径不变），哈希改流式分块，payload 格式与历史摘要逐字节兼容。
- `ohvul/engine_shards.py`：分片级快照改为仅声明输入（每分片 2 次限范围枚举）；清单/Profile 级保留树级摘要作为出版契约（能检出清单外文件变更，如契约测试 test_source_change_during_engine_scan_is_rejected 所要求），但整批只走 2 次全树（原 2S+2 次）且受预算限界；清单校验仍先于任何快照。
- `tests/test_engine_shards.py`：缺失文件测试改隔离临时目录（原用仓库根目录触发全树遍历）；新增回归——单文件请求不触碰无关缓存、清单快照访问次数精确为"2 次全树 + 每分片 2 次限范围"（canary 计数断言）、预算越限显式报错、payload 格式兼容、大文件流式哈希正确性。
- 验证：全量离线回归 853 项运行、849 通过、4 项环境跳过（303s，退出码 0）；CI 性能冒烟通过。审计文件 FFI 三条 P1（P1-2/3/4）的代码在另一机器的未提交工作集内，本轮不可修，待其落 PR 后处理。

# 2026-09-23（auth fuzz 第一 harness 建成挂机）

## CVE 挖掘 P0-2 第三靶施工完成（dsoftbus auth DeviceId 链）

- `UnpackDeviceIdJson`（auth_session_json.c:2107）全链 harness 建成：`D:/cve_data/fuzz_authdev/`（WSL 镜像 ~/fa，build.sh 一键重建）。30 函数逐字原样提取（file:line 标注），C 级 stub 约 20 处取向注明，D 级三处结构裁剪逐条声明差异。
- 方案级偏差（已回写施工图 §7）：DSoftBus 4.0.2 的 `JSON_*`/JsonObj API 底层为 nlohmann::json（C++）而非 cJSON——引入 OH 原 `softbus_adapter_json.cpp` + nlohmann v3.11.3（jsDelivr）与 C 主体混编；cJSON 保留真实现承载凭证协商子链，生产双解析器形态完整落地。cJSON_Utils 未编译，CVE-2026-87933 噪音面被结构性排除。
- 验证：6 枚结构化种子回归通过；120s 快测 1,494,196 runs 零崩溃（cov 2602/ft 9879，约 12k exec/s）；12h 长跑（-max_total_time=43200）挂机中。确认产品漏洞数口径不变（0），崩溃待分诊。

## 第四靶施工图落盘（DeviceInfo 消息链）

- `docs/design/deviceinfo_fuzz_extraction_plan.md`：靶 `UnpackDeviceInfoMessage`（auth_session_json.c:3388），A/C/D 资产全复用第三靶，D 级升级为全量 NodeInfo（三头整拷约 370 行）；头号嫌疑族已标记（BtV1 的 `OptInt64` 8 字节写 32 位 netCapacity——struct 内越界形态）。

# 2026-09-22（补录 2026-09-16 → 09-22 断档）

## 缺口案例批量落库与奖励计划提交

- 新增 `tools/kb_gap_audit.py` 四信号 L1-L4 上游修复缺口审计流水线，产出 curl×2 与 ffmpeg×5 共 7 个公开 CVE 缺口案例（`cases/`，均为 new_discovery=false、产品可达性 not_established、确认漏洞数 0）。
- ffmpeg 五案：CVE-2026-66036/66041 完成 WSL ASan/UBSan 运行时对照矩阵验证（补丁组干净、对照组通过）；CVE-2026-64832 源级 L4（运行时需 NVDEC GPU，not_run）；CVE-2026-65704/52296 源级对照（上游补丁 verbatim 可应用）。
- 已向 OpenHarmony 漏洞奖励计划提交 2 案：OHSA26-092209031（curl CVE-2026-80231）、OHSA26-092226014（curl CVE-2026-82209，2026-09-21）；另 5 案 ffmpeg 提交材料已备好（`D:/cve_data/submission_*`）待人工提交。

## 隔离执行授权与 cJSON 运行时闭环（09-16）

- 隔离执行授权文档双签合并（`docs/engineering/EXECUTION_AUTHORIZATION.md`）；登记 WSL 工具链 B-1 与 cJSON 源码根 A-2。
- cJSON MergePatch 案例授权 bubblewrap 运行矩阵通过：原版/独立副本观察到预期库级 UAF，补丁与控制组通过；第二复现者独立复现 26/26。
- 新增 `verify-runtime` 离线复核 cJSON 案例矩阵；生命周期 deleter 序列规则在 cJSON 案例回验。

## LLM 在线链路恢复（09-16/09-21）

- z.ai Anthropic 传输接入并有界在线评审验收通过（glm-5.3）；gpt-6-astra 加入白名单用于双模型交叉验证。29 组全量评审与双模型运行待执行，模型输出仍不作为漏洞结论。

## CVE 知识库运营化与版本探针（09-21）

- 伙伴导入 72 条双审记录（arkcompiler_ets_runtime、kernel_liteos_a、dsoftbus 等）；OSV 引用规范化；446 条第三方目标子知识库。
- 版本探针解析 JSON 数组型 README.OpenSource 清单；清单名内嵌版本的规范化漏报修复与回归测试（PR #45）。
- 技术说明书初稿 v0.9（`docs/deliverables/TECHNICAL_SPEC.md`，交付物 2）；隔离执行沙箱与四信号 triage 设计稿合并（均未实现，待主线决策 S1-S5 / A1-A5）。

## curl PSL 案例（09-21/09-22）

- 新增 curl 中间形态源级验证报告（`docs/analysis/CURL_MIDDLEFORM_VERIFY_20260921.md`）与 curl PSL supercookie 案例（CVE-2026-82209，首个中间形态案例）。
- 修复 cookie.c 固定摘要为原生 LF 规范值；补运行时验证记录并修复 PoC 控制模式。

## 2026-09-22 审计与清理

- 全面审计与剩余工作规划落库：`docs/status/AUDIT_REMAINING_PLAN_20260922.md`。
- 落库此前未跟踪的 6 个案例目录与 `kb_gap_audit` 工具；记录两案 OHSA 提交工单。
- 移除 CHANGELOG 中误嵌入的 PROJECT_STATE 重写脚本片段。

- 完成固定 cJSON MergePatch 案例的授权 bubblewrap 运行矩阵：原版/独立副本观察到预期库级 UAF，补丁与控制组通过；产品可达性仍未知，产品漏洞确认数为 0。

- 新增 `docs/design/camera_app_engine_profile.json`，固化 cameraApp 组件的提交、文件、include、define 和引擎参数。
- 新增 `engine_profile` loader，校验组件 profile 并生成 WSL 编译参数。
- profile loader 增加完整 commit SHA 和相对路径边界校验，修正 IPC profile commit 摘要。

## FSM CLI engine integration

- 主 CLI 增加 `--engine-files-from`，在 static_scan 阶段运行受控 WSL Clang 分片并合并 EvidenceBundle。
- 引擎输入错误随结果记录，不自动升级审核状态；受控 fixture CLI 验证 completed 路径通过。
- 完成带 checkpoint、journal、report 的完整 fixture 验证：结果校验、报告绑定和 static_scan 状态均通过。
- 引擎接入后运行完整测试集：155 项通过，4 项环境相关跳过；既有 FSM、报告、审核和归档测试保持通过。
- 对 OpenHarmony 快照中的 7 个 bzip2 C 文件完成受控分片运行：7/7 完成、0 个输入错误、6 条候选；结果保持本地候选语义。
- 为实际出现的 Clang 规则增加保守 CWE 候选映射：`unix.Malloc`→CWE-416、`DeprecatedOrUnsafeBufferHandling`→CWE-676；仅作为候选字段。
- CWE 候选映射增加 `builtin_engine_rule_map` 来源和映射版本 `1`，并纳入 EvidenceBundle 校验。
- 增加 `core.NullDereference`→CWE-476 候选映射，并用真实 Clang Analyzer 空指针诊断完成本地转换验证。
- 引擎结果增加本地知识库交叉匹配：按组件/版本和已有 CWE 候选过滤，绑定 CVE/CWE、数据库摘要、源记录摘要及 EvidenceBundle，仍保持 candidate-only。
- `wildtrace-clang` CLI 增加 `--knowledge-base --component --version`，完成本地知识库匹配的可执行入口验证。
- 全量回归确认：155 项通过，4 项环境相关跳过。
- 本地 Demo 文档补充 WSL Clang 单文件、显式清单和知识库匹配用法，并说明 `completed/partial/input_error` 状态语义。
- 全量回归更新为 156 项通过、4 项环境相关跳过。
- 增加 `wildtrace-engine-benchmark` 离线评测入口，支持人工标注 case 与 schema 0.3 引擎结果的候选级 TP/FP/FN、precision/recall 统计。
- 全量回归更新为 157 项通过、4 项环境相关跳过。
- 新增 `docs/design/ENGINE_BENCHMARK.md`，规定引擎候选基准的人工标注字段、证据绑定、输入不可用处理和指标边界。
- 引擎基准评测器增加 CWE 格式、标签和安全样本空标注校验。
- 全量回归更新为 158 项通过、4 项环境相关跳过。
- 新增 `docs/design/engine_benchmark_template.json`，提供不带准确率结论的人工标注起始模板。
- 用隔离合成样本验证评测 CLI：2 cases、TP=1、FP=1、FN=0；该指标仅验证工具链，不代表 OpenHarmony 准确率。
- 评测器现在排除与 `input_errors` 对应的样本，避免缺失构建上下文被统计为 false negative。
- 引擎评测器增加 `bootstrap_cases`，可从保存结果生成待人工复核草稿，默认不填 CWE。
- 全量回归更新为 160 项通过、4 项环境相关跳过。
- 基准设计文档补充 `bootstrap_cases()` 草稿生成与正式评测的先后边界。
- `wildtrace-engine-benchmark` 增加 `--bootstrap-output` 模式，可从结果文件生成待人工复核 cases。
- bootstrap 草稿现在要求 64 位十六进制源码快照 SHA-256。
- 引擎评测优先按标注 `source_file` 精确对齐，避免同名文件造成候选误配；无路径时保留 ID 前缀回退。
- 全量回归更新为 162 项通过、4 项环境相关跳过。
- 全量回归更新为 163 项通过、4 项环境相关跳过。
- 全量回归更新为 161 项通过、4 项环境相关跳过。
- README 增加引擎评测 bootstrap 草稿生成示例。
- 新增 `scan_engine_profile()`，可按版本化组件 profile 直接运行声明的文件清单和编译参数。
- 使用 cameraApp profile 在 `OpenHarmony-complete` 工作区完成真实分片复跑：3/3 completed、0 个输入错误、0 条诊断。
- 新增 `docs/engineering/COLLABORATION_PLAN.md`，定义用户、Codex 和 GLM-5.3 的职责及 GitHub 协作流程。
- 根据代码审查更新协作和比赛规划：先修适配层正确性，再固定组件 profile、做双引擎试验和高价值漏洞族，GLM-5.3 通过 PR 编辑边界模块，Codex维护核心链。
- 阶段 A 修复：引擎分片合并重新编号 `alert_id`，并区分 `clang` 与 `clang-tidy` 来源。
- 引擎 CLI 输出绑定源码快照 SHA-256；直接保存的 schema 0.3 结果现在带有 `scan.source_snapshot_sha256`。
- 引擎结果合并增加源码快照一致性门控，拒绝跨快照混合证据。
- 全量回归更新为 164 项通过、4 项环境相关跳过。
- 全量回归更新为 170 项通过、4 项环境相关跳过。
- 全量回归更新为 173 项通过、4 项环境相关跳过。
- 阶段二增加 `validate_profile_sources()`；cameraApp profile 在 `OpenHarmony-complete` 中验证为 complete（3 个源文件、16 个 include 目录）。
- 阶段二增加 `validate_profile_provenance()`；cameraApp profile 的 4 个关键仓库 commit 与本地 Git HEAD 全部一致。
- Semgrep taint pilot 在合成 C 样本上成功捕获 `getenv`→`strcpy` 数据流；规则和边界记录在 `docs/design/semgrep_taint_pilot.yml`。
- Semgrep taint pilot 已在 cameraApp 三个真实文件上完成离线复跑：0 条命中、无输入错误；结果仅表示该规则未命中这些文件。
- 竞赛差距分析文档新增最新代码审查结论和收敛后的执行顺序。
- 已验证 Semgrep JSON 候选可与基础扫描结果通过 `merge_engine_result` 合并，并通过 `validate_result`。
- WSL 隔离 venv 安装 Semgrep 1.177.0；cameraApp 本地规则扫描完成且无结果，合成 C 样本可产生候选；新增 Semgrep JSON 统一结果转换。
- 新增 `run_wsl_semgrep()`：仅接受源码根目录内的本地规则和显式文件清单，禁止远程规则输入。
- 在独立 `C:\Projects\OpenHarmony-complete` 工作区补齐 build、camera sample、ability_lite、bundle_framework_lite、ui_lite、graphic_utils_lite、IPC、camera_lite、media_lite 等直接依赖；提取 GN include/define 参数后，camera `camera_ability.cpp` Clang 状态由 input_error 变为 completed、0 条诊断。
- 组件工作区关键提交已记录：build `71de884ecc242fa7757c5506e3a3606b9d51c5b0`、camera `f41db9875943bc560444827d2effd5e16e4e821d`、ability_lite `ac5b043bc0b53cfa3c3da9e5f87c0ee5d14df803`、IPC `a36ce279edb3045cef80853f3fb65c6005a5e48`。
- 补齐 surface_lite、media_lite/recorder_lite、hilog_lite、bounds_checking_function 等头文件路径后，cameraApp 三个 C++ 源文件均完成 Clang 分析：3/3 completed、0 个输入错误、0 条诊断。
- 增加 WSL clang-tidy 单文件执行适配；cameraApp `camera_ability.cpp` 使用同一编译参数完成 `clang-analyzer-*` 检查。
- 全量回归更新为 159 项通过、4 项环境相关跳过。
- 本地 Demo 文档补充人工标注完成后的离线引擎候选评测流程。
- README 增加本地 Clang 引擎、知识库匹配和候选评测入口说明。

## Clang WSL engine adapter

- 接入 WSL 中 LLVM 22.1.8 Clang Static Analyzer 的 plist 输出转换。
- 增加 Windows 路径到 WSL 路径映射、超时处理和 `input_error` 结构化结果。
- 在 OpenHarmony camera sample 上完成真实本地调用；因缺少 `ability_loader.h` 返回输入构建错误，不将其解释为干净扫描。
- 7 项适配器测试通过；合成 use-after-free plist 可转换为候选结果。
- WSL Clang 适配器支持显式 tuple 编译参数；当前 OpenHarmony 快照未提供可用 compile database，真实复跑仍记录为 `input_error`。
- 检查 OpenHarmony 根目录确认缺少 `.gn`、`build.sh`、`prebuilts`、`out` 和目标 sample 依赖头文件；当前快照不足以生成真实编译数据库，未启动构建或修改源码。
- 读取 `.repo_snapshot.json` 和同步日志确认该快照为裁剪快照：`build`、`ability_lite`、`bundle_framework_lite`、`ui_lite`、`camera_lite`、`media_lite` 等依赖均为 skipped，不能据此作完整平台分析结论。
- 在裁剪快照中的 `third_party/bzip2/bzip2recover.c` 上完成一次真实 Clang Analyzer 运行，状态为 `completed`、0 条候选；该结果仅代表该文件在默认编译上下文下无诊断，不代表 OpenHarmony 全局结论。
- 接入 clang-tidy 文本诊断转换；对同一真实文件运行受限 `clang-analyzer-*` 检查，解析 32 条候选，保留规则、行号、列号和原始描述。
- 增加外部引擎结果到 schema 0.3/EvidenceBundle 的投影，并用现有 `validate_result` 对 32 条真实 clang-tidy 候选完成联合校验。
- 增加 `wildtrace-clang` CLI：对单个本地文件运行 WSL Clang，完成时输出 schema 0.3/EvidenceBundle，输入依赖不完整时输出 `input_error`。
- `wildtrace-clang` 增加 `--files-from` 受控清单模式，逐文件运行、合并候选、保留部分失败和输入错误，不对整个源码树盲扫。
- 增加 `ohvul.engine_shards`，复用现有 manifest/shard 结构逐文件调用 WSL Clang，并保留每个分片的输入错误和候选证据。
- 增加 `merge_engine_result`，将引擎证据并入 schema 0.3 扫描结果，检查源码根目录和 EvidenceBundle 冲突，并通过现有结果校验器。
- 主 CLI 增加 `--engine-files-from`，在 `static_scan` 前运行受控 WSL Clang 分片并合并结果；引擎输入错误随结果记录，不自动升级审核状态。

## Joint verification single-read consistency

- 扫描结果摘要和解析共用单次读取字节，修复原先两次读取可能不一致的问题。
- 增加联合校验/CLI 成功路径、结果字节变化、错任务、缺失证据、损坏 envelope 和无效 workflow 测试。
- 相关 11 项测试：10 通过、1 跳过；只验证合成 JSON 关联，不宣称 harness 或漏洞复现成功。

## Actual checkpoint linkage validation

- 新增 make_checkpoint_link / validate_checkpoint_link，以实际检查点字节生成并验证摘要，同时核对 schema、任务、local_verification 状态与 harness 记录。
- 复用 validate_checkpoint_data，解析和摘要使用相同字节来源。
- 新增字节变化、任务变化、伪造摘要、错误状态及无效记录测试；相关 38 项测试通过。
- 校正 Phase 4 验收声明：旧 link 校验不证明检查点关联；生产链集成仍待完成。本轮不推送。

## 2026-09-10

- 建立防御性代码审计 MVP。
- 增加工程主提示词、阶段状态和恢复协议。
- 当前扫描器仅处理本地 C/C++ 源码，输出候选发现。

## 2026-09-10 (Phase 2)

- 增加只读本地组件识别和版本元数据读取。
- CLI JSON 结果加入 components 字段。
- 通过 2 项单元测试。

## 2026-09-10 (Phase 2 metadata)

- 增加可选本地 JSON 漏洞元数据加载和组件/版本匹配。
- CLI 增加 --vuln-db 参数，默认不联网。
- 通过 3 项单元测试。

## 2026-09-10 (Phase 3 evidence)

- 增加统一 EvidenceBundle 数据模型。
- 静态候选结果加入 evidence_id 和证据摘要。
- 通过 4 项单元测试。

## 2026-09-10 (Phase 3 evidence links)

- 本地漏洞元数据匹配结果关联 EvidenceBundle。
- 通过 4 项单元测试。

## Evidence validation increment

- 证据标识改用完整记录的 SHA-256，扫描格式升级到 0.3。
- 新增 python -m ohvul.verify，检查摘要、静态片段、位置和引用。
- 新增 3 个测试方法，全套 7 项通过。
- 修复 PROJECT_STATE.md 换行错误，明确开发标签不是运行时 FSM，普通 JSON 不是不可变存储。
- 恢复入口及限制详见 docs/engineering/EVIDENCE_VALIDATION.md。

## Conservative metadata matching

- 版本缺失、unknown 或星号标记进入 unresolved，不能作为版本匹配成功。
- 精确版本相等输出 exact_version_candidate，仍不代表目标代码受影响。
- 元数据输入采用 UTF-8 BOM 兼容读取并拒绝无效记录。
- 校验器检查 unresolved 证据引用；全套 11 项测试通过。
- 后续继续补完整数据库来源绑定和 FSM，未完成总体目标。

## Metadata source binding

- 匹配 EvidenceBundle 绑定本地数据库数组摘要和来源标识。
- 校验器检查元数据来源标识，11 项测试通过。

## Complete metadata presentation binding

- 匹配项保留来源记录副本并绑定数据库数组摘要、来源标识和 evidence_id。
- 校验器核对 id、cwe、summary 等展示字段与来源记录一致；修改后拒绝。
- CLI 回归验证通过；全套 11 项测试通过。
- 这仍是候选元数据证据，不是漏洞确认或来源签名。

## Output and source protection

- CLI 默认拒绝覆盖已有结果，显式 `--force` 才允许替换。
- 本地漏洞数据库文件写入字节 SHA-256；数组摘要继续保留用于记录语义。
- 新增覆盖保护回归测试；全套 12 项测试通过。
- 哈希仍用于完整性检测，不等同于数字签名或可信来源证明。

## Deterministic FSM checkpoint core

- 新增有限状态机核心和检查点保存/恢复。
- 非法迁移、阻断原因、恢复清除和检查点覆盖保护均有测试。
- 全套 15 项单元测试通过。
- 尚未接入 CLI、Agent 或目标代码执行。

## CLI workflow checkpoint integration

- CLI 增加 --checkpoint 和 --task-id，扫描结果包含 workflow。
- 仅在本地扫描成功后进入 static_scan；错误记录 blocked。
- 全套 16 项测试通过；未自动推进到 triage/report。

## Checkpoint result binding

- 检查点增加 result_sha256，绑定实际保存的结果字节。
- verify 增加 --checkpoint，检查摘要、任务、状态和证据。
- 新增修改拒绝和失败检查点测试，全套 18 项通过。
- 重写恢复状态，清除过期能力声明：尚无自动恢复或事务保存；数据库数组摘要未单独保留，前文所述“双摘要”并未实现。

## Path isolation and atomic result publishing

- 拒绝结果/检查点位于扫描源码目录内。
- 拒绝结果/检查点与漏洞数据库相同，即使传入 `--force`。
- 结果使用同目录临时文件、fsync 和 replace 发布。
- 新增路径安全测试，全套 20 项测试通过。
- 尚未覆盖符号链接/硬链接竞争和多文件事务。

## Bounded recovery

- `resume_blocked` 只接受 blocked 检查点。
- 恢复目标限制为 intake 或 static_scan，禁止跳到 triage/report/completed。
- 重试次数上限为 3；恢复清除旧结果摘要。
- 新增恢复边界和预算测试，全套 22 项通过。

## Explicit recovery CLI

- 新增 `python -m ohvul.recover checkpoint.json --target intake|static_scan`。
- 只读取 blocked 检查点并写入下一状态，不自动运行扫描。
- 受最大 3 次重试限制；非 blocked 和越权目标均拒绝。
- 新增 CLI 恢复测试，全套 24 项通过。

## Checkpoint schema validation

- 检查点固定版本 1 和字段集合。
- 校验 task_id、状态、重试次数、错误字段和结果摘要格式。
- 拒绝未知字段、缺失字段、错误类型和超出预算的检查点。
- 新增 schema 回归测试，全套 26 项通过。

## Recovery task association

- 恢复命令不自动运行扫描。
- 使用同一个 `--task-id` 重新运行 CLI 后，结果和检查点保持同一任务标识。
- 重新扫描会生成新的结果摘要，旧摘要不会复用。
- 新增恢复关联回归测试，全套 27 项通过。

## Source snapshot binding

- 扫描开始前为普通源码文件生成路径、大小和内容 SHA-256 清单摘要。
- 摘要写入结果 workflow 和检查点；跳过符号链接，不执行文件。
- 摘要用于恢复时比较输入是否变化，不等同于提交签名或漏洞证据。
- 27 项测试通过；源码快照变更拒绝和竞争保护仍待实现。

## Snapshot recovery gate

- 使用已有检查点重跑时校验源码快照摘要。
- task_id 不一致、源码发生变化或检查点仍为 blocked 时拒绝。
- blocked 检查点必须先用 `ohvul.recover` 恢复。
- 新增快照门禁测试，全套 29 项通过。

## Checkpoint link safety

- 保存检查点时拒绝符号链接路径。
- 防止普通文本写入跟随链接修改非预期目标。
- 链接能力不可用的平台测试会显式 skipped，不伪装为通过。
- 全套 30 项测试通过。

## Atomic checkpoint publishing

- 检查点保存改用临时文件、flush、fsync 和 replace。
- 结果和检查点的跨文件一致性仍由 result_sha256 校验，不宣称多文件事务。
- 全套 30 项测试通过。

## Source snapshot regression

- 验证相同目录摘要稳定。
- 验证普通文件内容变化会改变摘要。
- 验证符号链接不参与摘要；当前环境不支持时显式 skipped。
- 全套 32 项测试通过。

## Journal core

- 新增追加式 AuditJournal，事件写入后 fsync。
- 可区分 committed、incomplete 和 aborted 任务。
- 非法事件或记录拒绝读取。
- 暂不接入默认 CLI，避免在事务策略未定前改变主流程；全套 34 项测试通过。

## CLI journal integration

- CLI 可选 `--journal`。
- 成功顺序：begin、result、checkpoint、commit；异常记录 abort。
- 日志位于扫描目录外并通过 AuditJournal fsync。
- 默认未启用日志时主流程不变；全套 35 项测试通过。

## Journal consistency validation

- `validate_commit` 只认 committed 终态。
- 同时校验 task_id、结果字节摘要、检查点和证据结构。
- 结果被修改或日志未提交时拒绝。
- 全套 36 项测试通过。

## Read-only journal status

- 新增 `python -m ohvul.journal_status JOURNAL`。
- 只读报告任务状态。
- incomplete 状态提示人工检查结果和检查点，不自动重放。
- 全套 37 项测试通过。

## Journal sequence integrity

- 修复异常路径可能追加 commit 的缺陷。
- 合法提交序列严格为 begin/result/checkpoint/commit。
- 失败路径追加 abort，不再追加 commit。
- validate_commit 核对日志摘要、checkpoint 状态和源码快照。
- 新增失败回归测试，全套 38 项通过。

## Joint journal/checkpoint/result report

- `journal_status --task-id TASK --result RESULT --checkpoint CHECKPOINT` 联合校验三类文件。
- 输出 `CONSISTENT` 或 `INCONSISTENT`，并使用非零返回码表示不一致。
- 不提供联合文件时仍只显示日志状态。
- 全套 39 项测试通过。

## Stable JSON status report

- `journal_status --json` 输出稳定 JSON。
- 联合校验成功包含 task_id、journal_status、consistent=true。
- 失败包含 consistent=false 和 error。
- 不执行恢复或目标代码；全套 40 项测试通过。

## Defensive audit report schema

- 新增 `ohvul.report`，定义 report schema 0.1。
- 报告将候选发现、证据引用和 workflow 状态分离。
- 默认安全状态为 `candidate_only`，确认漏洞数固定为 0。
- 校验器拒绝把候选改写为已确认漏洞。
- 全套 42 项测试通过。

## Candidate report CLI

- CLI 增加 `--report-output`。
- 报告与扫描结果分开保存并原子发布。
- 写出前执行报告 schema 校验，固定为 candidate_only。
- 全套 43 项测试通过。

## Report source binding

- report schema 升级到 0.2。
- 报告记录生成它的扫描结果 SHA-256。
- `validate_report_against_result` 检查报告和扫描结果一致。
- 报告仍固定 candidate_only；全套 44 项测试通过。

## Report verification CLI

- 新增 `python -m ohvul.report_verify report.json scan.json`。
- 只读校验报告与扫描结果绑定。
- 扫描结果变化、报告越权状态或证据缺失时返回非零。
- 全套 45 项测试通过。

## Human review record

- 新增 review schema 0.1 和 `python -m ohvul.review_record`。
- 审核记录独立于报告，不修改候选或证据。
- 只允许流程决定，`final_vulnerability_verdict` 固定为 false。
- 记录绑定报告 SHA-256；全套 47 项测试通过。

## Review record overwrite protection

- 审核记录输出默认拒绝覆盖。
- `--force` 是显式替换开关。
- 替换前后仍要求报告摘要绑定；不改变最终 verdict=false。
- 全套 48 项测试通过。

## Review verification CLI

- 新增 `python -m ohvul.review_verify review.json report.json`。
- 校验审核记录 schema、报告摘要和非确认结论。
- 报告变化后拒绝旧审核记录。
- 全套 49 项测试通过。

## Review task binding

- 审核记录包含 task_id。
- task_id 从报告 workflow 继承。
- 校验拒绝跨任务复用审核记录。
- 全套 49 项测试通过。

## Review batch binding

- 新增批次审核 schema 0.1。
- 批次绑定 batch_id、task_id、报告摘要和审核条目。
- 跨任务或跨报告批次拒绝；最终 verdict 固定 false。
- 全套 50 项测试通过。

## Review batch verification CLI

- 新增 `python -m ohvul.review_batch_verify batch.json report.json`。
- 校验批次、任务、报告摘要和审核条目一致性。
- 报告变化后拒绝旧批次记录。
- 全套 51 项测试通过。

## Review batch journal event

- AuditJournal 新增 `review_batch` 事件。
- 事件记录 batch_id、task_id、report_sha256。
- 强制 `final_vulnerability_verdict=false`。
- 全套 53 项测试通过。

## Review chain verification

- 新增 `python -m ohvul.review_chain_verify BATCH REPORT JOURNAL`。
- 联合校验报告、批次审核和 journal review_batch 事件。
- 校验 task_id、batch_id、报告摘要和 final_vulnerability_verdict=false。
- 全套 54 项测试通过。

## Review chain JSON output

- `review_chain_verify --json` 输出稳定机器可读结果。
- 成功包含 consistent、task_id、batch_id 和 verdict=false。
- 文本输出保持兼容；全套 55 项测试通过。

## Journal history query

- `journal_status --task-id TASK --history` 输出任务事件序列。
- `--json` 将序列放入 history 字段。
- 查询只读，不执行重放或修改日志。
- 全套 56 项测试通过。

## Journal history archive

- 新增 `python -m ohvul.journal_archive JOURNAL TASK_ID OUTPUT`。
- 导出事件序列和摘要，默认拒绝覆盖。
- 原始日志只读且保持不变。
- 全套 57 项测试通过。

## Journal archive verification

- 新增 `python -m ohvul.journal_archive_verify ARCHIVE`。
- 校验归档 schema、任务 ID、事件结构和事件摘要。
- 不读取或修改源日志；全套 58 项测试通过。

## Archive event filtering

- `journal_archive --event EVENT` 支持按事件类型筛选。
- 归档记录 `event_filter`，摘要基于筛选后的事件重新计算。
- 部分归档不会被误认为完整日志。
- 全套 59 项测试通过。

## Archive filter verification

- 归档校验器检查 `event_filter` 与实际事件一致。
- 筛选声明或事件内容被改动时拒绝。
- 全套 60 项测试通过。

## Journal timestamps and since filtering

- 事务事件记录 UTC `created_at`。
- 归档支持 `--since` ISO-8601 下界。
- 缺少时间戳时拒绝时间筛选，不猜测事件时间。
- 全套 61 项测试通过。

## Legacy journal compatibility

- 状态查询报告 `legacy_timestamp_events`。
- 旧日志缺少时间戳时仍可查看和归档（不使用时间筛选）。
- 使用 `--since` 时拒绝缺少时间戳的事件，不进行猜测或自动迁移。
- 全套 62 项测试通过。

## Legacy journal compatibility documentation

- 新增 docs/engineering/LEGACY_JOURNAL_COMPAT.md。
- 明确旧日志可验证字段、不可推断字段、时间筛选限制和人工迁移边界。
- 不自动改写历史日志或补造时间戳。

## Archive lifecycle policy

- 新增 docs/engineering/ARCHIVE_LIFECYCLE.md。
- 明确 active/sealed/superseded 逻辑状态、永久保留默认值和人工删除边界。
- 明确封存前校验、恢复和旧日志补充规则。
- 当前工具不自动清理、封存、删除或覆盖历史归档。

## Read-only archive seal marker

- 新增 seal schema 0.1。
- 封存标记绑定归档 SHA-256、操作者、时间和原因。
- 生成或校验封存标记不修改归档内容。
- 全套 64 项测试通过。

## Archive seal verification

- 新增 `python -m ohvul.archive_seal_verify SEAL ARCHIVE`。
- 只读校验封存标记和归档摘要一致。
- 归档变化后旧封存标记失效。
- 全套 65 项测试通过。

## Seal marker creation CLI

- 新增 archive_seal_record；复用 validate_archive，校验后独占创建独立标记，不提供覆盖开关。
- 源归档不修改，损坏归档不生成标记；创建不等于身份认证或整条审计链验证。
- 新增 3 项回归测试；全套 68 项中 66 通过、2 跳过。
- 重写 PROJECT_STATE.md，纠正历史测试统计重复替换造成的歧义；保留历史变更日志。
- 后续工作回到 Phase 3 核心验收，优先报告与扫描结果字段一致性。

## Report end-to-end binding regression

- CLI 同时生成扫描结果和候选报告。
- report_verify 成功校验保存文件之间的 scan_result_sha256 绑定。
- 全套 69 项测试，67 通过、2 项符号链接能力不可用而跳过。

## Scan-time input consistency gate

- CLI 扫描前后比较源码快照。
- 扫描期间源码变化会拒绝结果、报告和正常提交链。
- 新增输入门禁测试；全套 70 项，68 通过、2 项符号链接能力不可用而跳过。

## Strict report projection consistency

- 报告候选集合必须与扫描结果告警一一对应。
- 校验 alert_id、evidence_id、CWE、rule、location 和 evidence_refs。
- 缺少、篡改或新增报告字段时拒绝联合校验。
- 全套 72 项测试，70 通过、2 项符号链接能力不可用而跳过。

## Rule-quality suppression

- 支持源码行级 `// ohvul:ignore`，用于人工记录已审查的局部候选。
- 抑制只影响同一行，不影响其他位置。
- 不改变候选以外的结论，也不证明代码安全。
- 规则基准测试更新；总测试 74 项，72 通过、2 跳过。

## Static rule benchmark

- 新增离线 C/C++ 规则基准和标注类别。
- 覆盖候选、人工抑制、需要上下文和安全控制样例。
- 基准只评估候选命中，不宣称漏洞确认。
- 全套 75 项测试通过，2 项符号链接能力不可用而跳过。

## Offline rule benchmark statistics

- 新增 `python -m ohvul.benchmark docs/design/rule_benchmark.json`。
- 输出候选规则 TP/FP/FN、precision/recall 和逐例统计。
- 结果明确是候选规则统计，不是漏洞确认。
- 全套 76 项测试通过，2 项符号链接能力不可用而跳过。

## Rule benchmark evaluation contract

- 新增 docs/design/RULE_BENCHMARK.md。
- 明确 TP/FP/FN、precision/recall 和合成样例限制。
- 明确候选统计不等于漏洞真值或平台影响。

## Extended static rule benchmark

- 增加 CWE-190 整数长度和 CWE-476 指针解引用候选样例。
- 避免在内存复制 API 行上重复报告指针规则，减少明显重复候选。
- 全套 77 项测试通过，2 项符号链接能力不可用而跳过。

## Safe counterexample benchmark

- 增加已检查空指针的安全反例。
- 基准保留该候选作为 FP 观察，不隐藏误报。
- 全套 78 项测试通过，2 项符号链接能力不可用而跳过。

## Explainable benchmark labels

- 每条规则基准样例新增 `reason`。
- 原因说明候选、人工抑制、安全反例或上下文依赖。
- 基准统计仍不等同于漏洞确认。
- 全套 79 项测试通过，2 项符号链接能力不可用而跳过。

## Rule-overlap benchmark statistics

- benchmark 输出 `rule_overlap_cases`。
- 每例输出 `rule_overlap` 和标注 `reason`。
- 用于区分重复规则命中和新增候选覆盖，不改变漏洞结论。
- 全套 80 项测试通过，2 项符号链接能力不可用而跳过。

## Benchmark report snapshot

- 生成 docs/design/rule_benchmark_report.json。
- 当前合成基准：8 cases，候选 TP=5、FP=2、FN=0，precision 约 0.714，recall 1.0，重叠样例 1。
- 统计仅用于规则回归，不代表真实 OpenHarmony 准确率或漏洞确认。

## Benchmark taxonomy labels

- 基准样例增加 `language` 和 `component` 分类。
- 支持后续按语言、CWE 和组件类型分层统计。
- 不改变候选判定或安全结论。
- 全套 81 项测试通过，2 项符号链接能力不可用而跳过。

## Benchmark grouped statistics

- benchmark 报告新增按 `component::language` 的 groups 汇总。
- 每组包含 cases、TP、FP、FN，保留总体指标和免责声明。
- 统计不等同于真实漏洞准确率；全套 82 项测试通过，2 项跳过。

## Test count calibration

当前实际测试命令报告 81 项，79 通过、2 跳过；PROJECT_STATE 已按工作区输出校准。

## Current status calibration

当前工作区实测 81 项测试，79 通过、2 跳过；状态文档已校准。

## Benchmark input contract

- 在扫描前严格校验合成基准结构、标签/CWE 一致性、唯一 ID 和语言。
- 临时样例文件使用固定文件名，ID 保留为展示字段。
- 新增 5 个输入校验回归测试；全套 86 项测试通过，2 项跳过。

## Authorized OpenHarmony source sample

- 经用户授权对 C:\Projects\OpenHarmony 进行只读源码盘点。
- 发现约 292,493 个 C/C++ 文件；仅扫描 commonlibrary/utils_lite/timer_task 受限子树。
- 生成 docs/design/openharmony_timer_task_scan.json，29 条证据记录通过离线 verify。结果仍是候选发现，不是漏洞确认。

## Deterministic source shard manifest

- 新增本地 C/C++ 路径分片清单生成器及确定性摘要。
- 清单不读取源码内容、不执行目标代码；新增 2 项测试。

## Shard resource gate

- 分片清单新增 max_files 资源上限，非法预算明确拒绝。

## Manifest-bound shard scanning

- 扫描器支持显式相对文件集合。
- 新增 scan_shard 受清单约束运行，新增 2 项回归测试。

## Deterministic shard result merge

- 新增跨分片结果合并、根目录绑定、证据去重和确定性告警排序。

## Regression checkpoint

- 全套回归 92 项，90 通过、2 跳过。

## Shard evidence validation

- 增加合并结果通过现有 evidence verifier 的回归覆盖。

## Offline local evidence recheck

- 新增基于源码位置和行哈希的独立复核函数及 2 项测试。

## Local verification request gate

- 新增确定性本地安全验证请求门控，要求 static_scan 状态和全部证据可复现。

## Synthetic local harness contract

- 新增合成输入本地 harness 评估器，保持结果为 undetermined 并要求人工审核。

## Local verification transition intent

- 验证门控新增 local_verification 迁移意图，保留既有 FSM 检查点兼容性。

## FSM local verification state

- FSM 新增 local_verification 状态及 static_scan/local_verification/triage 迁移。

## Harness record schema

- 新增版本化合成 harness 记录校验，强制 undetermined 与人工审核。

## Verification linkage

- 新增工作流检查点与 review-only harness 记录的摘要绑定和校验。

## Phase 4 local verification entry

- 完成 timer_task 受限样本 29 条候选的端到端行哈希复核。
- 生成 review-only harness 记录及检查点摘要关联，保持 undetermined。
- 正式进入 Phase 4：本地安全验证与独立复现。

## Phase 4 closure checkpoint

- harness 记录 schema 与摘要关联离线校验通过。
- 全套测试 101 项，99 通过、2 跳过。

## Isolation harness I/O contract

- 新增合成 harness 输入/输出边界校验，拒绝路径对象和确定性漏洞结论。

## Phase 4 isolation regression

- 全套回归 103 项，101 通过、2 跳过。隔离 I/O 契约与既有证据链兼容。

## Isolation resource budgets

- 合成 harness 输入新增字节与超时预算门控。

## Enforced isolation input budget

- 实际执行合成输入 max_bytes 上限并增加超限测试。

## Phase 4 regression audit

- 全套回归 103 项，101 通过、2 跳过。

## Harness output gate

- 合成 harness 输出生成后立即执行隔离契约校验。

## Phase 4 validation contract documentation

- 新增本地安全验证契约文档，明确合成输入、资源预算、证据绑定和人工审核边界。

## Safe harness record persistence

- harness 记录采用独占创建，拒绝覆盖和符号链接路径。

## Audit fix: symlink consistency

- 扫描器显式跳过符号链接，和源码快照边界保持一致。

## Runtime LLM adapter

- 新增可选 LLM 适配器，key 仅从环境变量读取，输出保持 undetermined。

## LLM adapter safety regression

- 增加离线 mock 测试，验证 key 不出现在结果且输出保持 review-only。

## LLM context boundary

- LLM 适配器新增结构化上下文和 64 KiB 大小限制。

## LLM timeout gate

- LLM 适配器新增 1..60 秒超时校验。

## LLM runtime configuration docs

- README 增加 key 脱敏和显式调用说明。

## LLM model allowlist

- LLM 适配器限制为已验证的 grok-4.6 模型。

## LLM HTTPS boundary

- LLM 适配器强制 HTTPS Base URL。

## LLM response schema validation

- 新增 LLM 响应结构和文本类型校验。

## LLM draft size gate

- LLM 草稿输出新增 16 KiB 大小上限。

## Offline CI regression

- 新增 GitHub Actions 离线单元测试工作流。

## CI credential pattern gate

- GitHub Actions 新增离线 API key 形态扫描。

## Local credential ignore rules

- 新增 .env、密钥和 secrets 文件忽略规则。

## CI least privilege

- 离线测试 workflow 设置 contents: read 最小权限。

## Cross-platform CI verification

- Ubuntu GitHub Actions offline-tests 对 beadf8d 执行成功。

## Packaging metadata

- 新增最小 pyproject.toml，声明项目元数据与 wildtrace CLI 入口。

## Local package validation

- editable 安装（--no-deps）和 wildtrace CLI 帮助验证通过。

## Local installation documentation

- README 增加本地安装、测试和 LLM 环境变量说明。

## Repository security policy

- 新增 SECURITY.md，明确本地审计范围和安全报告边界。

## Code ownership

- 新增 CODEOWNERS，要求项目维护者审核变更。

## Safe verification link persistence

- 新增验证关联记录的 schema 校验、独占持久化和覆盖保护。

## Shard merge resource gate

- 跨分片合并新增 max_shards 上限。

## Scanner network isolation regression

- 增加扫描流程不触发网络或 LLM 的回归测试。

## Verification digest format gate

- 验证关联严格校验 checkpoint SHA-256 格式。

## Shard evidence conflict gate

- 跨分片合并拒绝同 ID 不同内容的证据记录。

## Phase 4 acceptance checklist

- 新增证据驱动的 Phase 4 验收清单。

## Verification link recovery

- 验证关联记录支持离线读取和重新校验。

## Current checkpoint clarification

- 明确 PROJECT_STATE 前部历史条目与末尾最新检查点的优先级。

## Phase 4 bounded closure

- Phase 4 允许范围闭环完成，明确不执行真实目标代码。
- 下一阶段进入 Phase 5 准备：分支影响、补丁验证和报告。

## Phase 5 branch impact comparison

- 新增本地扫描结果分支影响比较器，输出候选变化并保持 review_required。

## Phase 5 patch scope gate

- 新增本地补丁路径范围校验，拒绝越界路径。

## Phase 5 scan schema gate

- 分支影响比较要求扫描结果 schema 0.3。

## Phase 5 local path only gate

- 补丁路径校验拒绝 URL 形式输入。

## Phase 5 scan root binding

- 分支影响比较绑定扫描源码根目录。

## Phase 5 local result gate regression

- 增加非 local_only 结果拒绝测试。

## Phase 5 findings structure gate

- 分支影响比较新增 findings 结构校验。

## Phase 5 branch impact CLI

- 新增本地 JSON 分支影响比较 CLI。

## Phase 5 branch impact CLI regression

- 增加 CLI 成功路径回归测试。

## Phase 5 installed CLI entry

- 新增 wildtrace-impact 安装后命令行入口。

## Phase 5 JSON root type gate

- 分支影响比较器新增 JSON 根类型校验。

## Phase 5 patch hash verification

- 新增本地补丁文件 SHA-256 校验。

## Phase 4 joint file validation

- 新增检查点、扫描结果和 harness 记录的联合文件校验入口。

## Verification link generation consistency

- link 生成端与校验端统一 SHA-256 格式约束。

## Phase 5 patch digest format gate

- 补丁文件摘要校验新增标准 SHA-256 格式门控。

## Phase 5 impact draft projection

- 新增分支影响到 review-only 草稿的确定性投影。

## Phase 4 joint verification CLI

- 新增 verify-joint 联合文件校验命令行入口。

## Phase 5 impact draft validation

- 增加分支影响草稿 review-only schema 校验。

## Phase 5 impact report projection

- 新增绑定双扫描结果摘要的 review-only 影响报告。

## Phase 5 review report projection

- 分支影响报告可投影进入现有人工审核 API。

## Phase 5 task association validation

- 增加影响报告无效任务关联拒绝测试。

## Phase 5 review API integration test

- 验证影响报告可进入现有人工审核 API，保持不可确认结论。

## Phase 4 joint input symlink gate

- 联合验证入口拒绝符号链接输入。

## Phase 5 impact review batch

- 分支影响报告接入人工审核批次创建流程，禁止最终确认。

## Phase 5 bounded closure and Phase 6 start

- Phase 5 允许范围闭环完成：分支影响、补丁校验、报告草稿和审核批次均已验证。
- 123 项测试，119 通过、4 跳过。
- 正式进入 Phase 6：性能评测、演示和交付准备。

## Phase 6 synthetic performance benchmark

- 新增有资源上限的合成扫描性能基准。

## Phase 6 performance CLI

- 新增 wildtrace-perf 命令和 JSON 输出回归测试。

## Phase 6 performance regression

- 性能专项 3 项、全量 126 项测试通过（4 项跳过）。

## Phase 6 performance contract documentation

- 新增性能评测契约文档，明确合成输入和统计边界。

## Phase 6 performance matrix

- 新增受边界限制的多规模合成性能矩阵。

## Phase 6 CI performance smoke

- CI 增加受限性能基准 smoke test。

## Phase 6 throughput regression comparison

- 新增本地性能吞吐退化比较器和门控测试。

## Phase 6 local demo guide

- 新增安全本地演示流程文档。

## Phase 4 FSM joint verification gate

- local_verification 到 triage 必须通过 checkpoint/result/harness 联合校验。
- 验证失败保持状态不变，相关专项 47 项测试通过。

## Phase 6 performance result schema

- 新增性能结果 schema 和安全字段校验。

## Phase 6 throughput field gate

- 性能结果新增 files_per_second 字段门控。

## Phase 6 performance CLI schema gate

- 性能 CLI 输出前新增即时 schema 校验。

## Phase 6 bounded shard scheduler

- 新增按 manifest 顺序的受控分片扫描调度。

## Phase 4 source snapshot joint gate

- 联合验证新增 checkpoint/result 源码快照摘要一致性校验。

## Phase 4 source snapshot regression

- 全套测试 135 项，131 通过、4 跳过。
- 源码快照联合校验与完整工作流无回归。

## Phase 6 peak memory metric

- 性能基准新增峰值内存采样和 schema 校验。

## Phase 6 performance result persistence

- 新增性能结果安全落盘和覆盖保护。

## Phase 6 performance result recovery

- 性能基线支持读取并重新校验。

## Phase 6 performance report formatting

- 新增性能矩阵 Markdown 报告生成函数。

## Phase 6 performance baseline snapshot

- 新增合成性能基线 Markdown 快照。

## Versioned local vulnerability knowledge base

- 新增本地 CVE/CWE 知识库记录校验和整体摘要。

## Knowledge base resource handling

- 修复知识库读取未关闭文件句柄问题。

## Deterministic knowledge base matching

- 新增组件和版本精确匹配函数。

## Knowledge base unresolved matching

- 知识库版本未精确匹配时保留 unresolved 候选。

## Knowledge base source binding

- CVE/CWE 匹配结果携带知识库和源记录摘要。

## Local knowledge base contract documentation

- 新增本地 CVE/CWE 知识库契约文档。

## Knowledge base text field gate

- 知识库新增文本字段完整性校验。

## Knowledge base file size gate

- 本地知识库新增 16 MiB 文件大小限制。

## Current state and acceptance calibration

- 统一 PROJECT_STATE 顶部有效口径，保留历史记录但明确 Phase 4/5 完成范围与 Phase 6 原型范围。
- 最近全量测试为 139 项，135 通过、4 跳过。

## Phase 5 fixed local Git scope contract

- 新增本地固定版本、分支、日期和组件范围契约。

## Phase 5 local Git adapter

- 新增本地 revision、parent 和 changed_files 读取适配器。

## Phase 5 Git scope digest binding

- Git scope record 新增 observed_branch 和确定性 scope_sha256。

## Phase 5 local commit range

- 新增本地 Git 提交区间和变更文件读取。
## State checkpoint calibration

- 统一 PROJECT_STATE.md 顶部当前有效阶段、完成范围、未完成项和最新测试数字；保留追加式历史记录。
# 2026-09-13

- 收敛分析引擎适配层 Phase 1 检查点：记录当前 178 项通过、4 项环境跳过，并明确路径、快照、schema、来源和告警 ID 门禁的验证边界。
- 组件 profile 增加本地引擎允许列表，拒绝未声明的远程或未知引擎；全量回归更新为 179 项通过、4 项环境跳过。
- 组件 profile 支持源码根内的 Semgrep 本地规则文件，并通过统一证据合并链生成候选；全量回归 180 项通过、4 项环境跳过。
- 对 OpenHarmony-complete camera_ability.cpp 执行本地 Semgrep 合成规则试验：扫描成功、0 条诊断，规则哈希已记录；结果仅作为组件级静态证据。
- Semgrep profile 输出现在包含每个本地规则文件的 SHA-256，便于跨引擎结果复核和复现。
- 新增 `docs/design/camera_semgrep_profile.json`，记录 camera 组件固定提交、规则相对路径和哈希；保持 candidate-only 与源码根内规则门禁。
- 新增保守的 `ohvul.semantic_facts` 事实提取层及越界回归测试，为后续跨函数长度传播和生命周期规则提供统一输入；不升级为漏洞结论。
- 新增长度传播候选规则，将复制 sink、长度源和边界上下文绑定为可复核证据；修正复制行被误识别为长度源的问题。
- 增加显式文件集合内的 caller→callee 长度传播候选关联，并保留人工复核问题。
- 将语义长度候选投影到 schema 0.3 和 EvidenceBundle，绑定源码位置与快照摘要，并通过统一结果校验。
- 主 CLI 增加显式 `--semantic-files-from`，将语义候选并入现有结果、快照和报告链；默认扫描不受影响。
- 新增 `docs/design/CVE_KB_COLLECTION.md`，定义 CVE/CWE 本地知识库的字段、来源优先级、版本规范、双人复核、交付物和安全边界，供合作伙伴采集。

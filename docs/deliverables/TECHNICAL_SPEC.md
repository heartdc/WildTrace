# WildTrace 技术说明书（v1.0）

> 面向赛题《OpenHarmony 开源代码漏洞挖掘》交付件二。本文严格区分**已实现并验证**
> 的能力与**设计中/计划中**的能力（各节状态标注），不含未经验证的质量主张。
> 基线：master 分支 `1c80e2d`（PR #89 合并），2026-09-30，全量测试 **1016 项通过 /
> 5 项环境跳过**，CI（Ubuntu）全绿。
> v1.0 相对 v0.9 的主要更新：自动化分析管线（Autopilot v3）、跨函数 UAF、Joern CPG
> 桥接、LLM PoC 生成器、版本分支影响矩阵（kb 联接）、交付件组装器全部入册；
> 2026-09-29 全面代码审计的修复结果同步收录。

---

## 1. 概述

### 1.1 定位

WildTrace 是一套**本地、离线优先、证据可审计**的 OpenHarmony C/C++ 漏洞分析工具，
覆盖"静态候选 → 结构化研判 → 授权隔离执行 → 运行级证据 → 独立复现 → 报告"全链，
并在此之上提供**端到端自动化分析管线**（Autopilot）与**比赛交付件组装**能力。
所有自动产出物一律为 **candidate/lead（候选）**，漏洞确认只能由人工审核完成——
这是贯穿全部模块的第一设计约束。

### 1.2 设计原则

1. **证据优先**：每个结论绑定源码快照摘要、命令、退出码、产物哈希；证据不可变
   （只追加存储、独占创建、拒绝符号链接）。
2. **失败即失败**：构建失败、传输失败、输入变化都不会被粉饰为成功结果；离线
   核验器拒绝不完整的运行记录。
3. **最小权限**：扫描默认不联网、不执行目标代码、不接触凭据；唯一的执行通道由
   双人签署的范围化授权书打开。LLM 通道为显式选配且经注入/外泄加固（§3.4、§3.9）。
4. **有界性**：各模块按实现约束输入与运行资源；快照限制文件数、目录项数和总字节
   数；LLM 上下文读取有字节上限。
5. **不发明数字**（v1.0 新增）：影响矩阵只声明有证据的判定格（§3.10）；报告只
   投影 case.json 显式字段；确认漏洞数口径固定且不做推断。2026-09-29 审计曾发现
   三处"声明与代码不符"（跨组件基线兜底伪造全红矩阵、报告硬编码全分支受影响、
   "11 层"实为死代码），已全部修复并由回归测试钉死。

### 1.3 能力总览

| 能力 | 状态 | 验证证据 |
|---|---|---|
| 多引擎静态分析（7 层，§3.1） | ✅ 已实现 | 44 个真实 OH 源文件分析、35 条诊断入 29 个复核组 |
| **函数作用域规则引擎（detect/function_rules）** | ✅ 已实现 | 三规则（整数溢出/空指针解引用/固定缓冲拷贝）+ 守卫精度；34 项配对真假基准；削减正则粗筛两类已知误报，入 benchmark 对比 |
| **自动化管线 Autopilot v3（§3.8）** | ✅ 已实现 | dsoftbus 742K 行实测（历史口径，见 §5）；1016 项回归含专项测试 |
| **跨函数 UAF/双重释放（§3.8.2）** | ✅ 已实现 | 位置别名 + 局部变量追踪 + (callee,var) 去重；专项测试 20+ 项 |
| **Joern CPG 深度分析（§3.8.3）** | ✅ 已实现（--joern 选配） | WSL /opt/joern 实测 dsoftbus；异常安全降级 |
| **LLM PoC 生成器（§3.9）** | ✅ 已实现并加固 | 路径包含/注入防御/输出屏蔽 16 项安全测试 |
| **版本分支影响矩阵 + kb 联接（§3.10）** | ✅ 已实现 | 18 案 × 6 分支 = 88 证实 / 6 证实不受影响 / 14 待定（全部可复算） |
| CVE 知识库三层 + 版本探测（§3.6） | ✅ 已实现 | 全量层 375,265 条；靶区子库 446 条（kb 联接数据源） |
| 隔离执行与运行级证据（§3.5） | ✅ 已实现并实战 | cJSON 案例矩阵 26/26；第二人独立复现通过 |
| 运行矩阵离线复算（verify-runtime） | ✅ 已实现 | 复算=零执行 |
| 有界 LLM 审查（§3.4） | ✅ 通道验收通过 | z.ai/glm-5.3 在线单组验收；29 组全量待执行 |
| UAF 生命周期规则（§3.3） | ✅ 已实现 | 已知 cJSON 案例回验 + 反例语料 |
| 候选人工复核队列（triage） | 已实现五类队列 | 保留每条告警，不自动证明可达性与影响 |
| 交付件组装（vuln_report / competition_report，§3.11） | ✅ 已实现 | 18 案报告自动生成；证据引用 16/18 案 |
| 工具链预检（toolchain preflight） | ✅ 已实现 | `python -m ohvul.toolchain --output ...` |
| 执行沙箱自动化（§3.5 扩展） | 📐 设计稿已合入 | P0–P2 待实施 |
| 双模型交叉验证 | 📐 白名单就绪 | grok-4.6 / glm-5.3 / gpt-6-astra，待全量运行 |
| OH 真实库构建与平台验证 | IPC 库级证实；产品验证待完成 | `REAL_BUILD_PROBE_20260925.md`；库级≠平台复现 |

---

## 2. 总体架构

### 2.1 工作流状态机

`ohvul/workflow/fsm.py`：状态集 `intake → static_scan → local_verification →
triage → report → human_review → completed`（另有 blocked / 重试预算 ≤3）。
关键约束：

- 迁移合法性由 TRANSITIONS 表硬编码；`local_verification → triage` 必须携带
  checkpoint/result/harness 三元组并通过 `load_verified_checkpoint` 校验；
- blocked 恢复只能回到 intake/static_scan（有界恢复）；重试预算在迁移内强制；
- 检查点含 `source_snapshot_sha256`：扫描前后比对，源码期间变化即拒绝产出。

### 2.2 证据链模型

一切产物走同一条证据管道：

- **EvidenceBundle**（`domain/evidence.py`）：内容寻址（`EB-<sha256>`），源位置、
  环境指纹（execution/network 标志）、artifacts 摘要列表；
- **联合校验**（`verify.py` / `verify_joint.py`）：finding↔bundle 摘要逐字段一致；
  报告投影字段与扫描结果全等（`report_verify`）；
- **归档封存**：日志、检查点、报告归档后经 `journal_archive_verify` /
  `archive_seal_record` 生成不可覆盖的关联标记；
- **verification_link**：task_id + checkpoint 摘要 + harness 记录三元绑定。

### 2.3 模块地图（代码功能实现）

| 目录/模块 | 职责 |
|---|---|
| `ohvul/autopilot.py` | **端到端自动化管线 v3**（§3.8）：10 层扫描 + 置信度 + PoC + 统一报告 |
| `ohvul/cross_uaf.py` | 跨函数 UAF/双重释放（位置别名、局部变量、去重语义） |
| `ohvul/joern_bridge.py` | Joern CPG 桥接（--joern 选配层，异常安全降级） |
| `ohvul/llm_poc.py` | LLM PoC 生成器（安全加固，§3.9） |
| `ohvul/impact_matrix.py` / `vuln_report.py` / `competition_report.py` | 影响矩阵（kb 联接）与交付件组装（§3.10/§3.11） |
| `ohvul/toolchain.py` | 工具链预检（真实通道探针，required/optional 分级） |
| `ohvul/detect/`（scanner、lexical） | 内置规则初筛 + 词法层 |
| `ohvul/semantic_facts / semantic_rules / semantic_syntax` | 语义事实抽取、长度传播规则、有界词法解析 |
| `ohvul/clang_facts / clang_flow / clang_ranges` | 编译器 AST 事实、精确值标量流、区间抽象域（§3.2） |
| `ohvul/engine_adapter / engine_profile / engine_shards / compile_database` | Clang/CSA、clang-tidy、Semgrep 适配；profile 来源校验 |
| `ohvul/llm_adapter / llm_review / llm_evidence` | 有界 LLM 审查（§3.4）与传输 |
| `ohvul/knowledge_base / kb_sync` | CVE 知识库三层与同步（§3.6） |
| `ohvul/runtime_evidence` + tools/cjson_case.py | 授权运行案例管线（§3.5） |
| cases/、bench/、kb/ | 钉死验证案例（18 案）、反例语料、靶区知识库 |

---

## 3. 关键技术原理

### 3.1 多引擎静态分析栈（已实现）

七层互补，全部产出统一 schema 0.3 候选（带 EvidenceBundle）：

1. **内置规则**（正则初筛，定位为粗筛不作为依据）；
2. **语义层**：有界词法解析（结构剥离：注释/字符串/预处理行；括号平衡参数提取）
   + 跨函数长度传播候选；
3. **Clang 静态分析器**（WSL 隔离运行，plist 归一化）；
4. **clang-tidy**（文本诊断归一化，检查器集合显式声明）；
5. **Semgrep 污点**（本地规则文件强制、显式文件清单）；
6. **编译器 AST 事实层**：固定版本 clang `--analyze` 流式 AST 解析，进程隔离；
7. **标量流 + 区间域**：AST 上的保守数据流（§3.2）。

统一约束：`_normalize_engine_path` 将 /mnt 形态路径统一为相对根并拒绝越界；
引擎结果经 `engine_result_to_audit_result` 投影进主 schema 并可合并去重。

### 3.2 编译器背书的事实层与区间抽象域（已实现）

- **进程隔离**（`compiler_analysis._command`）：固定编译器路径 + 外层
  `timeout --kill-after` + `env -u` 清除 CPATH 等 5 个环境注入向量 +
  `--no-default-config` 禁配置文件发现；shell=False、stdin 封死；双流有界读取
  线程（超限即 kill，字节计数与 sha256 入证据）。
- **精确值标量流**（`clang_flow`）：仅自动存储期整型局部变量；**kill-on-unknown**
  ——任何调用、未知存储、取地址、非结构化控制即清空环境；循环入口杀死循环前
  赋值；预算墙（10 万节点/128 深/4096 绑定/64 证据源）。
- **区间抽象域**（`clang_ranges`）：类型域约束下的区间算术（四角乘积、比较三值
  逻辑）；转换语义是正确性核心——有符号越界返回 None、无符号仅同模数块内回绕；
  混合符号比较反推与非保值转换约束全部有测试钉死。
- **类型尺寸**（`clang_facts.size_of`）：括号指针声明符一律指针尺寸；不可建模
  形态返回未知——解析失败绝不产生看似精确的错误数。

### 3.3 UAF 生命周期规则与已知案例回验（已实现）

两条窄规则（#34）：同句柄 use-after-delete 与同 pointee 类型别名使用。
**方法论**：每条新规则先在 `bench/lifecycle_counterexamples/` 配对语料（含真实
cJSON 正例与安全反例）上回验再上线。

### 3.4 有界 LLM 审查（通道验收通过，29 组全量待执行）

- **传输**（`llm_adapter`）：HTTPS-only 白名单端点、模型白名单、密钥仅运行时
  读取、请求与消息双向凭证形态拒绝、无流/无重试/无重定向、尺寸与超时上限；
  畸形 provider 响应一律收敛为 `LlmTransportError`（不裸逃异常）。
- **审查契约**（`llm_review`）：五维评估问题；`independent_validation` 强制
  unknown；系统提示内建注入防御；`final_verdict` 恒为 undetermined。
- **交接**（`review_handoff`）：LLM 草稿投影为"带证据引用的开放任务"，全部标记
  untrusted_model_proposal。
- **双模型交叉验证**（设计中）：白名单已就绪，待全量运行。

### 3.5 隔离执行与运行级证据（已实现并实战验证）

以双人签署的《隔离执行环境授权书》为唯一通道：

- **隔离**：bubblewrap `--unshare-all --cap-drop ALL`，只读绑定源码与工具链，
  tmpfs /tmp、clearenv、loopback-only；运行前隔离探针验证；prlimit 限制。
- **判定**：崩溃分类完全机器判定（ASan 报告 + 访问轨迹 + 日志特征）；
  功能对照要求零 sanitizer 报错 + CASE_OK 标记。
- **离线复算**（verify-runtime）：不执行任何代码复算每行分类。
- **实战验证**：cJSON 公开案例（CVE-2026-87933 库级）矩阵 26/26，含第二复现人
  独立环境复现（26/26，结构全等）。边界声明：已知公开案例的库级验证，非新发现、
  非产品级结论。

### 3.6 CVE 知识库三层与版本探测（已实现）

| 层 | 内容 | 规模与状态 |
|---|---|---|
| 全量层 | cvelistV5 归一化 | 375,265 条 / 188 分片，本地构建+verify（体积原因不入库） |
| 精选层 | OH 官方公告 CVE，双人复核 | 72 条入库，含逐分支修复 commit + diff 边车 |
| 靶区子库 | 19 个高价值 third_party 组件 | 446 条入库（openssl 133 / curl 98 / ffmpeg 80…） |

**靶区子库自 2026-09-29 起兼任影响矩阵的判定数据源**（§3.10）。版本探测
（`tools/kb_version_probe.py`）与 OSS-Fuzz OSV 层的边界同 v0.9 记录。

### 3.7 安全边界体系

默认禁令（不执行目标代码/不联网/不自动提交）→ 唯一例外 = 双签授权书；
LLM 凭证永不入库入日志；CI 含密钥形态扫描。LLM PoC 生成器在选配时叠加：
路径包含检查、提示注入防御（围栏消解 + 摘要绑定 + 不可信标注）、输出危险 API
屏蔽（§3.9）。

### 3.8 自动化分析管线 Autopilot v3（已实现）

```
python -m ohvul.autopilot <source_root> --output <dir> [--min-confidence N] [--joern]
```

一条命令完成：文件面发现（CJ FFI / 通用 C/C++ 分类）→ 多层扫描 → 置信度排序
→ PoC 模板生成 → 统一 JSON+Markdown 报告。

**3.8.1 层级结构（默认 10 层，--joern 时 11 层）**

1. P1–P3：CJ FFI 面三族（空指针+长度 unchecked、整型截断、多级解引用）；
2. P4–P9：通用 C/C++ 六族（无界拷贝、栈溢出、空指针、分配溢出、UAF、格式串）；
3. 第 10 层：跨函数 UAF/双重释放（§3.8.2）；
4. 第 11 层（选配 `--joern`）：Joern CPG 深度分析（§3.8.3）。

`summary.scanners` 如实列出执行过的层；`conf>=70` 为精确计数。

**3.8.2 跨函数 UAF（cross_uaf）**

三种单函数 P8 看不到的模式：A（caller 释放后传给 callee 解引用）、B（callee
释放后 caller 继续使用）、C（双重释放）。要点：

- **位置别名解析**：caller 的 `ptr` 映射 callee 的第 N 个参数（参数名可不同）；
  函数指针/数组/未命名参数保留位置空槽，后续参数不错位；
- **局部变量追踪**（`freed_any`）：`malloc → free → 传参` 的局部指针 UAF 可检出
  （callee 侧判定仍严格限参数，避免同名局部误报）；
- **去重语义**：每个模式按 (callee, 变量) 只发一条——每个调用点一条的旧实现
  在 3000 次 `sink(a)` 调用上产出 3000 条重复发现；
- **宏免疫**：`#define` 宏体不解析为函数，dsoftbus `LIST_FOR_EACH_ENTRY_SAFE`
  类宏误报已实证为零并有回归测试钉死；
- **同名多定义**：事实完全相同的同名函数保留（归属无关），不同则判歧义丢弃
  （不静默 last-writer-wins）。

**3.8.3 Joern CPG 桥接（选配）**

`--joern` 显式启用：J4（无界拷贝）/J6（空指针路径敏感）/J8（UAF 跨定义）三个
CPG 查询，发现转换为管线 Finding（CWE/严重度/置信度保留），报告含 joern 统计块。
默认运行不触碰 WSL；不可用时警告降级不崩溃。工程细节：

- 全部 subprocess 异常安全（WSL 缺失返回 False 而非抛异常）、UTF-8 容错解码；
- Scala 侧 JSON 转义（含引号/反斜杠的代码不再静默丢发现）、路径 shlex 引用；
- CPG 二进制写入分析环境 `/tmp/wildtrace-cpg/<源根哈希>.bin`（不污染被审计树，
  按源根命名跨运行复用；`remove_cpg()` 回收）；
- CPG 构建失败只试一次（旧版每查询重试最长 33 分钟）。

**3.8.4 置信度打分**

每条发现 0–100 分并附人类可读因子分解（Coverity 式统计优先级）。打分测试
正确的变量（如 P4 的 size 变量、P9 的格式参数位）；调用方空检查降分保留而非
丢弃；跨函数发现携带别名证据加分。`lead ≠ 漏洞`：置信度是排序优先级，不是
准确率保证。

### 3.9 LLM PoC 生成器（已实现并加固，选配）

```
python -m ohvul.llm_poc findings.json <source_root> --output llm_pocs   # 需 OSLOVELACE_API_KEY
```

把 autopilot lead + 源码上下文交给 LLM 生成可编译 C PoC（从"带 TODO 的模板"
升级为"真实代码"）。安全契约（2026-09-29 审计后加固，16 项专项测试）：

- **路径包含**：`finding['file']` 必须解析在 source_root 内（`../` 逃逸与绝对
  路径覆盖一律拒绝）——旧实现可把任意本地文件前 3000 字符发往远端端点；
- **注入防御**：扫描源码与 findings 字段按不可信数据处理（围栏序列消解 +
  sha256 摘要绑定 + "UNTRUSTED DATA" 标注 + 系统提示证据契约）；
- **输出屏蔽**：危险 API 黑名单（system/popen/exec*/fork/unlink/remove、
  /bin/sh、curl/wget/nc）命中即不落盘；截断响应（finish_reason=length）拒绝；
- **批量鲁棒**：逐项异常隔离、摘要 finally 写出、429 退避、文件名哈希防碰撞；
- **有界读取**：上下文读取 256 KiB 封顶。

### 3.10 版本分支影响矩阵与 kb 联接（已实现）

```
python -m ohvul.impact_matrix --cases cases --output docs/deliverables/IMPACT_MATRIX
```

18 案 × 6 分支（v4.1–master）。判定规则**证据分级、绝不推断**：

1. **kb 联接（首选）**：按 CVE 联接 `kb/third_party_targets/records.json`
   （cvelistV5）的上游受影响/修复版本，按 cvelist 边界语义逐分支判定；
2. case.json 结构化受影响范围（CVE 5.0 语义）；
3. 版本等价传播（分支基线与实测验证基线同版本）；
4. OH 原生代码仅计源级验证过的分支；**绝不跨组件借用基线**。

**当前交付件结果：🔴 证实受影响 88 格 / — 证实不受影响 6 格 / ？待定 14 格**
（待定 = cJSON 各分支基线未录入 6 格 + OH 原生旧分支 CJ FFI 引入时间未确认 8 格，
各有明确升级路径）。值得一提的负向结论：quirc（cvelist 引入版本 7.0）在 n4.1/
n5.1.6/n6.1.1 四个基线上**证实不受影响**——旧手写矩阵的全红口径被库内数据证伪。

### 3.11 交付件组装（已实现）

- `ohvul.vuln_report`：分案完整报告（位置与内容、描述、PoC、影响分析、修复
  建议）。源码片段承载内容：案例目录 `source_snippet.txt/.c` 嵌入，否则引用已
  记录的源码级证据（16/18 案）；已存在输出拒绝静默覆盖（--force）。
- `ohvul.competition_report`：异构 case.json 的防御性投影 + 证据完整度六维矩阵；
  空输入大声失败；markdown 先于 JSON 发布；confirmed 数字只投影不推断。

### 3.12 函数切分的注释安全性（已实现，贯穿 autopilot/cross_uaf）

函数头识别与括号匹配在**长度保真的注释/字符串掩码**上进行：注释中的撇号不再
吞掉整个函数（742K 行级的大面积漏报根源）、注释内 `}` 不再截断函数体、`// {`
不再吞并下一函数、`else if` 与 `#define` 宏不再被当函数；块注释按换行数替换，
报告行号不漂移。

---

## 4. 工程实现

### 4.1 规模与质量

- 测试：**1016 项通过 / 5 项环境跳过**（Windows 符号链接限制）；CI（Ubuntu）
  全绿；从审计基线 895 项增长 121 项（全部为审计/修复驱动）。
- **2026-09-29 全面代码审计与修复**：四子代理并行审查 + 逐项实证复现，发现并
  修复 2 项 P0（影响矩阵跨组件基线兜底伪造全红、"11 层"死代码）、多项 P1/P2
  （P9 格式参数位、P4 打分变量、P6 静默丢弃、cross_uaf 重复计数与别名错位、
  llm_poc 注入/路径穿越、报告边界崩溃等），修复即配回归测试钉死。
- 分支治理：单一交付分支（master），PR 独立审查、CI 全绿后合并，合并后自动
  删除头分支；行尾策略（.gitattributes）与本地产物忽略（.gitignore）就位。

### 4.2 数据契约族（schema 清单）

`audit-result-0.3`、`evidence-bundle-1`、`workflow-checkpoint-1`、
`engine-profile-0.1`、`llm-review-plan/draft-0.1`、`review-evidence-handoff-0.1`、
`knowledge-base-0.1`、`kb-manifest-0.1`、`partner-evidence-sidecar-0.1`、
`cjson-observed-matrix-0.1`、`case-specific-validation-0.2`、
`kb-version-probe-0.1`、`wildtrace-competition-report-0.1` 等——全部带版本号与
向后兼容策略（旧格式显式拒绝）。

### 4.3 CLI 入口速查（节选）

```
# 自动化管线（默认 10 层；--joern 启用第 11 层，需 WSL /opt/joern）
python -m ohvul.autopilot <root> --output <dir> [--min-confidence N] [--joern]
# LLM PoC 生成（选配，需 OSLOVELACE_API_KEY）
python -m ohvul.llm_poc findings.json <source_root> --output llm_pocs
# 影响矩阵与交付件
python -m ohvul.impact_matrix --cases cases --output docs/deliverables/IMPACT_MATRIX
python -m ohvul.vuln_report --cases cases --output docs/deliverables/VULN_REPORT.md --force
python -m ohvul.competition_report --cases cases --output out/report.json --markdown out/report.md
# 工具链预检（演示第一步）
python -m ohvul.toolchain --output preflight.json
# 离线管线与知识库
python -m ohvul.cli <root> --output ... --checkpoint ... --vuln-db ...
python -m ohvul.kb_sync build/verify ...
python -m ohvul.llm_review --plan|--run --allow-network|--verify ...
python -m ohvul.benchmark <cases.json> [--scanner ...]
```

---

## 5. 实测证据汇总（截至 2026-09-30，全部可复验）

| 项目 | 数字 |
|---|---|
| 全量测试 | 1016 通过 / 5 环境跳过；CI 全绿 |
| 真实 OH 文件分析 | 44 文件（3 组件，profile 来源校验通过） |
| 运行级证据案例 | cJSON 矩阵 26/26；独立复现 26/26（双重复现） |
| CVE 知识库 | 375,265（全量，本地）+ 72（精选）+ 446（靶区，兼矩阵数据源） |
| Autopilot 实测 | dsoftbus 742K 行 / 217s / 2466 lead（**历史口径**：检测质量修复
  前的运行记录；cross_uaf 去重与判定收紧后计数将下降，性能交付件将统一复测） |
| Joern CPG 实测 | dsoftbus：CPG 构建 158s + 查询 58s = 8153 lead（独立运行记录；
  管线内为 --joern 选配层） |
| 影响矩阵 | 18 案 × 6 分支：88 证实受影响 / 6 证实不受影响 / 14 待定（可复算） |
| 漏洞案例与工单 | 18 案（15 缺口回验 + IPC/KV 新发现方向）；平台工单 16 张全部
  待受理（15 缺口 + IPC 新发现 OHSA26-092953990）；8 案已补 PoC 评论 |
| 确认漏洞数 | **0**（口径：产品级确认；公开案例库级复现与工单待受理不计入） |

## 6. 创新点（与现状对齐的表述）

1. **证据链优先的漏洞分析管线**：从静态候选到运行证据全程内容寻址、可离线
   复算、可第二人独立复现——以 cJSON 案例完成全链实战验证。
2. **有界 LLM 的"供信号不裁决"实现**：审查侧五维评估 + 注入防御 + 强制 unknown；
   PoC 生成侧路径包含 + 围栏消解 + 摘要绑定 + 危险 API 输出屏蔽——LLM 永远
   不产生漏洞结论，也不成为本地文件外泄或代码注入的通道。
3. **编译器背书的保守数据流**：精确值/区间双层域，转换语义保守化 +
   kill-on-unknown + 全线预算墙——误报驱动修复并以配对反例钉死。
4. **证据分级的影响矩阵**：kb（cvelistV5）联接 + 版本等价传播 + ？不推断的
   三级判定，产出含负向结论（证实不受影响）的可复算分支影响面。
5. **已知案例回验新规则**的方法论 + **审计驱动的自我纠错**：2026-09-29 全面
   审计发现的"声明与代码不符"全部修复并由回归测试钉死（含手写矩阵被库内
   数据证伪的案例）。

## 7. 已知局限与未完成项（诚实清单）

- 确认漏洞数为 0：现有运行证据为公开已知案例的库级复现 + 2 项真库级证实
  （IPC 已提交工单、hiappevent 待提交第 17 单）；产品可达性未建立。
- 性能交付件已复测落盘（2026-09-30，`docs/deliverables/PERFORMANCE.md`）：dsoftbus
  681,529 行 / 10 层管线 651.7s（~1,046 行/s）/ 3033 lead / 峰值 176.4MB，为检测
  质量修复后的现役口径。
- 干净环境独立复跑已完成（新 venv 安装 + 全量 1058 项通过，2026-09-30）；
  DEMO 视频录制待执行（VIDEO_SCRIPT.md 就绪）。
- 影响矩阵 18 个 ？格：cJSON 各分支基线未录入（6）、OH 原生案（hiappevent/ipc/kv）
  旧分支 CJ FFI 引入时间未确认（12）。
- LLM 29 组全量审查与双模型交叉验证待执行（通道就绪）。
- 内置正则扫描仅作初筛；语义结论以上层引擎为准；跨函数分析为轻量别名级，
  非完整指针分析。
- CJ FFI 30 条批量候选的对侧构建被 ninja 图冲突阻塞（PR #76 记录），执行件
  全部在库。

## 8. 附录：关键文档索引

- 交付件：`docs/deliverables/`（TECHNICAL_SPEC、VULN_REPORT、IMPACT_MATRIX、
  PERFORMANCE、VIDEO_SCRIPT、DEMO_RUNBOOK）；
- 状态台账：`docs/status/`（CASE_LEDGER、SUBMISSION_QUEUE、PROJECT_STATE 等）；
- 审计记录：`docs/analysis/`（含 2026-09-29 L4 三级审计、REAL_BUILD_PROBE、
  cJSON 运行案例、独立复现、各轮代码审查）；
- 设计稿：TRIAGE_SIGNALS_DESIGN.md、EXECUTION_SANDBOX_DESIGN.md；
- 工程契约：docs/engineering/*（LLM_REVIEW、REVIEW_HANDOFF、KB_VERSION_PROBE、
  EVIDENCE_VALIDATION 等）；
- 变更史：CHANGELOG.md（追加一至二十，含全部审计修复记录）。

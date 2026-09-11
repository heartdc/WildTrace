# OpenHarmony 开源代码漏洞挖掘工具
# 技术说明书与设计方案 v2（合并版）

|        |                                                                                   |
| ------ | --------------------------------------------------------------------------------- |
| 文档版本   | v2.0（合并"技术说明书 v1"与"受控 Agent 工作流设计文档"，取代 v1）                                       |
| 日期     | 2026-09-09                                                                        |
| 赛题     | 26 年网安揭榜赛·OpenHarmony 开源代码漏洞挖掘                                                    |
| 截止时间   | 2026-10-22                                                                        |
| 团队前期基础 | 张鑫棋《基于大语言模型与静态程序分析的自动化代码安全检测方法研究》（2025）；朱笑锋《结合大语言模型的鸿蒙 ArkTS 应用污点分析研究》（2026），均有源码 |

**合并说明**：本版以"受控 Agent 工作流"的工程治理骨架（LangGraph 状态图、证据链、四层发现、双环境验证、独立复现）为主体，嫁接 v1 的检测与研判内容（已知漏洞线、多信号安全性研判、LLM 规则自生成、commit 范围模式、分支影响分析、45 天排期），并裁决了三项技术分歧：静态分析采用三层并行（§4.2）、harness 与 fuzz 入口合流（§6.1）、OpenHarmony 真机复现收缩至最终提交集（§7.2）。

---

## 1. 项目概述

### 1.1 目标

面向 OpenHarmony 社区开源代码，构建端到端自动化漏洞挖掘工具：

```
代码库获取 → 组件/CVE 匹配 → 静态候选生成 → 多信号安全性研判
    → PoC 合成 → 主机侧验证 → 独立复现 → (提交集)OH 环境复现
    → 影响分析 → 报告生成 → 人工审核 → 提交奖励计划
```

产出三类结果：
1. **已知漏洞记录**：组件版本 + CVE 匹配，重点捕获"上游已知、OpenHarmony 未处置"的中间形态；
2. **新发现漏洞**：带运行级证据（可执行 PoC + sanitizer 崩溃报告 + 独立复现证据），提交 OpenHarmony 安全漏洞奖励计划；
3. **完整漏洞分析报告**：对齐官方安全公告格式，附研判留痕与性能数据。

### 1.2 核心原则

1. **证据优先**：所有结论绑定源码版本、环境指纹、命令、日志、退出码和产物哈希；LLM 输出只是信号，永远不是结论。
2. **模型受控**：LLM 只提出分析计划、上下文解释、PoC 草稿和修正建议，不能绕过策略与验证门禁；研判融合由确定性决策表完成，不由模型投票产生结论。
3. **最小权限**：Agent 通过带 schema 的受限工具接口访问源码、构建系统、沙箱和报告库，不执行任意 Shell。
4. **双环境验证**：主机侧快速筛选，OpenHarmony 环境目标平台确认，证据分开保存、结论规则分开定义。
5. **独立复现**：最终提交结论必须由新建的独立复现任务重新执行验证，不复用生成任务的进程状态或临时文件。
6. **失败可解释**：每次失败记录阶段、错误类别、重试次数、输入版本和修正动作；所有 discard（不报）决定同样留痕。

### 1.3 明确不做（写入展望）

ArkTS 应用 → native 服务跨语言攻击路径、权限提升类规则挖掘、信息泄露类规则挖掘、全量组件的 OH 真机复现。

---

## 2. 总体架构

### 2.1 架构总览

```
┌────────────────────────────────────────────────────────────────────┐
│                     CLI 入口层（LangGraph 状态图即状态机）             │
│   全量扫描模式 │ commit 范围模式 │ 单仓库模式 │ 独立复现 │ 报告重生成    │
├────────────────────────────────────────────────────────────────────┤
│  Agent 编排层：Planner / Static / Dynamic / Context / PoC /          │
│  Verifier / Repair / Report（全部经由工具注册表，schema 校验）         │
├───────────────────────┬────────────────────────────────────────────┤
│  检测线 A（已知）       │  检测线 B（未知，主线）                      │
│  组件识别 + 版本清单    │  三层静态：tree-sitter 规则引擎（全量打底）   │
│  OSV/NVD CVE 匹配      │   → CSA/Clang 深析（高分组件）              │
│  补丁签名比对          │   → CodeQL 按需（污点路径）                  │
│  中间形态标记          │  动态补充：libFuzzer + Sanitizer（复用 harness）│
├───────────────────────┴────────────────────────────────────────────┤
│  多信号安全性研判 triage（核心创新）：                                │
│  攻击面可达性 / 数据可控性 / 执行证据 / 安全边界 × DoS 四判据          │
│  LLM(双模型交叉验证)供信号，确定性决策表出结论，全量留痕               │
├────────────────────────────────────────────────────────────────────┤
│  PoC 生命周期：生成(模板+LLM填充)→编译→运行→失败分类反馈→独立复现      │
│  主机侧沙箱（Docker+ASan/UBSan）→ 提交集 OH 复现（SDK/模拟器/设备）    │
├────────────────────────────────────────────────────────────────────┤
│  影响分析（分支 diff 矩阵）│ 修复建议（补丁验证闭环）│ 报告生成器       │
├────────────────────────────────────────────────────────────────────┤
│  基础设施：LLM 网关（GPT-6 主判 + Grok 交叉验证/灾备，签名缓存）       │
│  仓库管理 │ 对象存储+哈希证据库 │ SQLite 元数据 │ 任务并行调度         │
└────────────────────────────────────────────────────────────────────┘
```

### 2.2 LangGraph 工作流与门控

推荐节点顺序：

```
intake → plan → kmatch ∥ static_scan → triage → poc_generate
      → host_build → host_run → feedback(回边≤3)
      → independent_reproduce → [ohos_reproduce：仅提交集] → impact → report → human_review
```

门控（gates）：`static → host → independent → ohos`，全部通过才允许进入 Submission 层。所有循环受最大重试次数、超时、资源配额与输入变更范围限制。

WorkflowState：

```python
WorkflowState = {
    "task_id": str,
    "repo": {"url": str, "commit": str, "branch": str},
    "target": {"module": str, "build_profile": str, "ohos_version": str},
    "mode": "full|commit_range|single_repo|reproduce",   # 新增：commit 范围模式
    "findings": list,          # 四层发现（§3.2）
    "poc_candidates": list,
    "verification_runs": list,
    "evidence_refs": list,     # EvidenceBundle 索引
    "retry_count": int,
    "gates": {"static": bool, "host": bool, "independent": bool, "ohos": bool},
    "decision": "candidate|rejected|host_verified|verified|reproduced|submitted|discarded",
}
```

### 2.3 Agent 角色与工具注册表

| 角色               | 职责                                 | 可调工具（schema 化）                                                                          |
| ---------------- | ---------------------------------- | --------------------------------------------------------------------------------------- |
| Planner          | 读任务范围与约束，产出分析计划、工具组合、资源上限          | `plan_task`                                                                             |
| Static Analysis  | 归并规则引擎/CSA/CodeQL/Semgrep 发现       | `run_rule_engine` `run_clang_analysis` `run_codeql_query` `run_semgrep_rules`           |
| Dynamic Analysis | 准备 Sanitizer/libFuzzer 配置并执行受限动态测试 | `run_fuzzer`                                                                            |
| Context          | 检索调用链、数据流、提交历史、补丁、API 语义           | `query_callgraph` `query_git_history` `search_rules_kb`                                 |
| PoC              | 依据漏洞类型与触发契约生成最小 PoC、构建文件、运行参数      | `gen_poc`                                                                               |
| Verifier         | 只执行编译与运行，核对预定义判据，**不修改漏洞结论**       | `build_poc` `run_poc_host` `collect_artifacts`                                          |
| Repair           | 基于失败日志与允许代码范围生成受限修正候选              | `gen_poc(修复模式)`                                                                         |
| Report           | 将已验证事实转换为报告，禁止补写无证据字段              | `render_report`                                                                         |
| （系统级）            | 独立复现、OH 侧构建运行、组件/CVE 匹配            | `create_reproduction_job` `build_poc_ohos` `run_poc_ohos` `checkout_source` `match_cve` |

每个工具校验路径、参数、资源配额与网络策略；全部调用留痕（调用者、参数摘要、结果、时间）。

---

## 3. 数据模型

### 3.1 Alert（检测线输出 → 研判输入）

```json
{
  "alert_id": "AL-xxxx",
  "source": "rule_engine|csa|codeql|semgrep|fuzzer|cve_match|clone_match",
  "cwe_candidate": "CWE-190",
  "location": {"repo": "third_party/libupnp", "file": "...", "func": "...", "lines": [412, 435]},
  "code_snippet": "...",
  "taint_evidence": {"entry": "...", "sink": "...", "path": ["..."], "controlled": "full|len|ptr|none|unknown"},
  "context_facts": {"caller_chain": ["..."], "build_db": true}
}
```

### 3.2 四层发现模型（候选 → 提交的晋升链）

| 层级 | 含义 | 准入条件 | 允许动作 |
|---|---|---|---|
| L1 Candidate | 静态命中/动态崩溃/LLM 推测 | 任一检测线产出 | 内部流转，禁止对外 |
| L2 Verified | 至少一次隔离验证成功 | 可复现命令 + 产物哈希 + 崩溃/判据证据 + 研判通过 | 进入报告草稿、待独立复现 |
| L3 Reproduced | 独立任务干净环境重建重跑 | 新 EvidenceBundle + 与生成任务隔离 | 进入提交候选队列 |
| L4 Submission | 最终提交版本 | L3 + 双环境结论规则（§7.3）+ 人工审核 | 提交奖励计划 |

L1 层允许误报存在；误报消减发生在 triage 与 host_run 两道门。所有 discard 决定（含"不构成安全漏洞"的理由）写入《研判留痕报告》。

### 3.3 EvidenceBundle（不可变证据）

```json
{
  "run_id": "run-...",
  "task_id": "task-...",
  "stage": "host_run|independent_reproduce|ohos_run",
  "source": {"repo": "...", "commit": "...", "branch": "..."},
  "environment": {"image": "...", "compiler": "...", "sdk": "...", "device": null},
  "command": "...",
  "inputs": [{"path": "seed.bin", "sha256": "..."}],
  "artifacts": [{"path": "asan.log", "sha256": "..."}],
  "exit_code": 0,
  "duration_ms": 1234,
  "resource_usage": {"cpu_ms": 0, "peak_memory_bytes": 0},
  "verdict": "triggered|not_triggered|build_failed|environment_failed",
  "parent_run_id": null
}
```

存储：产物入对象存储/版本化目录（只追加），数据库仅存元数据与哈希。独立复现任务只能读取版本化 PoC 与任务元数据，不得读取生成任务的进程内存、临时目录或未提交状态。

### 3.4 VulnerabilityReport（对齐 OH 安全公告口径）

```json
{
  "vul_id": "OHVUL-2026-xxxx",
  "title": "third_party/xxx 整数溢出导致堆缓冲区溢出",
  "cwe": "CWE-190→CWE-122", "cve": null,
  "severity": {"cvss_vector": "...", "level": "High", "rationale": "..."},
  "description": "...",
  "source_location": {"repo": "...", "commit": "...", "file": "...", "func": "...", "lines": "...", "code": "..."},
  "trigger_conditions": "...",
  "attack_surface": "解析远端 SSDP 订阅报文（网络可达，攻击者信任域低于受害者）",
  "taint_path": ["recv(buf)", "len=ntohl(hdr)", "malloc(len)..."],
  "poc": {"host": {"path": "...", "cmd": "...", "env": "x86_64 Linux + ASan"},
           "ohos": null},
  "verification": {"finding_layer": "L3", "asan_report": "...", "crash_stack_top": ["..."],
                    "attribution": "crash_frame_in_target=true",
                    "independent_reproduced": true, "repro_times": 3},
  "affected": {"modules": ["..."], "branches": ["master", "OpenHarmony-5.0-Release"],
                "evidence": "各分支函数指纹快照哈希"},
  "triage": {"surface_reachability": "...", "controllability": "len",
              "dynamic_evidence": "...", "boundary": "app→system_service",
              "verdict_reasons": ["..."], "llm_cross_agreement": true},
  "fix": {"suggestion": "...", "patch": "diff --git ...", "patch_verified": true},
  "audit": {"discard_history": [], "retry_history": [], "human_review": "pending"}
}
```

---

## 4. 检测能力设计

### 4.1 检测线 A：已知漏洞匹配（kmatch）

1. **组件识别**：解析 `README`/`BUILD.gn`/版本头文件宏 + 目录名启发式，产出（组件名， 版本， 语言， 构建系统）清单；
2. **优先级排序**：third_party C/C++ 组件按"历史 CVE 密度 × 攻击面类型 × 代码规模"排队，高分先扫；
3. **CVE 匹配**：集成 OSV-Scanner（支持 vendored C/C++ 依赖识别）对 OSV.dev/NVD 查询；
4. **代码确认**：对每条候选 CVE 取上游修复 commit diff，定位漏洞函数，在目标版本做函数级指纹比对（规范化 token 哈希，VUDDY/V1SCAN 式），区分`确认存在 / 已修复 / 版本不可判`；
5. **中间形态标记**：上游已公开 CVE 但 OH 版本未处置的，标记为奖励计划优先候选（确定性高、有上游参考 PoC/补丁），同样进入 triage→PoC 流程补运行级证据；
6. commit 范围模式下，kmatch 限定为 diff 文件集所属组件。

### 4.2 检测线 B：未知漏洞候选生成（static_scan）——三层并行

| 层 | 工具 | 覆盖范围 | 依赖 | 定位 |
|---|---|---|---|---|
| 底层（全量打底） | 自研规则引擎（tree-sitter） | 全部 C/C++ 文件，无需构建数据库 | 无 | 快速全覆盖，首批规则：CWE-190 整数溢出喂长度参数、CWE-476 判空缺失、CWE-415/416 UAF、CWE-121/122/125/787 危险内存函数 |
| 中层（深析） | Clang AST/CFG/CSA + 自定义 checker | 高分组件（有 compile_commands） | OHOS GN 构建抽取或手工 Makefile | 路径敏感检查、OH API/权限边界/生命周期/危险内存操作的自定义检查器 |
| 顶层（精确污点） | CodeQL（可选插件） | 建库成功的组件 | CodeQL 数据库 | 过程间污点路径，source/sink 来自 §4.3 规则闭环；无 CodeQL 环境时工作流照常运行 |

- Semgrep CE 仅做危险 API 初筛与局部模式匹配，结果必须进入统一 Alert 格式，不承担跨函数分析；
- 动态补充：libFuzzer + Sanitizer（ASan/UBSan/MemorySanitizer/LeakSanitizer 按模块选择）针对高风险解析器、序列化、IPC、媒体与文件格式入口；**fuzz harness 与 PoC harness 合流生成（§6.1），动态发现保存 seed、变异参数、崩溃栈、报告、二进制哈希与最小化输入**；
- 两路结果统一归并 Alert，去重键 = (文件, 函数, CWE 类)。

### 4.3 LLM 污点规则自生成与缓存（团队前期工作迁移）

承接朱笑锋论文验证过的闭环（DeepSeek-Chat 实测检出率 95.24%、签名缓存命中 80%+；本作品成本不构成约束，主模型升级为 GPT-6），迁移到 C/C++：

- **触发**：规则引擎/CodeQL 遇到未建模库函数（自研封装、第三方库）；
- **输入**：仅函数签名 + 调用点上下文片段；
- **输出**：C/C++ 扩展语义污点规则 `{method, from, to}`，`from/to ∈ {ret, arg0..n, *argI 写穿, global, field, dst↔src 参数间传播, len 参数→指针}`；JSON schema 强校验，失败回退"不传播"；
- **Prompt 底稿**：张鑫棋论文附录 B（角色 + 10 类转移条件 + 格式规范 + few-shot + JSON 输出）翻译为 C/C++ 版 10 类传播条件（参数→返回值、src→dst、长度参数→指针、`*out` 写穿、全局变量、结构体字段、宏展开、回调上下文、别名、error path）；
- **缓存**：签名哈希 → 规则，SQLite 持久化；缓存定位是**性能与一致性**手段而非成本手段。

---

## 5. 多信号安全性研判（triage 节点定义）——核心创新

对每条 L1 Alert 计算四路信号，由**确定性决策表**融合出结论。本模块即赛题备注 3/4（排除功能性 bug 与普通 DoS）的可执行实现。

**信号 1：攻击面可达性（静态）**。OH 攻击面入口知识库：文件格式解析器、网络协议栈与守护进程（lwIP/DHCP/mDNS/SSDP）、samgr 注册的系统服务 IPC/Parcel 处理函数、HDF 驱动 ioctl、NAPI 绑定、hap 包/BMS 解析、init 配置解析。判定漏洞函数到任一入口的调用路径（正向 BFS 深度上限 + 反向 caller 闭包），输出 `reachable_from: [surface_type]`。

**信号 2：数据可控性（污点）**。档位 `full（值全可控）> len（长度/索引可控）> ptr > none`。来源：CodeQL 污点路径 / 规则引擎证据 / LLM 语义判定——后者复用张鑫棋 RAGSASTSieve 管线（上下文检索 → 按漏洞类型内嵌误报判定标准的 prompt → 结构化输出真伪+可控性）。**LLM 研判采用双模型交叉验证：GPT-6 主判 + Grok 复核；一致→采纳，不一致→从严（可控性取低档、真伪转执行验证裁决或人工复核队列）；双模型一致率全程记录。**

**信号 3：执行证据（动态）**。来自 §6 验证环节：ASan 报告分级（heap-overflow WRITE > READ > UAF > 野指针 > NULL-deref）；崩溃归因剥离 harness 帧后确认崩溃 PC 落在目标组件内方为有效。

**信号 4：安全边界跨越（OpenHarmony 特有）**。信任域模型 `app ↔ system service(samgr) ↔ kernel/HDF ↔ normal daemon`；判定漏洞所在进程信任域与可达入口的攻击者最低权限；**攻击者信任域低于受害者 = 边界跨越 = 危害升级**（普通 DoS 升为安全漏洞）。

**DoS 四判据（全部命中才保留 DoS 类，落实备注 4）**：

| # | 判据 | 通过标准 |
|---|---|---|
| D1 | 受害者边界关键 | 系统服务/内核/HDF 驱动/常驻守护进程 |
| D2 | 权限差 | 攻击者权限 < 受害者 |
| D3 | 影响持续性 | crash loop / watchdog 重启 / 启动失败，非自愈重启 |
| D4 | 放大效应 | 小输入代价 → 大资源消耗或大范围影响 |

**融合决策表**：

| CWE 类 | 可控性 | 边界 | 结论 |
|---|---|---|---|
| 内存破坏类 | ≥len | 任意（可达即报） | 进入 PoC 验证，通过后 L2 |
| NULL-deref / DoS | ≥len | 跨界且 D1–D4 全过 | 进入 PoC 验证 |
| NULL-deref / DoS | 任意 | 未跨界 | **discard（留痕：不构成安全漏洞）** |
| 任意 | none | — | **discard（留痕：健壮性问题）** |

LLM 结论永远不是最终裁决：模型筛候选、定档位，执行验证（真实崩溃）才是确认依据——这是整个低误报故事的底线。

---

## 6. PoC 生命周期闭环

### 6.1 生成（poc_generate）

- **触发契约**：Alert + 研判产物 → 输入形态（畸形文件/报文/参数）、攻击向量参数、触发条件（如 `a*b` 回绕）；
- **合成方式**：模板骨架（人工维护，保证可编译性）+ LLM 填充漏洞特异参数，避免全 LLM 生成的不可编译问题；
- **模板库按 CWE 分派**：CWE-190/122/787 畸形输入文件 + 独立加载器；CWE-416/415 调用桩序列（alloc→free→use）；CWE-476 传 NULL 桩（仅跨界保留者）；IPC/Parcel 类畸形报文模拟客户端（首批 1~2 个高频服务）；
- **harness 合流**：函数级 harness 同时作为 PoC 验证器与 libFuzz 入口（一份投入两处收益）；
- 产物带版本号与内容哈希；编译失败由 Repair 基于报错修复一轮，仍失败降级 `poc_wip`。

### 6.2 编译（host_build）

主机侧优先复用目标模块编译选项与 Sanitizer（`-fsanitize=address,undefined -fno-omit-frame-pointer -g`）。编译器版本、构建命令、依赖锁定、警告、产物哈希全部入证据。**编译失败只产生反馈，不得解释为漏洞不存在。**

### 6.3 运行（host_run）

沙箱：Docker，禁外网（或白名单）、非特权用户、只读源码挂载、临时工作目录、CPU/内存/时间限额、超时终止（默认 10s）。判据：稳定崩溃、Sanitizer 报告、越界访问、预定义安全状态变化。

### 6.4 反馈修正（feedback）

失败分类：编译失败 / 启动失败 / 输入未到达 / 触发条件不满足 / 环境不匹配 / 非安全崩溃 / 证据不足。Repair 只基于失败日志与允许代码范围生成下一版，**重试默认 ≤3 次**；超限标 `unconfirmed`（存疑单列，不静默丢弃——执行验证不对称：触发即真，未触发仅存疑）。

### 6.5 独立复现（independent_reproduce）

独立任务重新 checkout 固定提交、重建目标与 PoC、重跑并独立取证；使用独立工作目录/容器，只读版本化 PoC 与任务元数据。通过后 L2 → L3。

---

## 7. 双环境验证与结论规则

### 7.1 主机侧（所有 L2 的必经门）

用于快速确认数据流、Sanitizer 触发、输入最小化与 PoC 编译可行性；结果标签 `host_verified`，不能单独作为 OpenHarmony 影响结论。

### 7.2 OpenHarmony 环境复现（收缩范围：仅最终提交集）

使用指定版本 SDK/工具链/系统镜像/模拟器或专用测试设备，记录系统版本、设备标识、镜像哈希、权限配置、安装包哈希、日志采集方式与复现次数。涉及设备写入、权限变更或系统服务调用时必须使用专用设备/模拟器。**45 天周期内只对 L3 提交集（预计 3~8 个漏洞）执行，不做全量门禁。**

### 7.3 结论规则

| 主机侧 | OH 侧 | 结论 |
|---|---|---|
| ✅ | ✅ | 进入独立复现 → L3 → 可提交 |
| ✅ | ✗/未做 | `host_verified`，入待平台确认队列（报告如实标注） |
| ✗ | ✅ | 平台特定漏洞，补平台证据后单独评审 |
| 仅静态/LLM 证据 | — | 保持 `candidate`（L1），禁止提交 |

---

## 8. 影响分析与修复

- **分支影响**：拉取赛题指定 OH 分支（master、5.0/5.1-Release 等）目标文件，漏洞函数跨分支指纹比对：漏洞写法在→受影响；修复写法在→不受影响；输出分支矩阵 + 每分支快照哈希证据；
- **修复建议**：LLM 生成 diff 风格补丁（上下文 = 漏洞函数 + 研判结论 + 上游修复写法若有）；
- **补丁验证闭环**：应用补丁 → 重编译 → 重放 PoC → 崩溃消失 = `patch_verified: true`；时间不足降级为"建议补丁，未验证"。

---

## 9. 报告生成（report）

- 单漏洞报告：VulnerabilityReport（§3.4），字段对齐 OH 安全公告（攻击面、触发条件、危害、影响分支、补丁），奖励计划可直接走流程；
- 批次报告：《漏洞分析报告》（指定 commit 范围/版本）、《研判留痕报告》（discard 决定与理由）、《工具性能说明》；
- 渲染：Jinja2 → Markdown，可选导出 docx/pdf；
- Report Agent 禁止补写无证据字段，报告审计字段（discard/retry/human_review）随报告落库。

---

## 10. LLM 网关（基础设施）

- **GPT-6 主判**（规则生成、语义研判、PoC 填充、补丁生成），**Grok 交叉验证与灾备**（主模型不可用整体切换）；成本不构成约束，选型只看准确率与稳定性；
- 双模型交叉验证见 §5 信号 2；
- JSON schema 强约束输出 + 失败重试 5 次；
- 签名缓存：精确（prompt 哈希）→ 语义（函数签名哈希）→ 直调；
- 全局并发池 + 限速；全部调用留痕（请求/响应/耗时/token/模型名）。

---

## 11. 创新点与相关工作定位

### 11.1 团队前期工作（直接继承）

| 前期工作 | 继承内容 |
|---|---|
| 张鑫棋（2025，Java） | RAGSASTSieve 误报缓解管线（OWASP 上误报率 38-47%→3-15%）；三套提示词资产；LangChain/LangGraph Agent 骨架 |
| 朱笑锋（2026，ArkTS） | LLM 污点规则自生成闭环（事件钩子→签名投喂→JSON 校验→失败回退→签名缓存）；True/False 配对评测范式；DeepSeek 实测数据支撑缓存/校验设计 |

### 11.2 相关工作与差异化

| 方向 | 代表工作 | 本文差异化 |
|---|---|---|
| LLM×静态分析 | IRIS（ICLR'25，Java，开源）、LLift、LATTE、LLM4FPM、SemTaint | 方法论同源；本文落地 C/C++ 内存安全类 + OpenHarmony 生态，与研判/PoC/报告全链集成 |
| PoC 自动生成 | PAGENT（2026）、DrillAgent、POCGEN | 并行研究；本文面向 OH 组件 harness 与 Parcel/IPC 报文类 PoC，从扫描告警全自动进入，产出对齐奖励计划格式 |
| 崩溃研判 | AURORA、Pipe-Cleaner | **本文独有**：OH 安全边界建模 + DoS 四判据 + 可审计研判留痕 |
| 补丁驱动检测 | V1SCAN（USENIX'23）、VULTURE（NDSS'25）、VulGenie | 已知方法在 OH 语料的 LLM 化落地，定位为工程能力 |
| 组件 CVE 匹配 | OSV-Scanner、VUDDY、SPADE | 直接集成，无创新主张 |
| 全流程 LLM 挖洞 | OpenAnt（开源） | 最近整体对照；其通用仓库 vs 本文 OH 专用攻击面/边界知识 + CVE/CWE 报告链 + 真实提交 |

### 11.3 创新点表述

1. **基于 OpenHarmony 安全边界模型的多信号漏洞安全性研判**：把"功能性 bug / 普通 DoS / 安全漏洞"的区分形式化为四信号融合 + DoS 四判据的确定性决策表，每个结论可审计、可留痕，LLM 供信号而非下结论。（头牌，尚无直接同类）
2. **检测—合成—执行验证—独立复现的端到端受控闭环**：静态告警 → 触发契约 → 模板化 PoC → ASan 沙箱 → 崩溃归因回灌 → 独立复现取证，PoC 以运行级证据交付，全程证据哈希链。
3. **LLM 污点规则自生成在 C/C++ 上的扩展**（承接团队前期工作）：C/C++ 传播语义形式化扩展 + 签名缓存 + 校验回退 + 双模型交叉验证。

---

## 12. 实验与评价设计

- **指标体系**：候选数、真实漏洞数、误报率、漏报率、PoC 编译成功率、主机侧触发率、独立复现成功率、双模型一致率、平均/P95 验证耗时、峰值内存、LLM 调用次数/缓存命中率、重试率、每漏洞证据完整度；
- **误报自证基准**：仿前期工作 True/False 配对范式自建 C/C++ 基准（每场景配安全写法反例），覆盖首批 5 类 CWE；
- **消融**：triage 开/关、双模型交叉验证开/关对最终报告误报率的影响（核心卖点必须量化）；
- **真实数据**：3~5 个 third_party 组件全量扫描的告警/确认/误报数；奖励计划提交数与收录数（动态更新）；
- 普通功能 bug、无安全影响的 DoS、无法稳定复现的崩溃不计入最终漏洞数量（与赛题备注 6 对齐）。

---

## 13. 技术栈与工程结构

| 项 | 选型 |
|---|---|
| 语言 | Python（编排/规则/LLM/报告）+ C（harness 模板） |
| 解析 | tree-sitter（C/C++）、ctags（调用闭包） |
| 静态深析 | Clang/CSA 自定义 checker（高分组件）、CodeQL（按需） |
| 动态 | libFuzzer + ASan/UBSan/MemorySanitizer/LeakSanitizer |
| 编排 | LangGraph（状态图即 FSM） |
| LLM | GPT-6（主判）+ Grok（交叉验证/灾备）；JSON schema 约束输出 |
| 沙箱 | Docker（主机侧）；OH SDK/模拟器/专用设备（提交集） |
| 存储 | SQLite（元数据）+ 版本化目录/对象存储（证据，只追加+哈希） |
| SCA | OSV-Scanner 集成 |
| UI | CLI 优先；时间富余加 Streamlit 演示页 |

```
ohvul/
├── cli.py                  # full / commit-range / repo / reproduce / retrace
├── graph/                  # LangGraph 状态图、门控、重试策略
├── agents/                 # 8 角色 + 工具注册表（schema）
├── sync/ identify/         # 仓库同步、组件识别与优先级
├── detect/
│   ├── known/              # OSV 匹配 + 补丁指纹比对
│   ├── rules/              # tree-sitter 规则插件注册表
│   ├── clang/              # compile_commands 抽取 + CSA checker
│   └── codeql/             # 查询集与建库
├── triage/                 # 四信号、DoS 判据、融合决策表、留痕
├── llm/                    # 网关：双模型/缓存/重试/校验/审计
├── poc/                    # 触发契约、模板库、harness 合流、LLM 填充
├── verify/                 # 主机构建沙箱、执行器、崩溃归因
├── reproduce/              # 独立复现队列 + OH 侧构建运行
├── impact/ fix/            # 分支比对、补丁生成与验证
├── report/                 # 模板与渲染
├── evidence/               # EvidenceBundle 存取与哈希链
└── store/                  # SQLite schema 与迁移
```

---

## 14. 45 天实施计划（9/9 → 10/22）

| 周 | 对应阶段 | 里程碑 | 验收标准 |
|---|---|---|---|
| W1（~9/15） | 阶段一闭环骨架 | LangGraph 状态图 + 工具注册表 + 数据模型 + 仓库同步/组件识别 + OSV 匹配 | 第一份自动生成的已知漏洞报告（含代码确认证据） |
| W2（~9/21） | 阶段二分析能力 | 规则引擎三类规则 + LLM 研判管线 + 双模型交叉验证；3~5 组件跑通 | 候选→研判全流程出数；**第一批疑似漏洞提交奖励计划** |
| W3（~9/28） | 阶段二+四 | PoC 模板库 + 主机沙箱执行 + 崩溃归因 + 独立复现队列 | ≥1 个漏洞达 L3（ASan 崩溃 + 独立复现证据） |
| W4（~10/5，含国庆，有效时间打折） | 阶段四 | 四信号融合定稿 + DoS 判据 + commit 范围模式 + 补丁建议 | 研判消融数据可测；discard 留痕可展示 |
| W5（~10/11） | 阶段三（收缩版） | 提交集 OH 环境复现（3~8 个漏洞）+ 分支影响 + 性能数据 | 完整《漏洞分析报告》+《性能说明》草稿 |
| W6（~10/18） | 阶段五比赛交付 | 技术说明书、使用说明书、DEMO 视频、工具打包 | 五项交付件齐备 |
| 缓冲（10/19–22） | — | 提交与修补 | — |

持续动作：漏洞发现即提交奖励计划（W3 前交出第一批）；文档从 W3 起边做边写；每周末跑一次全链冒烟。

---

## 15. 风险与降级预案

| 风险 | 影响 | 降级预案 |
|---|---|---|
| OHOS 构建抽取 compile_commands 受阻 | 中/顶层静态分析卡死 | tree-sitter 规则引擎独立承担全量扫描（本就无构建依赖）；纯 C 组件手工 Makefile |
| PoC 合成通过率低 | L2/L3 数量不足 | 收缩到 3 类 CWE × 少数组件做深；中间形态 CVE（上游有参考 PoC）兜底 |
| LLM 研判不稳定 | 误报上升 | 双模型交叉验证从严；执行证据门槛；受控 JSON 输出；关键报告人工复核 |
| 外部 LLM API 限速/不可用 | 流水线阻塞 | Grok 灾备整体切换；签名缓存削峰；批任务排队重试 |
| 主机与 OH 环境不一致 | 结论可靠性存疑 | 双环境结论规则（§7.3）；host_verified 如实标注，不冒充平台结论 |
| OH 真机/模拟器环节不顺 | 提交集复现延期 | 复现收缩到 1~2 个代表性漏洞；其余按 host_verified 提交并注明 |
| 奖励计划评审结果赶不上 | 新漏洞加分落空 | 中间形态 CVE 兜底（有 CVE 编号确定性）；留痕报告自证价值 |
| 国庆假期损耗 | W4 进度 | W4 只排可暂停软任务，硬里程碑前移 W3/W5 |
| 证据被临时文件污染 | 审计可信度 | 产物版本化+哈希，独立复现干净目录（§3.3） |
| 工具链版本漂移 | 不可复现 | 固定容器镜像、编译器、SDK、规则包、查询包版本 |
| 单人关键路径 | 人力风险 | 构建沙箱与 LLM 网关两人分头持有；文档不占主力开发 |

---

## 16. 交付件映射

| 赛题交付件 | 本方案对应 |
|---|---|
| 1 工具源代码 | ohvul 仓库（§13 结构） |
| 2 技术说明书 | 本文档 §2–§12（正式稿待排版） |
| 3 使用说明书 + DEMO 视频 | CLI 手册（W6）；视频脚本围绕 commit 范围模式 + 一个 L3 漏洞全流程（含独立复现） |
| 4 漏洞分析报告 | §9 批次报告（指定 commit 范围/版本） |
| 5 工具性能说明 | §12 指标体系实测数据 |

---

## 附：待办与占位

- [ ] 攻击面入口知识库初版（IPC 服务清单、解析器组件清单）——W1-W2 人工沉淀
- [ ] C/C++ 污点传播 10 类条件 prompt 翻译稿（张论文附录 B 底稿）
- [ ] 首批 3~5 个目标组件清单（候选：第三方网络/多媒体/解析器类，W1 定）
- [ ] DoS 判据 D3（影响持续性）自动化取数方式（服务重启机制，可能半自动）
- [ ] OH 模拟器/设备资源确认（W4 前落实，否则 W5 预案降级）
- [ ] 引用文献格式整理（IRIS/PAGENT/OpenAnt/V1SCAN/VULTURE/AURORA/OSV + 两篇前期论文）
- [ ] 自定义 CSA checker 清单（对齐首批规则集，W2 评估是否顺延至 W4）

# 多信号安全性研判（triage）设计稿 v0.1

> 状态：**设计稿，未实现**。本文供主线裁定模块边界后立项；按协作协议，
> 候选/确认状态语义与 FSM 迁移归主线，本模块只产出"带证据的建议"。

## 0. 待主线裁定的事项（先读这节）

| # | 事项 | 本稿的提议 | 需要主线的决定 |
|---|---|---|---|
| A1 | discard 建议的效力 | triage 产出 `discard_non_security` **建议**及理由码，是否终止/搁置某条 finding 由主线状态机决定 | discard 是终态还是可恢复的搁置态 |
| A2 | LLM 供信号的入口 | 不改 `llm_adapter.py`；新建独立的 `triage_signals_llm` 调用入口（同样 review-only、白名单、HTTPS-only）还是扩展原 adapter | 入口归属与模型白名单管理 |
| A3 | 攻击面知识库的维护权 | `surface_kb` 与 engine profile 同构（本地 JSON + 来源摘要绑定），初版由 GLM 侧起草、主线审订 | 归属仓库路径与 schema 命名 |
| A4 | TriageAssessment 是否进 checkpoint 主链 | 本稿只定义 JSON schema + EvidenceBundle 绑定，不接触 checkpoint/verification_link | 接入时机与门控位置 |
| A5 | 信号 3（执行证据）的取数口 | 预留槽位，读 harness 记录；当前全部为 `absent`，不产生任何晋升建议 | 与 Phase 4/5 执行层的对接方式 |

若 A1–A5 均按提议接受，本模块可在不改任何禁改文件的前提下落地。

## 1. 问题定义

赛题评分明确：误报负向扣分；备注 3/4 要求不把"普通功能性 bug、非安全健壮性问题、
无实际危害的 DoS"当作安全漏洞。这要求在"静态候选"与"进入验证/报告"之间有一道
**可审计的安全性研判**：每条候选要么获得"构成安全问题的证据支撑"，要么留下
"不构成安全问题"的结构化理由。现状：FSM 有 `triage` 状态，但没有任何实现定义
它做什么——本设计就是往这个空槽里填的内容。

## 2. 总体设计

```
Alert（来自 rule/engine/kmatch）
   │
   ├─ 信号1 攻击面可达性 ← surface_kb（路径/入口模式 → 信任域）
   ├─ 信号2 数据可控性   ← 规则证据 + engine 污点信息 + LLM 供信号（建议档位）
   ├─ 信号3 执行证据     ← harness 记录（当前恒 absent，预留）
   ├─ 信号4 边界跨越     ← surface_kb 信任域 × 组件域映射
   │
   ▼
确定性决策表（纯函数，无 LLM 参与）
   │
   ├─ advance_to_verification（建议进入验证）
   ├─ hold_for_human（存疑，人工队列）
   └─ discard_non_security（建议不构成安全问题，附理由码）
   │
   ▼
TriageAssessment（schema 0.1 + EvidenceBundle 绑定，全量留痕）
```

三条铁律：
1. **LLM 供信号，不裁决**——模型只对信号 2 给出建议档位，最终档位由确定性规则
   收敛（与现有 `final_verdict: undetermined` 哲学一致）；
2. **决策表是纯函数**——同样的信号输入永远得到同样的建议，可单测、可复现；
3. **discard 也要留痕**——每条"不报"的决定携带理由码和证据引用，构成
   《研判留痕报告》的素材，是"低误报"的自证材料。

## 3. 四信号定义

### 信号 1：攻击面可达性（surface_reachability）

**回答**：漏洞所在代码是否从不可信输入入口可达。

- 取数（P0 可实现）：对 finding 的 `location.file` 匹配 `surface_kb` 的
  路径/组件模式，输出 `reachable_from: [surface_id...]`；
- 取数（P1）：engine profile 已有 `source_files` 与调用信息，做函数级
  反向调用闭包（ctags/clang callgraph），把可达性从文件级提升到函数级；
- 档位：`remote | local_app | local_privileged | internal | unknown`。

### 信号 2：数据可控性（controllability）

**回答**：触发越界/崩溃的那个值，攻击者可控到什么程度。

- 取数（P0）：规则证据里的 `rule_detail`（如 "size expression 'w*h' uses
  unchecked operand(s)"）→ 操作数是否出现在入口参数中；
- 取数（P1）：clang/CodeQL 引擎的污点输出（若携带 source→sink 路径）；
- 取数（P1，LLM 供信号）：结构化输入（函数 + 告警 + 入口签名），输出
  建议档位 + 理由；**双模型交叉验证**：两模型一致 → 采纳建议档位；
  不一致 → 收敛到更保守档位并标记 `llm_disagreement`；
- 档位：`full（值可控）> len（长度/索引可控）> ptr（仅指针间接）> none > unknown`。

### 信号 3：执行证据（execution_evidence）

**回答**：是否已有运行级证据及其性质。

- 取数：读 harness/验证记录（A5 对接后）；当前恒为 `absent`；
- 档位（对接后）：`asan_write > asan_read > uaf > wild_ptr > null_deref >
  assert > none`；崩溃点归属校验（栈帧落在目标组件内）由执行层负责，
  triage 只消费结论。

### 信号 4：安全边界跨越（boundary_crossing）

**回答**：攻击者信任域是否低于受害者信任域（OpenHarmony 特有）。

- 信任域模型：`app < system_service(samgr) < kernel/HDF`，
  `normal_daemon` 介于 app 与 system_service 之间按 surface_kb 标注；
- 取数：信号 1 的入口信任域（攻击者侧）× finding 所属组件的信任域
  （surface_kb 组件映射）；
- 输出：`crossed: bool` + `attacker_domain` + `victim_domain`；
- 跨界 = 普通崩溃升格为安全问题（如低权应用打死系统服务）。

## 4. DoS 四判据（备注 4 的可执行化）

仅当候选为 DoS/空指针类时评估；**四条全过才建议保留**：

| # | 判据 | 取数（P0） |
|---|---|---|
| D1 | 受害者是边界关键组件 | surface_kb 中组件域 ∈ {system_service, kernel/HDF, 常驻 daemon} |
| D2 | 权限差（攻击者 < 受害者） | 信号 4 输出 crossed |
| D3 | 影响持续性（crash loop / watchdog / 启动失败） | P0 人工标注字段；P1 半自动（组件重启配置） |
| D4 | 放大效应（小代价大消耗/大范围） | P0 人工标注字段 |

D3/D4 在 P0 阶段取 `unknown` 时按"未证实"处理（不满足），宁可搁置不误报。

## 5. 决策表（纯函数）

输入：`cwe_class ∈ {memory_corruption, dos_null, other}`、信号 1–4 档位、DoS 判据。

| cwe_class | controllability | boundary | Dos 判据 | 建议动作 | 理由码 |
|---|---|---|---|---|---|
| memory_corruption | ≥ len | 任意 | — | advance_to_verification | MC-CTRL |
| memory_corruption | unknown/none | 任意 | — | hold_for_human | MC-UNCTRL |
| dos_null | ≥ len | crossed | D1–D4 全过 | advance_to_verification | DOS-CROSS |
| dos_null | 任意 | 未跨界 | — | discard_non_security | DOS-INAPP |
| dos_null | crossed | 任一未过 | — | hold_for_human | DOS-UNPROVEN |
| other | none | — | — | discard_non_security | ROBUST-ONLY |
| other | unknown | — | — | hold_for_human | NEED-CONTEXT |
| 任意 | unknown 且信号 1 = internal | — | — | discard_non_security | NO-SURFACE |

理由码是稳定枚举，进留痕报告；表中未覆盖的组合按最保守动作处理并记 `FALLBACK`。

## 6. 数据契约

```json
{
  "schema": "triage-assessment-0.1",
  "alert_ref": "<evidence_id 或主链 finding 键>",
  "cwe_class": "memory_corruption | dos_null | other",
  "signals": {
    "surface_reachability": {"level": "remote", "reachable_from": ["surface:ipc_lite"]},
    "controllability": {"level": "len", "basis": "rule_detail+llm",
                         "llm": {"models": ["a","b"], "agree": true}},
    "execution_evidence": {"level": "absent"},
    "boundary_crossing": {"crossed": true, "attacker_domain": "app",
                           "victim_domain": "system_service"}
  },
  "dos_checks": {"d1": true, "d2": true, "d3": "unknown", "d4": "unknown"},
  "recommendation": "advance_to_verification | hold_for_human | discard_non_security",
  "reason_code": "DOS-CROSS",
  "disclaimer": "Advisory assessment; state transitions remain on the mainline."
}
```

- 每份 assessment 经 `make_bundle(stage="triage", ...)` 绑定 EvidenceBundle，
  输入信号快照进 evidence（可复现）；
- 决策表版本号随 schema 走，assessment 记录表版本。

## 7. 攻击面知识库（surface_kb）契约

与 engine profile 同构（本地、版本化、来源摘要绑定）：

```json
{
  "schema": "surface-kb-0.1",
  "entries": [
    {"id": "ipc_lite", "trust_domain": "system_service",
     "path_patterns": ["foundation/communication/ipc/**"],
     "entry_kinds": ["parcel_callback", "ioctl"],
     "component_domains": {"foundation/communication/ipc": "system_service"},
     "evidence_source": "openharmony docs + profile provenance"}
  ]
}
```

初版条目建议：IPC/Parcel 处理、HDF 驱动 ioctl、媒体/图片/字体/压缩等解析器、
网络守护（lwIP/DHCP/mDNS）、BMS/hap 解析、init 配置解析。

## 8. LLM 供信号边界（不裁决的实现保证）

- 调用入口独立（A2），输出为结构化 JSON：`{level, rationale}`；
- 双模型一致 → 采纳；不一致 → 收敛保守档 + `llm_disagreement` 标记；
- LLM 输出**永远不出现在 recommendation 字段的产生路径上**——决策表只读
  确定性信号档位；
- 全部调用留痕（模型、耗时、一致率），供性能报告与消融实验。

## 9. 与现有模块的接缝

| 现有模块 | 关系 |
|---|---|
| FSM `triage` 状态 | 主线决定何时进入；本模块是状态内执行体的候选实现 |
| rule/engine findings | 输入（alert_ref + rule_detail） |
| `knowledge_base` | kmatch 命中的 CVE 候选同样过研判（信号 1/4 判平台相关性） |
| harness 记录 | 信号 3 的未来取数口（A5） |
| benchmark 设施 | 配对反例基准复用同一 runner 模式 |

## 10. 本模块明确不碰的领地（协议重申）

`workflow/`、`domain/`、`verification_link.py`、`verify.py`、checkpoint/事务主链、
候选/确认状态语义、安全边界门控（isolation_contract）。落地时全部为新增文件：
`ohvul/triage_signals.py`、`ohvul/surface_kb.py`、`docs/design/surface_kb.json`、
对应测试。

## 11. 测试与基准计划

- 决策表纯函数：全组合真值表单测（含 FALLBACK）；
- 配对反例（沿用 True/False 范式）：
  - 正例：系统服务 IPC 回调里的可控长度溢出 → advance（MC-CTRL）；
  - 正例：低权入口打死 samgr 服务且 D1–D4 过 → advance（DOS-CROSS）；
  - 反例：应用自身进程内 NULL 解引用 → discard（DOS-INAPP）；
  - 反例：internal 路径无攻击面 → discard（NO-SURFACE）；
  - 存疑：D3/D4 unknown 的跨界 DoS → hold（DOS-UNPROVEN）；
- 消融（交付材料用）：研判开/关对最终上报集合的假阳性差值。

## 12. 分阶段落地

- **P0（纯规则，无 LLM）**：surface_kb 初版 + 信号 1/4 + 决策表 + 留痕 + 测试；
- **P1**：信号 2 的 LLM 供信号（双模型）+ 函数级可达性（callgraph）；
- **P2**：信号 3 对接执行层，D3/D4 半自动化。

P0 不依赖任何待裁定的 A2/A5，可在裁定 A1/A3/A4 后立即开工。

## 13. 开放问题

1. `alert_ref` 用 evidence_id 还是主链 finding 主键？（建议 evidence_id，已全局唯一）
2. surface_kb 条目的证据来源标准——是否要求逐条附 openharmony 仓库/文档引用？
3. 研判留痕报告是独立交付物还是并入现有 report 体系？

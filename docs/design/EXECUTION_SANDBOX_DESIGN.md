# 执行沙箱设计稿（Isolated Execution Sandbox）v0.1

> 状态：**设计稿，未实现**。前置条件：`EXECUTION_AUTHORIZATION.md` 完成双人签署并合入。
> 本设计是授权书的工程化蓝图；实现归主线，GLM 侧可按协议承担模板/反例/测试部分。

## 0. 待主线裁定的事项

| # | 事项 | 本稿提议 | 说明 |
|---|---|---|---|
| S1 | 执行层的模块归属 | 新增 `ohvul/sandbox/` 独立包，不改 `isolation_contract`（合成路径原样并存） | 合成 harness（现状）与真实执行 harness 是两条并行通道 |
| S2 | 执行记录的 schema 载体 | 新 `execution-record-0.1`，独立于 `harness_record`（后者保持 undetermined 语义） | 真实执行可以产出 `triggered`，语义不同不该复用 |
| S3 | 与 FSM 的接缝 | `local_verification` 状态内新增执行任务引用；迁移门控仍走主线 `verification_gate` | 不新增状态，不加迁移边 |
| S4 | 首个目标组件 | cameraApp（已有 verified profile、3 文件、来源校验链） | 最小闭环路径 |
| S5 | PoC harness 的入库门槛 | 模板骨架人工维护 + LLM 填充产物必须人工审查后入库才可执行（授权书 §2 已定） | 需要主线确认审查人 |

## 1. 目标与问题定义

把静态候选变成运行级证据：**编译 → 运行 → 崩溃归因 → 证据链 → 独立复现**。
产出物是"该候选在隔离环境中可（不）被触发"的可审计记录；**执行结果永远是证据，
不是漏洞确认**——确认仍由人工审核（`human_review`）完成，与全项目语义一致。

不解决的问题：exploit 开发（只到"触发崩溃/断言"）、跨进程攻击链、真实设备验证
（后者进 OH 环境复现层，见 §8）。

## 2. 总体架构

```
静态候选（review_queue 组）
   │  ①触发契约构造（候选 + 语义/区间证据 → 输入形态与目标函数）
   ▼
②PoC harness（模板骨架 + LLM 填充 → 人工审查入库；未入库不可执行）
   │
   ▼
③执行任务（execution-task-0.1：harness + 源码 profile + 镜像登记号 + 资源限额）
   │
   ▼
④沙箱执行器（授权门 → 容器起 → 只读挂载源码 → 构建(ASan/UBSan) → 运行 → 采集）
   │
   ├─ ⑤崩溃归因（栈帧过滤 → 崩溃点归属判定 → sanitizer 分类）
   ▼
⑥执行记录（execution-record-0.1 → EvidenceBundle 绑定，只追加存储）
   │
   ├─ 未触发/构建失败 → ⑦失败分类 → 修复回路（≤3 次，修复须走审查入库）
   └─ triggered → ⑧独立复现任务（新容器、新 checkout、仅读版本化任务元数据）
                    → ⑨补丁验证（应用补丁 → 重建 → 重放 → 崩溃消失）
```

## 3. 授权门（硬门禁）

执行器入口第一件事是校验授权状态，任何一步失败即拒绝且留痕：

1. `EXECUTION_AUTHORIZATION.md` 双签署行完整（解析 §8 表格）；
2. 源码根目录在附录 A 登记表内（路径精确匹配登记号）；
3. 镜像/工具链在附录 B 登记表内；
4. harness 文件在仓库内且经审查入库（commit 存在于 master 或经批准的分支）。

四项任一不满足 → `execution_refused` 记录（含原因码），不发容器。

## 4. 沙箱环境契约

| 项 | 契约 |
|---|---|
| 隔离 | Docker 容器（`--rm`，一次性）；无 Docker 时可用专用 WSL 实例 + 快照恢复 |
| 源码 | 只读挂载授权根目录；容器内构建产物落独立工作卷，不回写源码树 |
| 网络 | 默认 `--network none`；任务计划显式声明回环时仅 `--network internal` |
| 资源 | `--memory`、`--cpus`、运行超时 ≤60s、输出字节上限（对齐授权书 §3） |
| 镜像 | 附录 B 登记号唯一可用；镜像 digest 固定，`docker image inspect` 指纹入记录 |
| 工具链 | 镜像内 clang/llvm 与附录 B 一致；`clang --version` 输出哈希入记录 |

## 5. PoC harness 契约

- **模板骨架**：按候选族分模板（整数溢出喂长度、UAF 序列、空指针桩、
  越界拷贝输入），骨架保证可编译性与资源边界（输入上限、无外联）；
- **LLM 填充**：触发契约（目标函数签名、区间证据、约束）注入模板参数；
  产物走 PR 人工审查入库（授权书 §2/§6）；
- **manifest**：每个 harness 附 `poc-manifest.json`（目标组件、源文件、
  profile 登记号、期望观测点），执行器据此做归因校验。

## 6. 执行记录与崩溃归因

`execution-record-0.1` 最小字段（兼容 EvidenceBundle 绑定与
`verification_link` 的摘要-关联模式）：

```json
{
  "record_id": "EX-<sha256>",
  "task_id": "...", "parent_run_id": null,
  "authorization": {"doc_sha256": "...", "registry_a": "A-1", "registry_b": "B-1"},
  "source": {"root_registry": "A-1", "commit": "...", "snapshot_sha256": "..."},
  "harness": {"repo_path": "...", "commit": "...", "manifest_sha256": "..."},
  "environment": {"image_digest": "...", "compiler_sha256": "..."},
  "command": "...", "exit_code": null, "duration_ms": 0,
  "verdict": "triggered|not_triggered|build_failed|timeout|non_target_crash|environment_failed|execution_refused",
  "sanitizer": {"kind": "ASan|UBSan|none", "report_sha256": null},
  "attribution": {"crash_in_target": null, "target_frames": [], "filtered_frames": []},
  "artifacts": [{"name": "...", "sha256": "..."}]
}
```

**归因规则**（`triggered` 的必要条件，全部机器判定）：

1. sanitizer 报告存在且可解析；
2. 崩溃帧序列过滤 harness 帧后，**崩溃 PC 所在帧属于目标组件源文件**
   （对照 `poc-manifest` 与 profile 的 `source_files`）；
3. 崩溃类别登记（heap-buffer-overflow WRITE/READ、UAF、stack-overflow、
   null-deref、assert、UBSan 类别）。

不满足 2 的崩溃 → `non_target_crash`（harness 自身缺陷），进修复回路。

## 7. 失败分类与修复回路

| verdict | 处置 |
|---|---|
| build_failed | 编译日志入记录；harness 修复走审查入库，预算 ≤3 次 |
| timeout / environment_failed | 记录资源指纹；调参重试 ≤2 次，超出标 `unconfirmed` |
| not_triggered | **不是漏洞不存在的证明**（授权书 §1 语义）；候选保持原状态 |
| non_target_crash | harness 缺陷，修复回路 |
| triggered | 进独立复现；两次独立 `triggered` 才允许进入报告草稿的人工审核 |

修复回路绝不自动执行未入库代码——每次修复都是新 commit + 审查。

## 8. 分层验证与 OH 环境（远期）

本沙箱是 **host 侧**（x86_64 Linux 容器）。`triggered` 的候选若需平台结论，
进远期 OH 复现层（QEMU/真机，对齐 v2 方案 §7：仅提交集、双环境结论规则）。
host 侧证据的边界在报告里如实标注。

## 9. 与现有模块的接缝

| 模块 | 关系 |
|---|---|
| isolation_contract | 并存不互改；合成路径继续产出 undetermined |
| engine_profile / component_batch | 提供源码 pin 与来源校验（复用，不改） |
| review_queue | 候选组即执行任务的输入源 |
| EvidenceBundle / verify | 记录经 `make_bundle` 绑定；`validate_result` 兼容扩展 |
| verification_gate / FSM | 执行任务挂在 `local_verification` 内，门控语义归主线 |
| verification_link | 独立复现与补丁验证的关联复用同一摘要-绑定模式 |
| knowledge_base / triage（PR #6） | `triggered` + 归因分类是研判信号 3 的取数口（A5） |

## 10. 测试计划

- 授权门：四项缺失各拒一次（合成授权文档夹具）；
- 归因：崩溃在 harness/在目标/栈被过滤三类合成栈夹具；
- 记录：schema 校验、哈希链、只追加存储拒绝覆盖；
- 端到端：在合成"漏洞组件"（仓库内 fixture，非 OH 源码）上走通
  构建→触发→归因→独立复现→补丁验证全链，全程不触碰授权根目录外的代码。

## 11. 分阶段落地

- **P0（授权签署后 ~3 天）**：cameraApp 上**手工 PoC** 一次全链走通
  （harness 手写、执行器脚本级、记录手工核对）——先拿"≥1 个带运行证据的
  候选"这个里程碑，再谈自动化；
- **P1（+1 周）**：执行器模块化 + 记录/归因自动化 + 测试；
- **P2（+1 周）**：harness 模板库 + 修复回路 + 补丁验证闭环 + 与 FSM 接线。

## 12. 风险

| 风险 | 缓解 |
|---|---|
| harness 触发的是 fixture 缺陷而非目标缺陷 | 归因规则 2 强制崩溃点在目标源文件 |
| 组件在容器内构建失败（GN 依赖） | P0 选 cameraApp 纯 C++ 三文件 + 手工 Makefile；profile 已有 include/defines |
| 误把 not_triggered 当阴性结论 | 语义已写死：not_triggered ≠ 不存在（§7） |
| 授权被撤销后残留任务 | 执行器每次起任务重验授权门（§3），撤销即时生效 |

# FSM 检查点契约

当前是本地扫描编排原型。CLI 记录 intake，扫描及元数据读取成功后停在 static_scan；捕获到读写或数据解析错误则记录 blocked。其他生命周期状态仅在核心库声明，尚未有对应执行器。

## 保存与校验

```powershell
python -m ohvul.cli C:\path\to\source --output result.json --checkpoint checkpoint.json --task-id audit-001
python -m ohvul.verify result.json --checkpoint checkpoint.json
```

检查点保存 task_id、state、retry_count、last_error、result_sha256。写出结果后计算其实际 UTF-8 字节 SHA-256，存入检查点。结果内部 workflow 不包含自身摘要，避免递归哈希。只输出 stdout 时不生成可绑定结果摘要。

校验只读取显式提供的两个文件，不根据检查点执行命令或自动打开路径。先检查检查点为 static_scan、有摘要且文件一致，再核对任务 ID、状态和证据结构。返回码 0 表示上述校验通过，1 表示校验失败，不代表漏洞成立或平台受影响。

结果和检查点不能使用相同解析路径；默认拒绝覆盖，--force 可替换。旧检查点没有摘要时仍能读取，但绑定校验拒绝，不能假定它对应某个现存结果。

## 恢复限制

尚未实现自动恢复执行和多文件事务；重试预算及严格 schema 已实现 和两个文件的原子事务。blocked 核心迁移目前也未限制回到原阶段，因此不能用于无人值守恢复。断电或进程终止后两个文件可能不一致，需要先校验。

哈希和检查点不带签名；同步修改两者不能被此机制防止。写入输入目录、硬链接和 --force 风险尚待修复。

## 验证记录

18 项测试通过。新增：修改结果字节后校验失败；损坏元数据库产生 blocked、带错误原因、无结果摘要且不输出结果。均为临时合成输入，未执行目标代码。

## 显式恢复命令

```powershell
python -m ohvul.recover checkpoint.json --target intake
```

命令只改变检查点状态并输出 RECOVERY_READY，不运行扫描或其他外部操作。恢复后必须重新显式运行 `ohvul.cli`；旧结果摘要已清除，不能直接当作新阶段证据。

## 检查点格式

检查点版本固定为 1，字段集合为 checkpoint_version、task_id、state、retry_count、last_error、result_sha256。未知字段或不合法类型拒绝加载。

## 恢复后关联

恢复后必须显式使用原 task_id 重跑：`python -m ohvul.cli SOURCE --task-id TASK --checkpoint CHECKPOINT --output RESULT --force`。CLI 结果和检查点会重新绑定同一任务的新摘要；不继承旧结果摘要。

## 输入快照

CLI 对扫描目录普通文件生成确定性 source_snapshot_sha256，并将其放入结果 workflow 和检查点。符号链接跳过。恢复后应由人工比较新旧摘要；当前不会自动阻止不同源码重跑，完整快照门禁尚未实现。

## 快照恢复门禁

当 checkpoint 已存在且使用 `--force` 重跑时，CLI 会加载并检查原 task_id、非 blocked 状态和 source_snapshot_sha256。源码变化会拒绝；必须显式重新创建任务或人工决定如何处理。

检查点和结果都使用临时文件、fsync、replace 发布；检查点拒绝符号链接路径。硬链接、目录替换竞争和检查点/结果多文件事务仍未解决。

## 事务日志核心

`AuditJournal` 追加 begin/result/checkpoint/commit/abort 事件并 fsync，可识别最后一次操作是否完整提交。当前仅作为核心库测试，尚未接入 CLI；因此不能宣称已有多文件事务。

## CLI 日志

使用 `--journal JOURNAL` 后，CLI 记录 `begin → result → checkpoint → commit`；捕获错误只记录 `abort`，不会追加 commit。`committed` 只表示本地文件和检查点写入流程完成，不表示漏洞成立。日志可选，当前未实现崩溃后自动重放。

## 日志一致性

`validate_commit(journal, task_id, result, checkpoint)` 要求最后事件为 committed，并复用结果/检查点校验。它只证明本地记录链一致，不证明漏洞、安全影响或来源可信。

## 中断检查

使用 `python -m ohvul.journal_status JOURNAL` 查看 incomplete/aborted 任务。命令只读，明确要求人工检查并重新显式运行，不执行日志中的命令或路径。

`validate_commit` 还会核对日志 result_sha256、checkpoint 状态和 source_snapshot_sha256；日志状态为 aborted/incomplete 时拒绝。

## 联合状态报告

```powershell
python -m ohvul.journal_status journal.log --task-id audit-001 --result result.json --checkpoint checkpoint.json
```

`CONSISTENT` 仅表示日志、检查点、结果的本地摘要和证据结构一致；`INCONSISTENT` 需要人工检查。命令只读，不执行恢复。

JSON 模式示例：`python -m ohvul.journal_status journal.log --task-id audit-001 --result result.json --checkpoint checkpoint.json --json`。该输出是机器可读的状态报告，不是漏洞判定。

## 报告边界

`ohvul.report` 的 0.1 schema 只生成候选审计报告，包含证据引用和 workflow，不产生漏洞确认结论。任何后续确认必须来自独立验证和人工审核，不能由报告生成器推断。

CLI 的 `--report-output` 生成独立候选报告；报告生成不会推进 FSM、不会生成确认漏洞结论，也不会自动提交外部系统。

报告 schema 0.2 增加 scan_result_sha256；生成器和校验器可确认报告对应的扫描结果。该摘要绑定不改变 candidate_only 安全边界。

报告可用 `python -m ohvul.report_verify REPORT SCAN_RESULT` 做只读联合校验；该命令不执行源码、不改变报告、不推进 FSM。

人工审核记录独立保存，使用 review_record 生成；它只能批准进入验证、驳回候选或要求验证，不能确认漏洞或修改 EvidenceBundle。

审核记录命令默认拒绝覆盖已有文件，需显式 `--force`。审核记录不会修改报告或 EvidenceBundle。

审核记录可用 `review_verify` 只读校验；报告修改后旧审核记录失效。该命令不会修改任何文件或改变候选状态。

审核记录包含报告 workflow.task_id，review_verify 会拒绝 task_id 不一致的报告/审核组合。

批次审核记录聚合多个同任务审核条目，并绑定同一报告摘要；它只表达流程状态，不改变候选证据或确认漏洞。

批次审核可用 `review_batch_verify` 只读校验；它不会推进 FSM、修改审核条目或产生漏洞确认。

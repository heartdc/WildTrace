# Phase 4 验收清单

| 条目 | 当前证据 | 状态 |
|---|---|---|
| 本地候选行复核 | `local_recheck.recheck_finding` 与 29 条 timer_task 记录 | 已完成 |
| 隔离输入输出 | `isolation_contract` 与预算测试 | 已完成 |
| FSM 验证状态 | `local_verification` 迁移 | 已完成 |
| 检查点关联 | `make_checkpoint_link` / `validate_checkpoint_link` 比较实际字节、任务和状态；尚未接入生产 CLI/FSM 迁移 | 部分完成 |
| 合成 harness | `local_harness`，始终 `undetermined` | 已完成 |
| 回归验证 | 108 项本地测试，Ubuntu CI 成功 | 已完成 |
| 真实目标代码执行 | 未执行 | 明确禁止 |
| 漏洞最终确认 | 未做 | 必须人工审核 |

本清单只证明工程门控和可复现证据链，不证明任何 OpenHarmony 漏洞成立。

校正：旧 `validate_link` / `load_link` 只检查 link 和记录的一致性，不读取检查点，不能证明检查点绑定。旧样本的全零 checkpoint_sha256 不能作为验收证据。新增联合校验也不验证源码快照、扫描结果或 harness 的行为正确性；这些仍需端到端接入。此前 Phase 4 整体完成的声明证据不足，不得凭此进入最终交付。

# Phase 4 本地安全验证契约

- 输入：已通过证据复核的候选和标量合成输入；禁止路径、网络地址和真实攻击载荷。
- 资源：合成输入不超过 1 MiB，超时预算不超过 60 秒。
- 输出：固定为 `undetermined`，必须 `review_required=true` 和 `no_target_execution=true`。
- 证据：记录必须绑定 task、检查点摘要和 harness 记录摘要。
- 验收：验证器通过、记录摘要一致、人工审核前不得进入最终报告。
- 边界：主机上的静态复核或合成 harness 结果不代表 OpenHarmony 平台漏洞结论。

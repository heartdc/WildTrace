# 合成引擎反例语料（synthetic counter-example corpus）

本目录是**手工合成的单模式样本**，用于引擎（clang-static-analyzer / clang-tidy /
semgrep 等）与内置规则的候选级回归对比，不来自任何授权的 OpenHarmony 源码快照。

两点边界说明（评审意见落实）：

1. `cases.json` 中的 `source_snapshot_sha256` 为空是**有意的**：合成样本不存在
   固定源码快照可绑定；该字段保留为模板格式的一部分，真实源码语料才会填充。
2. `expected_cwe` 全部是**规则回归标签**（尤其 CWE-676/CWE-416 依赖特定检查器
   是否开启），只用于验证引擎规则映射与候选指标管线的正确性，
   **不得外推**为真实 OpenHarmony 代码上的准确率、查全率或任何漏洞确认。

运行方式见 `docs/design/ENGINE_BENCHMARK.md`；评测输出自带 disclaimer。

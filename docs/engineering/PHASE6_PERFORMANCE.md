# Phase 6 性能评测契约

`python -m ohvul.performance --files N --lines M` 只生成临时合成 C 源码并调用本地扫描器。

- N 范围：1..10000；每文件行数：1..1000。
- 输出耗时、吞吐、候选数量，并标记 `local_only` 和 `no_execution`。
- 结果用于同一环境的规则回归和演示，不代表真实 OpenHarmony 性能、覆盖率或准确率。
- 基准不读取外部源码，不联网，不执行编译或目标程序。

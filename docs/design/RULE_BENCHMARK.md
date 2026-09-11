# 静态规则基准评测契约

## 输入

`docs/design/rule_benchmark.json` 是人工编写的本地合成样例。每个样例包含唯一 id、C/C++ 片段、期望的 CWE 候选集合和 label。样例不会联网、不会编译、不会执行。

当前 label 只表示评测意图：`candidate`、`reviewed_suppressed`、`candidate_requires_context`、`safe_control`。它不是漏洞真值，也不代表平台影响。

## 统计

`python -m ohvul.benchmark docs/design/rule_benchmark.json` 对每个样例单独扫描：

- TP：观测 CWE 与期望 CWE 的交集数量；
- FP：观测但不在期望集合的 CWE 数量；
- FN：期望但未观测的 CWE 数量；
- precision = TP / (TP + FP)，没有分母时为 null；
- recall = TP / (TP + FN)，没有分母时为 null。

统计对象是规则候选命中，不是确认漏洞、可利用性或 OpenHarmony 影响范围。一个 CWE 可能需要调用链、版本、配置和人工上下文才能判断，不能只凭命中计为真实 TP。

## 使用边界

该基准用于回归规则变化和展示统计流程，不用于对外宣称模型或工具准确率。扩展样例时要同时加入安全反例、人工复核依据和预期局限；不要加入真实敏感代码或真实攻击输入。

当前样例规模很小，统计不具备代表性。下一步需要按 CWE、语言特性和 OpenHarmony 组件类型扩展，并记录人工标注依据。

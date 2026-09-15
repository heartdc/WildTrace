# 候选复核证据链验收 — 2026-09-14

## 范围与结论

工作区 `C:\Projects\LSH`；基线 HEAD 为
`132b05670b539203cf5eafe3872b2f6979e75f75`。本批新增正式、离线、
可独立校验的候选复核队列和显式授权源码上下文提取入口。没有改变组件或
漏洞族总体范围，没有重新运行静态分析器，没有执行目标代码或调用 LLM。

本批工程验收通过；不是完整漏洞研判、PoC、平台复现或比赛交付验收。
Codex 原生工具返回 `DAEMON_STARTUP_FAILURE`，未取得模型执行回执，
实现与测试由 TaskQuay 直接工具完成。

## 实现

- `ohvul/review_queue.py`：验证明确指定的已完成批次及结果、报告、收据，
  保留全部原始诊断，按受限等价规则生成稳定复核组和待回答问题。
- `ohvul/review_context.py`：要求逐作业显式源码根，重验来源快照，从候选
  位置提取有限文本窗口和原始行号、文件摘要；窗口不等于控制流证明。
- `tests/test_review_queue.py`、`tests/test_review_context.py`：39 项测试；
  覆盖篡改、来源/状态冲突、跨引擎分组、重复记录、输入变更、独占写入、
  源码越界及资源限制等；不运行分析器。

独立校验会拒绝队列改写、诊断删除、报告重复行、引擎/规则/版本显示字段
与绑定证据不一致、声明引擎缺失、失败文件、bool 冒充数值计数等情况。
将分组用于减少重复阅读，不删除翻译单元与执行配置不同的观察。

## 本次实际执行结果

完整机器记录：`.cache/review_33f843/acceptance.json`。

| 检查 | 命令/入口 | 结果 |
| --- | --- | --- |
| 基线全量 | `python -X utf8 -m unittest discover -s tests -v` | 336 项，332 通过，4 跳过，退出码 0 |
| 新功能专项 | `python -X utf8 -m unittest tests.test_review_queue tests.test_review_context -v` | 39 项全部通过，退出码 0 |
| 最终全量 | `python -X utf8 -m unittest discover -s tests -v` | 375 项，371 通过，4 跳过，退出码 0 |
| 真实队列独立校验 | `ohvul.review_queue --summary ... --verify ...` | 退出码 0 |
| 真实源码窗口生成 | `ohvul.review_context --summary ... --queue ... --source-root ... --output ...` | 退出码 0；约 10.065 秒 |
| 真实源码窗口独立校验 | 同入口 `--verify` | 退出码 0；约 4.810 秒 |
| 差异/稳定性 | Python 摘要、HEAD、Obsidian、`git diff --check` | 均通过 |

4 项跳过为当前环境 `symlink unavailable`；不能计为通过。初次新测试运行
因模块尚未创建而导入失败；这不是“旧实现被39项测试击败”的对照数据。
原有336项基线、后续实测39项新增测试和375项全量结果分别保留。

本批正式队列消费上一批真实静态分析产物：
`.cache/real_components_c0d3/batch/summary-0005.json`。
原批次含 camera、securec、hilog 三个组件、44个显式源文件；本轮是复核
输入链处理，并未新增扫描覆盖。

实际队列保留35条诊断，得到29个组：27个API提示组、2个代码质量信号组。
全部保持 `undetermined`，确认漏洞数0。零诊断camera仍保留来源记录。
从16个相关文件提取了29组文本窗口，摘录输入共304,314字节；该数值不
包含来源根目录快照读取的额外开销，也不是工具内存占用测量。

## 已保存产物

```text
.cache/review_33f843/queue.json
.cache/review_33f843/context.json
.cache/review_33f843/acceptance.json
.cache/review_33f843/final-focused.log
.cache/review_33f843/final-full.log
.cache/review_33f843/real-queue-verification.log
.cache/review_33f843/real-context-build.log
.cache/review_33f843/real-context-verification.log
```

功能使用约定见 `docs/engineering/REVIEW_QUEUE.md`。不覆盖已有目录/文件；
旧批次的结果、报告、收据、临时复核索引均保持原样。

## 边界与后续

队列校验只证实已保存输入之间的一致性；它不擅自打开JSON内的原始profile、
manifest和源码路径。上下文入口是在显式传入源码根后才重新读取源码。
摘要不是签名，前后快照也不是不可变挂载；协调改写所有输入的行为不在
真实性证明范围内。选用显式历史summary不代表自动选中了最新运行。

当前新增的是人工/受控LLM研判的证据输入层，不是已经接通模型的Agent。
后续可在独立记录中引用队列与group摘要，加入可达性、输入可控性、边界
条件和安全影响的结构化判断，并要求每个判断指回实际证据。
现阶段无需新增人工条件即可扩展这些契约与本地测试；完整产品版本矩阵、
运行级验证隔离环境、私下提交责任人仍见已有 `HUMAN_ACTIONS_20260914.md`。

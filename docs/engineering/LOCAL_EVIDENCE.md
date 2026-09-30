# 有界本地证据扩展

`ohvul.review_evidence` 在已经校验的批次、复核队列和源码窗口之上，收集诊断
所在的函数/宏范围、同文件相关定义及同文件调用语法位置。它不调用模型、
分析器或网络，不执行源码，也不执行模型提出的文本请求。

这是词法导航工具，不是编译器 AST、预处理器、控制流图或调用图。
函数/宏名称关联不是完整符号解析，调用语法不证明可达性或输入可控性。
条件编译下的同名定义全部保留，不擅自选择某个产品分支。

## 输入与输出

调用者明确提供 summary、queue、context 和每个 job 的源码根。复用原有
证据校验，检查当前文件字节与旧窗口的文件摘要一致，扩展前后重检源码快照。
只搜索诊断所在文件，不沿 include、JSON 内嵌路径或模型文本读取其他文件。

输出包含原始行号、字节摘要、词法完整范围、实际摘录范围、截断状态，以及
与 `review_handoff` 一致的 task_id。补充局部证据不会关闭任务；所有任务仍为
`needs_evidence_or_review`，答案仍为 unknown，确认漏洞数为 0。

默认处理全部复核组；显式 `--group` 可选择子集，遗漏组数会记录。
没有诊断的已完成批次也能生成并独立校验空证据文档，不伪造发现。

## 默认预算

| 参数 | 默认值 | 支持范围 |
| --- | ---: | --- |
| `--max-lines` | 160 | 1–400，每个摘录 |
| `--max-definitions` | 12 | 1–32，每组包含主范围与关联定义 |
| `--depth` | 2 | 1–3，同文件名称关联层数 |
| `--max-callsites` | 8 | 1–32，每组调用语法摘录 |

每文件最多 2 MiB、300000 个词法 token；单片段最多 64 KiB；最终文档最多
16 MiB。超出字节预算拒绝输出，不静默丢弃。行/定义/深度上限通过
`truncated`、`callsites_truncated`、`definition_traversal_complete` 显示。
达到深度上限不表示剩余定义不存在。括号布局不完整时不猜测函数归属。

## 实际入口

```powershell
python -m ohvul.review_evidence `
  --summary .cache/real_components_c0d3/batch/summary-0005.json `
  --queue .cache/review_33f843/queue.json `
  --context .cache/review_33f843/context.json `
  --source-root camera_app=C:/Projects/OpenHarmony-complete `
  --source-root hilog_featured=C:/Projects/OpenHarmony-complete `
  --source-root securec=C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --output .cache/evidence-new.json
```

独立复核时，保持上述输入不变，把 `--output` 改为 `--verify` 并指向已保存
文件。输出采用独占创建，不能覆盖已有文件，不能写入输入源码或批次目录。
校验会重新推导完整文档；编辑代码行、移除证据、改变任务状态或结论均会失败。

## 基础事实层修复与边界

`semantic_facts` 现在复用平衡范围：支持常见多行函数头，结束花括号之后
不继续沿用旧函数；控制块不冒充函数，函数定义不同时计为调用，注释、字符串
和宏定义本身不生成执行事实。读取采用有界严格 UTF-8，显式文件集合拒绝
重复、越界和链接路径。它仍是词法事实层，不是已完成的数据流分析。

`semantic_rules` 里的旧固定窗口/参数匹配规则仍需要单独收敛，不能因为基础
事实层修复就声称跨函数传播、别名、宏求值或安全性已被证明。

本地摘要用于一致性检测，不是签名；文件系统也不是不可变挂载。源码和模型
文本始终作为不可信数据。此入口不需要 API 凭据。

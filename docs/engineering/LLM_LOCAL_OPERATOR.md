# 在本机完成 LLM 研判

本入口使用已有、经过独立校验的真实批次、复核队列、源码窗口和扩展证据。
不会扫描新目标、执行 OpenHarmony 程序或执行模型给出的命令。
本次 ChatGPT 侧重试在凭据输入阶段被工具安全检查拦截，未发出新 API 请求；
不能把它解释为新的403、服务宕机、密钥无效或响应超时。

## 1. 无网络预检

在本机 PowerShell/Windows Terminal 中运行：

```powershell
Set-Location C:\Projects\LSH
python -X utf8 tools/llm_local.py plan --output .cache/llm-my-plan
```

默认配置是 `docs/profiles/llm_operator_20260914.json`，不允许出现key字段。
相对输入路径以项目根为基准，输出参数以当前终端目录为基准。
首次选择 securec `src/memcpy_s.c:518` 一组用于服务联通验证，不代表缩减项目范围。
预检需要重新校验源码快照，之后输出 `SELECTED_GROUPS 1 OF 29`、`prepared` 和
`calls_attempted: 0`。`plan.json`中可查看实际发送的证据、引用、片段省略和预算。
缓存输入缺失或源码改变时，应重建原始流水线，不得编辑哈希强行通过。

## 2. 隐藏输入密钥并运行

```powershell
python -X utf8 tools/llm_local.py run --output .cache/llm-my-live --allow-network
```

出现 `API key (hidden, not saved):` 后，只在本机粘贴测试凭据并按回车。
不回显字符是预期行为。凭据不是命令行参数，不写入配置、环境文件或输出。
无法隐藏输入时脚本拒绝回退到明文输入。非交互调用只能显式选择
`--key-source environment`读取当前进程继承的 `OSLOVELACE_API_KEY`；不要把
含真实凭据的赋值命令保存进终端历史。Python不保证内存字符串的安全擦除。

配置使用 `https://oslovelace.com/v1`、请求模型标识 `grok-4.6`，最多1次请求、
最多请求3072个输出token、300秒socket超时。该超时针对阻塞操作，不是整个
流程的严格墙钟上限；本地来源检查和分段读取不能简单等同于服务端推理时间。
保持TLS验证，禁止重定向，不自动重试。HTTP403是收到的拒绝响应；只有实际
超时才记录 `transport_timeout`，延长等待不能自动解释或修复403。

不要并行重复运行同一批来催促响应。中断请求可能已经到达服务端；缺失用量
不能证明没有收费，先检查已有记录。输出目录必须不存在，不能复用预检目录。

## 3. 离线核验成功或失败记录

```powershell
python -X utf8 tools/llm_local.py verify --output .cache/llm-my-live
python -X utf8 tools/llm_local.py inspect --output .cache/llm-my-live
```

`verify`只接受被选草稿全部通过格式、引用和输入绑定检查的运行。
`inspect`也接受记录一致的失败运行；`bound_incomplete`不是推理成功。
即使 `bound_completed`，也仍为 `reasoning_verified=False`。二者不会读取密钥、
再次请求网络、执行命令或确认漏洞。

首个调用的脱敏状态：

```powershell
Get-Content .cache/llm-my-live/item-0001.json -Raw |
  ConvertFrom-Json | Select-Object outcome,error_code,seconds
```

| 记录 | 含义及处理 |
| --- | --- |
| `valid_draft` | 格式与引用合格，仍需核实推理；不是漏洞已确认 |
| `transport_timeout` | 实际等待超时；保留记录，核对本机服务后再决定新的有界运行 |
| `http_status_403` | 收到拒绝响应；对照本机成功客户端和服务端日志，不只凭状态码断言原因 |
| `invalid_output` | 完整JSON、模型标识或引用契约不满足；保留原文和摘要，不伪造引用或关闭检查 |
| 没有 `summary.json` | 中断或发布未完成；不能将其当成成功运行 |

## 4. 交回记录与扩展选择

保留 `.cache/llm-my-live/` 内的 `plan.json`、`summary.json`、全部 `item-*.json`。
告知目录路径即可继续在项目中复核，不需要再次提供密钥、账户截图或环境变量。
不要修改运行记录、模型回答或原始证据，失败记录同样有排查价值。

一组成功后，复制无凭据配置并显式修改 `groups` 和 `max_calls`（最多32），
使用 `--config <文件>` 先plan确认预算再run，每次使用新输出目录。
`--group <ID>`可覆盖选择，但不会提高配置中的调用预算；未选组数始终保留。

底层 `ohvul.llm_review` 与 `ohvul.review_handoff` 都支持 `--evidence`。
扩展运行的独立核验必须显式提供同一份扩展证据，不会从JSON中自动跟随路径。
旧窗口运行保持原提示和摘要；模型的 E1 等扩展引用在交接目录中保留，任务不自动关闭。

默认使用的工程资料是 `.cache/real_components_c0d3/batch/summary-0005.json`、
`.cache/review_33f843/queue.json`、`.cache/review_33f843/context.json`、
`.cache/evidence_1ca10/expanded.json`，不上传比赛附件或整个仓库。

## 证据预算

请求保留L行引用、D诊断引用，新增E片段引用。按照主要范围、相关定义、同文件
调用语法顺序逐片段装入48KiB证据请求预算。不能容纳的片段逐项记录省略，
已有截断、未穷尽搜索、未求值预处理分支均保留。词法片段不是AST/CFG、真实
数据流、攻击者控制或运行复现证据；源码文本始终是不可信数据而非执行指令。

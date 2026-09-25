# WildTrace Demo Runbook

这是比赛演示的可复跑脚本，目标是展示“候选发现 → 证据核验 → 人工复核队列 → 报告”的离线流程。它不把合成或等价 harness 演示成 OpenHarmony 产品漏洞。

## 演示前准备

1. 使用干净 Python 3.10+ 环境安装仓库：`python -m pip install -e . --no-deps`。
2. 准备一份授权源码目录和固定源码快照摘要；输出目录必须是源码树外的新目录。
3. 若演示 Clang/clang-tidy，引入经过 profile 校验的本地工具链；若工具不可用，演示失败记录和 `input_error`，不要删除错误继续。

## 推荐录屏顺序

```powershell
python -m ohvul.cli .\demo-source --output .\demo-out\findings.json
python -m ohvul.candidate_triage --result .\demo-out\findings.json --output .\demo-out\triage.json
python -m ohvul.verify .\demo-out\findings.json
python -m ohvul.candidate_triage --result .\demo-out\findings.json --verify .\demo-out\triage.json
```

讲解每条告警的源码行、文件 SHA-256、行摘要、规则版本和 `final_verdict=undetermined`。随后展示 triage 队列如何保留全部告警，以及失败输入如何进入 `input_errors` 而不是被计为干净扫描。

## 真实案例片段

可以展示 `cases/cjson_merge_alias` 或 IPC/KV 案例的证据文件，但必须在画面中标出验证层级：公开已知案例、源码等价 reproducer、真实库构建、产品可达性和官方接受是独立状态。当前 IPC/KV 案例不能演示为已链接 OpenHarmony 二进制。

## 录屏交付清单

- 演示环境的 Python、工具链和源码提交摘要；
- 每条命令及退出码；
- findings、triage、verify 和报告 JSON；
- 失败输入或缺失工具的保留记录；
- 不包含 API key、真实用户数据、设备凭据或未授权源码；
- 视频旁附同版本的命令脚本和 SHA-256。

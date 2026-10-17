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

可以展示 `cases/cjson_merge_alias` 或 IPC/KV 案例的证据文件，但必须在画面中标出验证层级：公开已知案例、源码等价 reproducer、真实库构建、产品可达性和官方接受是独立状态。

2026-09-25 已生成自定义 x86_64 配置的真实 `libcj_ipc_ffi.z.so`，可以展示构建退出码、ELF、摘要及导出符号。修复隔离基础运行库后，未修改的 IPC 库已通过对象创建/大小查询及正常字节数组写入—读回检查。展示时必须同时说明基础运行库补丁和不完整的产品服务环境，不展示为官方产品复现；KV 真实库未完成。历史案例中的等价基线与新构建证据分别说明，不能自动提升案例状态。证据目录和摘要见 `docs/analysis/REAL_BUILD_PROBE_20260925.md`。

## 录屏交付清单

真实库正常调用的可复跑命令见 `tools/validation_cases/README_IPC_NORMAL.md`。
该命令要求已准备好的隔离构建树和新证据目录；运行时补丁必须随演示说明。

- 演示环境的 Python、工具链和源码提交摘要；
- 每条命令及退出码；
- findings、triage、verify 和报告 JSON；
- 失败输入或缺失工具的保留记录；
- 不包含 API key、真实用户数据、设备凭据或未授权源码；
- 视频旁附同版本的命令脚本和 SHA-256。

## 2026-10-17 增补段（配 VIDEO_SCRIPT v2）

1. 工作台段：预启动 `Start-Workbench.ps1` 并预载案例数据（避免冷启动）；
   演示路径 = 总览 → 案例对话框（ipc 案三标签）→ 候选审查 → 报告中心。
2. 真库验证段：预演一次 `run_malformed.sh` 与 `run_bt_dereg.sh`（WSL 环境 +
   OH 构建产物就绪为前置）；录制时展示 run.exit=139 与 attribution.txt。
3. 数字基线：全量回归 1,162 项；漏斗 2,662→13；影响矩阵 20 案全分支判定
   （实质率 68%）；四项真库级 SIGSEGV（ipc/hiappevent/udmf/bt）。

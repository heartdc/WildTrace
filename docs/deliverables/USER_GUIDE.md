# WildTrace 使用说明

本文对应比赛交付件三的命令行使用部分。命令默认在 Windows PowerShell 执行，扫描和离线核验不需要 API key，也不会执行被扫描的源码。

## 1. 安装与预检

使用 Python 3.10 或更高版本，在仓库根目录执行：

```powershell
python -m pip install -e . --no-deps
python -m unittest tests.test_candidate_triage tests.test_ffi_boundary_audit tests.test_kb_gap_audit -q
```

本地静态扫描只需要 Python。Clang、clang-tidy 和 Semgrep 通过显式 profile 配置；缺少工具、输入或编译参数时，结果必须保留 `input_error`，不能解释为零漏洞。

## 2. 扫描、triage 和离线核验

扫描一个授权源码目录，并把输出放在源码树之外：

```powershell
python -m ohvul.cli .\authorized-source --output .\out\findings.json
python -m ohvul.candidate_triage --result .\out\findings.json --output .\out\triage.json
python -m ohvul.candidate_triage --result .\out\findings.json --verify .\out\triage.json
python -m ohvul.verify .\out\findings.json
```

triage 会保留每条告警，并分到人工复核、需要上下文、语法线索、质量问题或测试支援工作队列。队列顺序不是严重性，`confirmed_vulnerabilities` 始终为 0，直到人工完成独立审核。

## 3. 编译器和多引擎分析

使用经过来源校验的 profile：

```powershell
python -m ohvul.cli .\authorized-source `
  --engine-profile .\profiles\component.json `
  --compiler-profile .\profiles\compiler.json `
  --output .\out\component-findings.json
```

profile 必须绑定本地 Git worktree、固定提交、源文件清单、include 目录和受限编译参数。报告中的编译器版本、命令、返回码和产物摘要属于证据绑定，不是工具安装路径的推断。

## 4. FFI 边界初筛

对 C/C++ 源码运行受限的 FFI 裸数组边界初筛：

```powershell
python -m ohvul.ffi_boundary_audit .\authorized-source --output .\out\ffi-boundary.json
```

该规则只提供导航候选。它不证明 C++ 类型绑定、调用者可达性、权限边界、数组容量或漏洞 CWE；证据不足时 CWE 为 `unknown`。输出中的 `files_scanned` 只统计成功读取和解码的文件。

## 5. 已知案例与等价 harness

`cases/` 中的案例分别记录源码位置、CWE/CVE 线索、PoC 或等价复现、修复材料和当前验证层级。`source_equivalent` 只说明复制的函数形状在本地 harness 中观察到行为；它不是 OpenHarmony 二进制、产品可达性或官方漏洞确认。

真实库验证必须额外绑定源码提交、产品配置、目标库 ELF 架构、导出符号、依赖库、调用入口、隔离环境和正常控制。没有这些绑定时，案例应保持 `platform_binary_linked=false` 或 `product_reachability=not_established`。

## 6. 报告和性能结果

候选结果可在扫描时生成防御性报告：

```powershell
python -m ohvul.cli .\authorized-source `
  --output .\out\findings.json `
  --report-output .\out\report.json
```

性能命令当前是合成基准：

```powershell
python -m ohvul.performance --files 100 --lines 100
```

合成吞吐和 Python 分配峰值不能代表完整 OpenHarmony 产品扫描。比赛性能说明必须另附固定源码提交、文件分母、阶段耗时、分析失败/跳过、进程树资源峰值和可复跑命令。

## 7. 安全边界

默认模式不联网、不执行目标、不访问设备、不提交外部报告。授权的隔离运行必须绑定授权记录、源码快照、工具链、PoC 摘要、资源限制和日志摘要。普通功能错误或没有安全影响的 DoS 不应升级为漏洞结论。

## 8. 工作台与真库验证（2026-10 增补）

- **工作台**：`Start-Workbench.ps1` 启动本地 Web 界面（总览指标 / 案例证据
  三标签 / 候选审查 / 报告中心）。概览指标断言为计数无关口径；Joern 为
  `--joern` 选配层（WSL /opt/joern），异常时规则层独立可用。
- **真库 malformed 验证**：`tools/validation_cases/run_malformed.sh`（通用，
  支持 udmf/ipc/kv/hiappevent 等客户端）与 `run_bt_dereg.sh`（bluetooth
  服务端空指针，含 ASan 构建、gdb 帧归因与 unstripped 符号化）。判读：
  run.exit∈{11,139} = 崩溃观测；证据目录含 inputs-before/after SHA-256。
- **LLM 审查**：`tools/llm_review_run.py`（全队列 plan/run/verify；密钥经
  `--key-file` 单行文件运行时注入）。模型输出恒为 proposal，
  final_verdict=undetermined。

## 9. 影响矩阵与分支实证（2026-10 增补）

`python -m ohvul.impact_matrix --cases cases --output docs/deliverables/IMPACT_MATRIX.md`
可复算。分支证据三层来源（case.json branch_evidence.reference 可溯源）：
分支 manifest 钉版 → gitcode README.OpenSource 版本实证（第三方 16 案）；
漏洞符号逐分支存在性探测（原生四案，2026-10-17）；master 检出三侧对照。

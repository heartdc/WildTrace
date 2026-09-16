# securec 固定版本的真实本地功能对照

本入口针对已授权的本地提交 `2ae82839ecaaa7d031e66ccbd2076d671acfd615`，
只编译复制的 `src/memcpy_s.c` 及三份声明/工具头文件。它不会执行上游构建
脚本、下载历史代码、回退补丁或修改原库，不是任意命令运行器。

## 实际执行

```powershell
Set-Location C:\Projects\LSH
python -X utf8 tools/validation_cases/run_securec_controls.py `
  --output .cache/securec-controls-new `
  --allow-target-execution `
  --approval-reference user-local-runtime-authorization-20260915
```

输出目录必须不存在，父目录必须存在。实际目标根默认是
`C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function`。
命令中的引用指向已给出的用户授权；工具不会自行认证授权人的身份。

重用现有 bubblewrap 沙箱：用户/进程/挂载/网络命名空间隔离，输入和工具链
只读，目标阶段无主机可写挂载，无网络，清空环境并移除能力。启动前读取
沙箱内的接口与能力状态，不满足条件立即停止，不回退到无隔离执行。

两次真实构建分别使用 `-O0` 与 `-O2`，均启用 ASan/UBSan、禁用 performance
addons。每个二进制运行三次，每次创建新沙箱；每个进程检验六个固定输入。
它们不是产品编译配置矩阵，也不是第二位审核人的独立复现。
编译和运行有 CPU、时间、输出与文件大小限制；ASan 的 RSS watchdog 不是
内核/cgroup 内存上限，LeakSanitizer 不启用，不能夸大隔离和内存指标。

六项对照为有界复制、count 超过 destMax 的拒绝/清零、空源拒绝/清零、空目标
拒绝、固定版本重叠分支、零计数不复制。实际分配对象均足够大，含哨兵检查，
不靠虚报目标容量制造库漏洞。重叠仅验证这份实现，不宣称可移植 API 保证。

## 离线核验与候选回填

```powershell
python -X utf8 tools/validation_cases/run_securec_controls.py `
  --output .cache/securec-controls-new --verify
```

核验重新检查固定源码、复制输入、当前审核的 harness、编译参数、二进制、
日志字节、运行顺序及原始 JSON 输出；不重新执行目标。超时、编译失败、
Sanitizer 报告和不完整输出不能变成成功对照。成功回执中的源码版本、
重复次数、执行数和漏洞结论也不能通过修改 JSON 来替换。

已准备的 `memcpy_s.c:518` 案例可以附加独立复核资料：

```powershell
python -X utf8 tools/validation_cases/run_securec_controls.py `
  --output .cache/runtime_c5d/securec-real `
  --attach-case .cache/delivery_ccd71/securec-review-case.json `
  --static-result .cache/integration_2b2e/final/real/batch/securec/result.json `
  --static-report .cache/integration_2b2e/final/real/batch/securec/report.candidate.json `
  --review-output .cache/securec-control-review-new.json
```

该操作复用 `runtime_evidence._case` 重建校验，不修改原候选、静态报告或运行
记录。对照与静态源码摘要必须一致。附件始终为
`functional_negative_controls_only`；候选保持开放、`undetermined`，不能作为
“漏洞已经触发”“已经修复”或比赛完整案例验收通过的依据。

## 下一步证据

这些对照回答了部分 API 参数门控的实际行为，尚未回答真实调用者的分配容量、
外部输入控制、产品可达性或安全影响。后续应围绕可复核的具体调用路径推进，
而不是继续为当前没有漏洞触发的输入重复累计运行次数。

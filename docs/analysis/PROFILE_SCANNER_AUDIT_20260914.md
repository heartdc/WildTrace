# Profile 来源、输入契约与内置扫描读取失败审计

## 范围与基线

- TaskQuay 工作区：`C:\Projects\LSH` / `ws_b372c68cd6`。
- 本轮：`run_9cc31543ea0746ddbae60b98379351d2`。
- HEAD：`9b3fdad5f37a1252ab21c59cc2a9bf2ac63f59e1`，本轮未提交项目、回滚或清理 Git。
- 在已有未提交的 P0/引擎补丁上继续增量开发；保留原有 Obsidian 修改。
- 修改前 `python -m unittest discover -s tests -q`：220 项运行，216 项通过、4 项跳过，退出码 0。
- 仅执行本地单元测试。分析器均用受控替身；没有运行真实 OpenHarmony 目标、真实分析器、网络扫描或外部模型调用。
- 来源测试使用临时合成 Git 仓库；临时仓库的 init/add/commit 不涉及项目 Git 历史。

## 实际发现与修改

### P1：profile 来源检查没有进入执行链

`validate_profile_provenance` 原来只比较 HEAD，执行 profile 的路径没有强制调用它。
嵌套普通目录可继承父仓库 HEAD；脏工作区仍可能宣称固定提交；Git 超时没有显式失败结果。

现有 `prepare_profile` 在分析器调用前校验 profile 字节、输入、声明仓库和目标文件：

1. profile 的 SHA-256 与解析对象来自同一次限长字节读取，拒绝重复 JSON 字段和非标准数值。
2. 仓库路径必须位于源码根内且确为 Git worktree 根，HEAD 必须匹配完整 SHA-1。
3. 记录声明仓库的 Git tracked/untracked 清洁状态；失败、超时、不可访问均不能转为 verified。
4. 不递归未声明的 submodule；源码/包含目录的实际所属仓库必须在声明中。
5. 目标源码必须被相应仓库追踪；忽略文件、assume-unchanged/skip-worktree 等索引隐藏不能继承提交声明。
6. Git 查询不继承 GIT_DIR/WORK_TREE/INDEX 等重定向环境，不刷新索引，关闭 fsmonitor，并拒绝配置了 clean/smudge/process 的过滤器。
7. 执行后再次核对 profile 字节与声明仓库状态，再结合原有源码快照检查发布结果。

结果的 `profile_validation` 保存 profile SHA-256、实际仓库核验记录、输入检查、规则摘要与源码快照。
`scan_engine_profile` 和独立 `engine_cli --profile` 都使用同一入口。
独立 engine CLI 的 profile 仅允许 `clang-static-analyzer` 单引擎选择，不能静默忽略其他声明引擎。
多引擎执行仍使用主 CLI 的 `--engine-profile`。

### P1：profile 参数类型、路径与编译参数约束不足

新增 `ohvul/source_scope.py`，共享相对路径、别名检测、符号链接/junction 前缀检查。
profile 严格检查数组类型、必需非空范围、重复来源/路径/引擎/宏名、非法宏与控制字符。
拒绝绝对路径、盘符相对路径、UNC、`..`、设备保留名、NTFS 冒号和歧义尾部字符。

`include_dirs` 和 `defines` 是独立字段，不允许以 `extra_compile_args` 逃逸。
额外参数只开放代码中列明的 `-std=...`、警告选项及少量固定选项；拒绝 response file、插件、
`-Xclang` 等任意转发、输出覆盖参数和任意 sysroot/include 重定向。
可选 `semgrep_rule_sha256` 必须与声明规则文件集合完全对应且匹配实际字节。
主 CLI 的输出冲突检查也包含 profile 和显式文件清单，不能以 `--force` 覆盖这些输入。

### P1：读取失败被静默跳过且错误计入扫描成功数

内置扫描器现在只读取一次源码字节，严格按 UTF-8 解码，成功后才增加 `files_scanned`。
失败项保存 `input_errors`、`file_results`、`error_type` 和错误原因。
每个成功文件及其候选证据保存实际读取字节的 `file_sha256`。

执行状态不再取决于候选数量：无错误为 `completed`，成功与失败并存为 `partial`，
存在失败且没有成功分析为 `input_error`。默认目录中没有符合扩展名的文件仍表示空范围完成，
不是“代码安全”；显式空文件清单、非法类型、重复别名直接拒绝。

使用带 onerror 的目录枚举，目录读取错误不再伪装成空范围：`scope_complete=false`，
总申报数量 `files_requested=null`，已观察数量保留在 `files_discovered`。
常规文件读取失败增加 `files_failed`；目录枚举错误不虚构未知文件数量。
默认扫描跳过的链接文件/目录明确列示，显式选择的链接输入作为错误处理。

`shards.merge_shard_results` 保留失败状态、计数、文件记录和错误，不因合并丢失信息。
主 CLI 对内置扫描未完成的结果阻断成功发布；记录 blocked/abort 并清空当前结果摘要。
上一轮关于多文件事务和旧产物留存的限制仍适用。

## 测试证据

实现修改前新增的首批 26 个测试方法已实际运行失败：34 个断言失败、33 个错误（含 subTest，
因此失败/错误计数不等于测试方法数）。日志：`.cache/profile_scanner_red_9cc31543.log`，退出码 1。
其中一个正常参数接受测试通过。该对照未更换或回滚工作区实现。

初次完整回归的 3 个错误来自旧 profile 测试用不存在的仓库/未声明依赖构造成功路径。
它们已改为真实临时 Git 仓库，保留 Clang/clang-tidy/Semgrep 分派与错误传递断言，未 mock 掉来源检查。
新测试还覆盖忽略目标、索引隐藏、规则哈希不符、Git 过滤器拒绝、目录枚举失败及显式链接输入。

最终执行：`python .cache/accept_profile_scanner_9cc31543.py`，退出码 0。
该脚本执行以下测试命令并保存完整日志和源码哈希：

```text
python -m unittest tests.test_profile_input_contract tests.test_scanner_read_contract tests.test_engine_profile tests.test_engine_profile_scan tests.test_workflow_p0 tests.test_engine_execution_contract tests.test_scanner tests.test_shards -v
python -m unittest discover -s tests -v
git diff --check
```

| 检查 | 观测结果 |
| --- | --- |
| 最终专项 | 87 项运行，86 项通过、1 项跳过；退出码 0；12.194 秒 |
| 最终全量 | 255 项运行，251 项通过、4 项跳过；退出码 0；20.516 秒 |
| 差异格式 | `git diff --check` 退出码 0 |
| 测试前后 Python 源码/测试哈希 | 一致 |
| 测试前后 Git HEAD | 一致 |
| 相对开工基线的范围外 Python 变更 | 无 |
| 原有 Obsidian 文件字节 | 未变化，保留其原有未提交修改 |

四个全量跳过项仍为 Windows 环境的 `symlink unavailable`：checkpoint_link、integrity、scanner、snapshot。
新增的模拟链接/junction 拒绝测试不是这四项真实文件系统测试的替代品。
测试耗时仅用于复核本轮执行，不是大规模扫描性能指标。

日志与机器记录：

- `.cache/profile_scanner_final_focused_9cc31543.log`
- `.cache/profile_scanner_final_full_9cc31543.log`
- `.cache/profile_scanner_acceptance_9cc31543.json`

## 兼容性与仍未完成的部分

- 历史 camera profile 的 include_dirs 涉及未完整声明的依赖仓库；需要补齐准确提交和可用依赖后再执行。
  本轮没有读取/修复 `C:\Projects\OpenHarmony-complete`，不宣称该工作区已经通过新契约。
- `semgrep-profile-0.1` 的历史设计样例不是 `engine-profile-0.1` 的可执行契约，不能直接混用。
- Git HEAD/clean 状态与 SHA-256 是本地一致性证据，不是官方来源认证、签名或不可变存储。
  被忽略的生成头文件、系统工具链头文件及隐式编译器依赖尚未构成完整构建来源证明。
- 路径前缀检查和前后哈希不是不可变文件系统；仍有并发目录替换/检查后变化窗口。
- 大源码根的重复快照及多次 Git 查询尚未优化，需独立测量而不能据单测耗时外推。
- 未运行真实分析器或真实 OpenHarmony 目标；不增加真实漏洞数，不宣称检测准确率或比赛成品完成。
- 后续先在授权、固定版本的组件上补齐可核验 profile，再做真实分析器 smoke 与性能基线。

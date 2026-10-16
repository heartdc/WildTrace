# OpenHarmony 构建脚本交接

这两份工具从 AerGap 本机项目缓存迁出，用于交接生成的 Ninja 构建图整理和 Rust 运行库准备步骤。路径全部由调用者提供，不依赖维护者用户名、源码目录或证据目录。

## 原件溯源

2026-10-16 实际找到的原件在 Windows 项目缓存，而非 WSL `~/.cache/`。原件未修改：

| 原件 | SHA-256（原始字节） |
|---|---|
| `C:\Projects\LSH\.cache\sweep_v3.py` | `26ca781f19d03a163060ce3e45c8fc57749d11d2407ecc0395a0a6719379fcda` |
| `C:\Projects\LSH\.cache\fix_rust_std2.sh` | `bfa1c54018d999ae652ed6ba3be16cc3b77ece587990c1ad282ca2f4712652e2` |

交接版保留实际目标的 `ninja -n` 检查和复制 Rust `.so` 为真实文件的处理方式，作了以下调整：

- 移除 `/home/airgap/oh-full-20261003`、`/mnt/c/Projects/LSH-fix-batch-sizeof` 等硬编码路径。
- 默认只检查，显式 `--apply` 才修改；修改前保存原件，错误返回非零状态。
- Ninja 去重比较完整 build edge（包括缩进变量），不再只比较第一行；有续行或无法判定的不同规则停止。
- 原版自动优先 `toolchain.ninja` / `m133` 的策略改为明确的 `--prefer-file`，避免另一环境无条件保留错误的工具链。
- Rust 脚本仅准备运行库，不删除旧证据、不修改 PATH、不自动调用 `run_malformed.sh`。后续验证由调用者使用独立的新证据目录执行。

## 环境和顺序

在 Linux 或 WSL 中执行。要求 Python 3.10+、Bash、GNU coreutils、已经完成依赖下载的 OH 源码树和已经生成的输出目录。先设置自己的路径：

```bash
OH_ROOT=/path/to/openharmony
OH_OUT="$OH_ROOT/out/x86_64_virt"
HANDOFF_BACKUPS=/path/to/build-backups
mkdir -p "$HANDOFF_BACKUPS"
```

### 1. 检查实际 Ninja 目标

在 WildTrace 仓库根目录运行，将 `COMPONENT_TARGET` 替换成当前构建目标：

```bash
COMPONENT_TARGET=path/to/component/library.so
python3 tools/oh_build/sweep_v3.py \
  --source-root "$OH_ROOT" --output "$OH_OUT" --target "$COMPONENT_TARGET"
```

退出码：`0` 表示该目标 dry-run 成功，`2` 表示发现可处理的重复规则但尚未修改，`1` 表示其他错误或无法自动处理。`GRAPH_CLEAN` 仅表示该目标可通过 Ninja dry-run，不表示真实构建成功或整个源码树都可构建。

确认待处理规则后使用一个尚不存在的备份目录：

```bash
python3 tools/oh_build/sweep_v3.py \
  --source-root "$OH_ROOT" --output "$OH_OUT" --target "$COMPONENT_TARGET" \
  --apply --backup-dir "$HANDOFF_BACKUPS/ninja-001"
```

默认 Ninja 路径为 `$OH_ROOT/prebuilts/build-tools/linux-x86/bin/ninja`，可用 `--ninja /absolute/path/to/ninja` 覆盖。脚本处理无变量的自引用 stamp 和完整相同的重复 edge。遇到不同 edge 时先检查输出中的错误、对应 `.ninja` 文件及工具链；确需沿用原件的工具链选择时添加 `--prefer-file toolchain.ninja`，或精确指定输出目录内的 `m133/...ninja` 文件。只有唯一匹配的保留 edge 时才应用该选择。

备份保留输出目录相对结构，`edits.tsv` 记录每次修改前后的摘要。停止构建进程后，可以从备份恢复对应 `.ninja` 文件；不要把 `edits.tsv` 复制到输出目录。GN 重新生成会覆盖这些手动整理结果，需要重新检查。

### 2. 准备 Rust 运行库

```bash
bash tools/oh_build/fix_rust_std2.sh "$OH_ROOT" "$OH_OUT"
bash tools/oh_build/fix_rust_std2.sh "$OH_ROOT" "$OH_OUT" \
  --apply "$HANDOFF_BACKUPS/rust-001"
```

默认读取：

```text
prebuilts/rustc/rust-std-nightly-x86_64-unknown-linux-ohos/rust-std-x86_64-unknown-linux-ohos/lib/rustlib/x86_64-unknown-linux-ohos/lib
```

如果 Rust 工具链布局不同，设置 `RUST_LIB_DIR=/absolute/path/to/rust/lib`。目标目录固定为 `$OH_OUT/obj/third_party/musl/usr/lib/x86_64-linux-ohos`，必须已经存在。该配方仅适用于匹配的 x86_64 OH 工具链；成功复制不证明 ABI 或产品环境兼容。

`original/` 保存已存在的文件或符号链接；`created-files.txt` 列出本次新建文件；`source-before.sha256` 和 `installed.sha256` 记录输入与输出摘要。恢复时仅删除清单中本次新建的文件，并将 `original/` 中的目录项恢复到 `destination.txt` 所记目录。不要跟随目标符号链接覆盖外部文件。

## 验收范围

```bash
python3 -m unittest tests.test_oh_build_handoff -v
bash -n tools/oh_build/fix_rust_std2.sh
```

测试只使用临时 Ninja 图和虚拟 `.so` 文本文件，不执行目标程序。覆盖实际 Ninja dry-run、备份、幂等检查、未知目标失败、不同 edge 变量拒绝、显式工具链选择，以及 Rust 文件复制和符号链接恢复。

本次交接消除两份脚本仅存在于本机缓存的缺口，但未重新执行第二环境的整条构建管线。接收方仍须固定 manifest/组件提交和工具链，在其输出树上完成目标 dry-run、真实构建及后续环境检查，并保存完整日志。

## 与构建流程文档的对应关系

对应构建流程文档 PR #130：第 3 步的 `python3 sweep_v3.py <target>` 应替换为本文的 `--source-root / --output / --target` 调用。第 4 步的真实 Ninja 编译仍单独执行；Rust 组件在后续加载前执行本文第 2 节的运行库准备。脚本入库解决的是文件交接，不替代接收机器自身的环境登记，也不能推断任何机器都已能跑完管线。

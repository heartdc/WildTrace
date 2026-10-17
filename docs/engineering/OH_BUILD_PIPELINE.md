# OpenHarmony 构建管线（基准环境说明）

> 来源：@AerGap 2026-10-15 环境交接说明（其本机实测口径）。本文件将其固化为仓库内文档，
> 使验证链可交接、可复现；两个本机脚本尚待入库（见"待补齐"节）。

## 基准环境（唯一受认可形态）

- **位置**：WSL Ubuntu 内 `~/oh-full-20261003`（86G，磁盘余量充足）——**不是 Windows 原生**。
  所有构建、验证都在 WSL 内完成；Windows 侧只放 WildTrace 仓库本身。
- **源码**：官方 `repo sync`（gitcode.com/openharmony 远端 manifest，master，471+ 项目）；
  manifests 快照 `0bc9850`（2026-09-29）。`.repo/projects/` 裸仓是构建提交溯源（HEAD）与
  LFS 对象来源。
- **prebuilts**：clang / build-tools / python / rustc / cmake / ark_tools / ohos / cangjie_sdk /
  gcc。AerGap 本机从旧树 `~/oh-real-20260925` 硬链接复用（省 9.9GB+ 下载）；全新部署走
  repo sync + LFS 拉取。

## 构建管线（每组验证同一条链）

```bash
# 1) 环境变量：UV_PYTHON=prebuilts/python，nodejs 进 PATH
# 2) 靶向生成（不做全量镜像）
gn gen out/x86_64_virt --root-target=//<目标>
# 3) 清理 ninja 构建图的重复规则（无此步 ninja 会被 dupbuild 卡死）
python3 sweep_v3.py <target>
# 4) 靶向编译
ninja -C out/x86_64_virt -j 6 <target>
# 5) 真库 malformed 验证
tools/validation_cases/run_malformed.sh
```

**树修改红线**：只允许登记性/环境兼容改动（bundle.json 补注册、设备目录移植、POSIX 脚本
修复、宿主 GCC12 头文件兼容），**不碰任何 FFI 源码**——这是证据可信度的根基。

## 已知坑（按实际踩坑代价排序）

1. **git-lfs 未安装**：日志 `git-lfs: not found` 曾被误判为"资源断供"，实际
   `apt install git-lfs` 即解决（2026-09 实录，耗时两天，PR #98 有记录）。
2. **sweep_v3.py 不在仓库**：位于维护者本机 `~/.cache/`（gitignored）。gen 后直接 ninja
   会被重复规则报错卡死——**这正是 lenovo 机 2026-10-15 全量构建卡在 dupbuild 警告阶段的
   已知原因**（该机另叠加 /mnt/d 的 9P 文件桥性能问题，但"卡住"本身是本坑）。
3. **在 Windows 原生跑 repo/build**：工具链是 Linux 的，必须 WSL 或原生 Linux；从 Git Bash
   驱动 WSL 存在路径改写（`/mnt/c` 被改写为 `C:/…/Git/mnt/c`）与 `$` 变量被外层 shell 吞掉
   的双重问题（lenovo 机实测确认）。
4. **Rust 依赖组件**（av_session 等带 Rust 的目标）：需把 Rust std 的 `.so` 拷入 musl
   sysroot（维护者本机 `fix_rust_std2.sh`，同样未入库）。
5. **授权边界**：执行授权（EXECUTION_AUTHORIZATION.md 附录 A）按机器登记。A-4 覆盖的是
   维护者本机 WSL 构建树；**在新机器（如 lenovo 机）执行构建/验证属新执行面，必须按该文件
   另行走登记，不能默认沿用**。

## 待补齐（阻塞交接的两项）

| 项 | 现状 | 动作 |
|---|---|---|
| `sweep_v3.py` | 维护者本机 `~/.cache/`，gitignored | 需入库（建议 `tools/oh_build/`），否则任何第二环境都无法完成管线第 3 步 |
| `fix_rust_std2.sh` | 维护者本机，未入库 | 同上（Rust 组件目标的前置） |

在两项入库前，**构建/验证只能在已登记的基准环境执行**；lenovo 机的 `D:/oh-full` 树仅作
源码只读参照（L4 对照、行号核验），不执行构建。

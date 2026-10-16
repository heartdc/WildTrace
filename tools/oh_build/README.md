# OH 构建链交接工具（tools/oh_build）

在第二台环境上复刻"官方完整树 → 真库 malformed 验证"管线所需的两个
阻塞脚本与已知坑清单。两脚本此前只在 AerGap 本机 `.cache/`（gitignored），
自本目录入库起为唯一权威版本。

## 管线（四步）

```bash
# 0) 环境（WSL/Linux；Windows 原生不可用，工具链是 Linux 的）
export UV_PYTHON=<oh_root>/prebuilts/python/linux-x86/current/bin/python3
export PATH=<oh_root>/prebuilts/build-tools/common/nodejs/current/bin:$PATH
GN=<oh_root>/prebuilts/build-tools/linux-x86/bin/gn
NINJA=<oh_root>/prebuilts/build-tools/linux-x86/bin/ninja
O=<oh_root>/out/x86_64_virt

# 1) gen（root-target 限定子图，避免触发无关组件）
$GN gen $O --root-target='//foundation/<...>/interfaces/cj:<xxx>_ffi'

# 2) 清图（阻塞交接点 1：见下"已知坑 2"）
python3 tools/oh_build/sweep_v3.py <oh_root> $O <ninja_target_label>

# 3) 构建
$NINJA -C $O -j 6 <ninja_target_label>

# 4) 真库 malformed 验证
bash tools/validation_cases/run_malformed.sh <oh_root> $O <evidence_dir> \
    <client_name> <library_rel>
```

ninja target label 用 `$NINJA -C $O -t targets all | grep <关键字>` 找。

## 脚本

| 脚本 | 用途 |
|---|---|
| `sweep_v3.py` | gen 后清 ninja 图重复规则（自盖章边/跨工具链碰撞/同文件 stamp-vs-real）。探针=对实际目标的 `ninja -n` dry-run |
| `fix_rust_std.sh` | 把 ohos Rust std 的 `.so`（`libstd.dylib.so` 等）拷入 musl sysroot lib 目录。av_session 等带 Rust 组件的目标需要；必须拷真实文件，符号链接不被 `find -type f` 发现 |

## 已知坑（按代价排序，全部实际踩过）

1. **git-lfs 未安装**：日志 `git-lfs: not found` 不是"资源断供"，
   `apt install git-lfs` 即解（PR #98 有完整教训）。LFS tarball 用
   `git lfs fetch -I "<pattern>"` 从裸仓取。
2. **`ninja -t targets all` 探针盲区**：对 root `toolchain.ninja` 内的
   同文件重复规则不报错，真实构建才报——所以 sweep 探针必须是
   `ninja -n <实际目标>`（图解析路径与真实构建一致）。
3. **asmjit/zydis 上游 manifest 缺口**：`third_party/asmjit` 与
   `third_party/zydis` 在全部 11 个 manifest（default/mini/small/codecheck/
   OAT/chromium_deps/llvm*/rust）中均无条目，`repo sync` 在任何机器上都
   拿不到。`arkcompiler/runtime_core/ark_config.gni:48` 上游自注：
   "We don't support x64 compiler in GN build, since asmjit is not available
   here"（`ark_enable_compiler_x64 = false`）。
   **结论：这不是部署操作错误。** 本管线 root-target 子图不触及
   runtime_core static_core 的 x86 AOT/JIT 路径，无需这两个仓；若自行
   扩大构建面（直接编 runtime_core/全量），会撞上该上游已知缺口，且
   GN 路线上游明说不支持，不要在这条路上花时间。
4. **Windows→WSL 驱动**：Git Bash 会吞 `$VAR`、改写 `/mnt/c` 路径；
   非平凡命令一律写成脚本文件经 `bash -lc` 执行。
5. **授权边界**：`EXECUTION_AUTHORIZATION.md` A-4 仅覆盖 AerGap 侧 WSL
   构建树。第二环境执行目标代码前需另行登记授权面。

## 树修改红线

只允许登记性/环境兼容改动（bundle.json 补注册、设备目录移植、POSIX
脚本修复、宿主 GCC12 头文件兼容），**不触碰任何 FFI 源码**——证据
可信度的根基。

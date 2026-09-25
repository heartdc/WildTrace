# OpenHarmony 真实 FFI 构建探测（2026-09-25）

## 当前结论

真实 `libcj_ipc_ffi.z.so` 已在 Linux 本地隔离副本 `/home/airgap/oh-real-20260925` 构建成功，最后一轮 Ninja 退出码为 0。修复隔离基础运行库后，未修改的 IPC 库通过导出符号正常创建、大小查询及字节数组写入/读回检查。KV 库、完整案例运行矩阵和产品验证仍未完成。下面的早期探测记录保留为历史。

## 已生成的 IPC 库及正常启动检查

- 文件：`out/ffi-direct-min/communication/ipc/libcj_ipc_ffi.z.so`。
- SHA-256：`2bccd55caf31989886225f4a5304b41dd1d291251d95dbec670ac19446352d63`。
- ELF：64 位小端 x86-64，DYN，共享库，含调试信息。
- IPC CJ 源码绑定复核：原仓 `interfaces/innerkits/cj` 的 Git 状态干净，该目录与 Linux 隔离副本逐文件比较一致（`diff -qr` 退出码 0）。IPC 仓已观察到的 HEAD 为 `edc6f3ab59a5b6fbbda92c427e1e4da6f6d64ae3`；该检查不替代全部依赖仓版本清单。
- 动态符号已确认包含 `FfiRpcMessageSequenceImplCreate`、`FfiRpcMessageSequenceImplWriteByteArray`、`FfiRpcMessageSequenceImplReadByteArray`。
- 成功日志：`out/ffi-direct-min/build-run7.log`；退出码文件：`build-run7.exit`，内容 `0`。最终步骤为 IPC FFI 库链接。
- 构建产生的 musl 加载器能够显示自身版本（x86_64，1.2.6）。使用同一 sysroot 编译的正常功能调用程序，在首条启动标记输出前退出，退出码 136；还没有证据表明进入了目标功能调用。记录在 `out/ffi-direct-min/evidence/normal-smoke.log` 与 `normal-smoke.exit`。
- 当前结论仅为自定义配置下的真实 IPC 库构建成功；正常运行基线、产品环境与完整依赖集合仍待验证。
- 后续调试已确认正常检查停在 musl 加载器初始化阶段，没有进入调用程序的主函数或 IPC 导出函数。调试记录为 `out/ffi-direct-min/evidence/normal-smoke-startup-backtrace.log`。该启动失败不得归为 IPC 功能问题或已完成的 IPC 运行验证；下一步须解决匹配运行时的正常启动条件。
- 已整理本机构建证据包 `.cache/ipc-ffi-build-evidence-20260925.zip`，31 个条目、622,498 字节，SHA-256 为 `75f5aec74b07a7dbcf5292f299be7f174876f43e8383efe882a989997a557c7e`。包内 IPC 库的摘要已重新核验；包含 IPC 许可证与说明，但不包含完整依赖运行环境，也未对外发送。

### 隔离基础运行库的诊断修复

保留原始 libc、IPC 库与分配器源码后，在 Linux 隔离副本的基础运行库中修复单槽初始化边界，未关闭原有检查选项。精确 libc 目标重建成功。证据目录为 `out/ffi-direct-min/evidence/runtime-init-fix`，包含 `original/`、原始与修复后摘要、`single-slot.patch` 和构建日志。

修复后 libc SHA-256 为 `51403d957a03307e80eebbca82387696bfc3ce5634c7fab74df5e1d01eff304c`；IPC 库摘要仍为本节记录的原值。首次修复后尝试报告 C++ 运行库缺失，退出码 3；补齐官方预置 OHOS x86_64 C++ 运行库搜索路径后，正常检查通过。此前失败记录保存在 `normal-smoke-missing-libcxx.log`，原证据压缩包保持原样。

正常调用结果：

- `normal-smoke.log` / `.exit`：创建对象返回 `object_id=1`，查询得到 `initial_size=0 error=0`，退出码 0。
- `normal-roundtrip.log` / `.exit`：通过真实导出符号写入并读回长度 1、3 和 0 的有效数组，各组 `write_error=0`、`read_error=0`、`matches=1`，最终退出码 0。输入包括正常的正、负及零字节值；此调用器不复制目标实现。
- 调用器源码/二进制与日志摘要在 `normal-roundtrip.sha256`；ABI 来自 CJ 官方头文件，编译使用同一 OHOS x86_64 sysroot。
- 日志中的 HiLog 服务连接告警保留；WSL 当前没有完整产品服务环境。
- Windows 侧证据副本：`.cache/ipc-ffi-normal-runtime-evidence-20260925/`，保留原始产物、运行库补丁和修复后的 libc。
- 已把正常检查客户端和执行入口纳入仓库：`tools/validation_cases/ipc_normal_roundtrip.c`、`run_ipc_normal.sh`，使用说明见同目录 `README_IPC_NORMAL.md`。脚本经语法检查及真实环境端到端执行，构建和运行退出码均为 0，三组数据往返全部匹配；证据位于 `out/ffi-direct-min/evidence/normal-tool-check-20260925/`。脚本要求新输出目录并比较执行前后的 IPC/libc/客户端源码摘要。

结论限定为“修改基础运行库后，原版真实 IPC 库的正常导出符号调用通过”。这不是原版基础运行库验证，也不是官方产品验证；基础运行库修复尚未完成上游发布要求的广泛测试。

## 后续实测：直接目标构建

- 输出目录：`out/ffi-direct-min`。使用官方 GN `--root-target=//foundation/communication/ipc/interfaces/innerkits/cj:cj_ipc_ffi`；该选项覆盖初始 BUILD 文件，不保证只解析一个目标。实测生成 23,135 个目标、读取 1,851 个文件，GN 退出码 0。
- 参数：`target_os="ohos" target_cpu="x86_64" is_standard_system=true support_jsapi=true product_name="x86_64_virt" is_debug=true utils_rust_enable=false`。这是自定义库验证配置，不能用于声称官方产品覆盖；最后一个参数使用 c_utils 已声明的开关关闭可选 Rust 包装目标。
- 生成配置先取 x86_64 产品产物；缺失部件索引从现有生成表及隔离源码真实 `bundle.json` 补齐，包括 components、part_subsystem、parts_path_info、path_to_parts 和 parts_deps。旧 rk3568 表曾用作诊断基础，因此仍须在正式证据封存前审计索引来源、架构标签和可重建性。不得把手工补齐索引称为官方 HB 产品构建成功。
- Ninja 精确目标 `cj_ipc_ffi` 初始约 4,442 项任务，已编译 musl、参数服务、IPC、故障诊断等实际依赖。最终 IPC FFI 库已完成链接，见上节；此前中间依赖库的生成不作为目标完成证据。
- 修复隔离副本中 Windows 检出造成的链接退化：`base/startup/init/services/init/include/init_cmdexecutor.h` 在 Git HEAD 中模式为 120000，却被复制成路径文本；通过原仓 `git archive HEAD <path>` 恢复真正符号链接，没有改接口源码。
- musl 上游 BUILD.gn 明确让 aarch64 与 x86_64 共用 `asm-arm64` UAPI 目录。编译参数为 `--target=x86_64-linux-ohos`；生成 `bits/syscall.h` 的 read/write/open/close 编号为 0/1/2/3。仍需最终 ELF 和运行对照核验。
- 构建命令必须显式把预置 Python 目录加入 PATH。仅在前一个 shell 设置 PATH 不会传给下一次调用。曾建立 `~/.local/bin/python` 和 `python3` 到预置 Python 的链接，属于主机构建辅助配置。
- Ark runtime 生成器缺 Ruby 的失败已识别，并安装 Ubuntu Ruby 包；后续继续同一输出目录增量构建。
- 持久日志位于隔离副本 `out/ffi-direct-min/build-run*.log`，对应 `build-run*.exit` 保存退出码。较早 `/tmp` 日志曾消失，不能作为唯一留存证据；不能仅凭观察超时判断构建失败或成功。

这轮恢复的部分源码提交：selinux `bd0e4b0b6bf80eb50d704d68988741ea3f91f104`、runtime_core `2d60241ed65d61e3bd0587fe673bee867e844960`、ets_frontend `8bf332f42afdf9f28cfae3df69b23d159696d3ae`、linux-5.10 patches `35a50995b2562a337506ea6710499822c2a12c77`。全部通过原本地仓 HEAD archive 写入隔离副本。完整源码清单、配置摘要、目标库符号和匹配运行时结果仍待封存。

## 已核查证据

- 源码根：`C:/Projects/OpenHarmony`。`.cache/oh-real-root-20260922` 的源码目录是 junction，真实路径会回到该原树，不能称为隔离副本。
- 探测期间曾按 `build/core/gn/dotfile.gn` 临时补齐根 `.gn`；修改前的单行文件摘要保存在 `.cache/oh-real-root-20260922/gn.backup-20260925` 及同名 `.sha256`。探测结束后已恢复原文件，当前原始 `.gn` 与备份 SHA-256 均为 `EC6E59E1FC6EF1B037A3D5670653240F82C07129FCA005F4595F73867ED78A84`。
- 预置 GN：`prebuilts/build-tools/linux-x86/bin/gn`，ELF x86-64，GN `1.13.2 (127dd2a6d582)`；Ninja 文件存在，版本输出为 `1.13.2`。
- `rk3568` PRELOAD 已生成到 `out/preloader/rk3568`，配置为 `target_cpu=arm`、`target_os=ohos`，parts 同时包含 `communication:ipc` 与 `distributeddatamgr:kv_store`。
- IPC 目标只有 `support_jsapi=true` 才编译八个真实 CJ 源文件；否则只是空 shared library。
- KV 目标在 `product_name == "ohos-sdk"` 时编译 `kvstoremock/frameworks/cj/distributed_kv_store_mock.cpp`，不能把 SDK 产物作为真实 KV 实现证据。`rk3568` 的非 SDK 分支才使用三个真实 CJ 实现源文件。
- 官方 `build/prebuilts_config.json` 仍声明 Node 14.21.1、OHOS Clang 15.0.4-3f002d_sp1 和 Python 3.12.10 等工具；当前 `prebuilts` 顶层仅发现 `build-tools`，没有这些完整预置目录。

## 实际执行

1. 用临时 `pipes` 兼容模块让 Ubuntu Python 3.14 导入现有 HB；这是运行时 shim，未修改 OpenHarmony 源码。
2. `python3 build/hb/main.py build --product-name rk3568 --build-only-gn true --no-prebuilt-sdk true` 成功进入 PRELOAD，生成新的 `out/preloader/rk3568` 信息；随后在 LOAD 阶段约 5 分钟无新产物，进程等待在跨挂载文件/进程同步，已停止。该次日志和输出保留在 `out/rk3568`，不标为成功。
3. 直接 GN 探测使用 PRELOAD 的 `build_gnargs.prop`、`support_jsapi=true` 和独立输出 `.cache/oh-real-root-20260922/out/ffi-rk3568`。GN 首次因标准 GN 将 `ohos_components_support` 当未使用参数失败；临时移除该行后继续，随后在 `//build/core/gn/BUILD.gn` 因缺少 LOAD 阶段生成的 `out/.../build_configs/BUILD.gn` 失败。之后恢复完整根 `.gn`。

## 真实阻塞与下一步

当前最小可靠路线是：在真正的 Linux 本地文件系统中使用官方 OpenHarmony 预置 Python/Clang/Node/GN，重新运行 `hb ... --build-only-gn`，并把 `build_configs` 生成物放入独立输出；完成后只构建明确的两个 target。由于官方预置工具需要下载或外部准备，且 `rk3568` 产物是 ARM，导出符号 harness 还需要匹配的 OHOS ARM 仿真/设备环境。没有这些条件时，报告必须停留在“真实构建未完成”，不得把等价 harness 升级为真实库证据。

等价 harness 继续作为 `source_equivalent` 基线；IPC/KV case 的 `platform_binary_linked=false`、产品可达性和权限边界未知状态不变。

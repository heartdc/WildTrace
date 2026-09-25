# OpenHarmony 真实 FFI 构建探测（2026-09-25）

## 当前结论

本轮没有生成真实 `libcj_ipc_ffi` 或 `libcj_distributed_kv_store_ffi`，也没有运行 OpenHarmony 目标程序。已完成构建入口、工具和产品配置的直接核查；真实构建仍缺少可用的官方 Python/Clang 预置链，并且当前源码通过 `/mnt/c` 挂载运行 HB 时在 LOAD 阶段出现长时间跨挂载扫描阻塞。

## 已核查证据

- 源码根：`C:/Projects/OpenHarmony`。`.cache/oh-real-root-20260922` 的源码目录是 junction，真实路径会回到该原树，不能称为隔离副本。
- 根 `.gn` 已按 `build/core/gn/dotfile.gn` 补齐；修改前的单行文件摘要保存在 `.cache/oh-real-root-20260922/gn.backup-20260925` 及同名 `.sha256`。当前补齐文件 SHA-256：`F4F622E59A1586E96A50BAC485320F58ADDFD2EA23C1DB6D1168DD221521A537`。
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

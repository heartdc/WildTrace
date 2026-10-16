# A-5 树修改台账（lenovo 机 WSL 自足构建环境）

依据 EXECUTION_AUTHORIZATION.md A-5 登记与 OH_BUILD_PIPELINE.md 红线（只允许登记性/
环境兼容改动，不碰 FFI 源码），以下为 2026-10-16 搭建过程中的全部树修改记录。
基准：gitcode manifest master 全新 repo sync（depth=1），非复制 airgap 树。

| # | 修改 | 类型 | 理由 |
|---|---|---|---|
| 1 | `productdefine/common/inherit/rich.json` 移除 11 个失效组件引用（prebuilt_hap、location_*×6、net_manager、ril_device_driver_interface、startup_l2） | 登记漂移修正 | 上游已改名/下架（location 七件套合并为单组件 "location"；prebuilt_hap 仓 gitcode 403）；当前 master manifest 与 productdefine 自相矛盾，qemu 产品 LOAD 阶段必炸。**保留** toolchain（首次误删已回滚——审计脚本排除目录名 toolchain 的 bug，见 #4） |
| 2 | 24 个仓绕过 repo 直克隆（含 device/qemu、third_party/vk-gl-cts、multimedia_media_foundation 等） | 环境兼容 | repo 2.69 新对象布局下首轮 -j8 同步在 7G 内存机器上 checkout 大面积中断，留下**顶层完整、子目录截断**的半截仓（vk-gl-cts 缺 bundle.json、media_foundation 缺 tests/BUILD.gn）；repo 重试被同坏簿记卡死，direct clone 为等价修复 |
| 3 | `prebuilts/` 按官方 `build/prebuilts_download.sh --build-level L1` 下载（clang/gcc/node/cmake 等 11G）+ 手动补 `ark_tools/ark_js_prebuilts`（330M tarball，含 ets_runtime 依赖的 llvm 头） | 官方部署路径 | 全新部署的标准手段；ark_js_prebuilts 为 src/indep 型不在 L1 基线，ets_runtime 编译必需 |
| 4 | WSL 系统安装 ruby（apt） | 环境依赖 | runtime_core logger_yaml_gen 步骤需 ruby；WSL 内环境项，不涉树 |

未做任何 FFI 源码/组件源码修改。工具链差异：本机 prebuilts ninja 对 dupbuild 默认
ERROR（airgap 主机为 WARN），靶向构建显式 `-w dupbuild=warn`（与该机 hb 调用一致）；
udmf FFI 目标自身边唯一，不受无关重复边影响。

## 过程中发现的两个工具问题（已反馈）

- PR #131 sweep_v3 对含非 UTF-8 字节的 .ninja 崩溃（rust crates 生成物 ×6 文件）——
  已在 PR 评论报告，建议 surrogateescape
- 本仓库审计脚本目录排除列表曾含 `toolchain`，导致 `arkcompiler/toolchain`（组件
  "toolchain" 提供者）被整目录跳过、rich.json 误删后回滚——教训：排除列表应锚定
  顶层路径而非任意层级同名目录

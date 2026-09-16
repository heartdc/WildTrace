# cJSON MergePatch 运行级案例记录

## 结果

在已签署的范围化执行授权和 bubblewrap namespace 约束下，对固定 cJSON 提交
`388cfc96925e4fb41a30735b270736626d26615d` 完成了本地案例运行：

- 隔离检查通过：独立 network/pid namespace、无 `/home` 和 `/mnt/c` 挂载，仅有 loopback；
- LLVM/Clang：22.1.8，版本指纹记录在运行目录；
- 原版构建：成功；
- 独立构建：成功；
- 补丁版构建：成功；
- 原版和独立副本：各 4 次预期 `library_uaf_observed`；
- 补丁及控制组：22 次 `functional_control_passed`；
- 运行矩阵：`passed`，`target_executed=true`；
- 运行目录：`.cache/cjson-runtime-wsl/runtime/acceptance.json`。

## 边界

这是公开已知 cJSON 案例的本地库级运行证据，不是 WildTrace 新发现。产品调用者、
OpenHarmony 产品可达性、设备影响和 CVE/CWE 定稿仍未建立；`product_reachability` 保持
`not_established`，确认产品漏洞数为 0。独立副本使用新构建和新 namespace，但仍由同一操作员和驱动执行，不能替代独立人工复现。

运行记录、sanitizer 输出和环境指纹保留在本地 `.cache`，不进入仓库。运行过程中未修改
原始源码树、未联网、未读取凭据、未执行未经审查的模型代码。

# F 组 Tier B udmf 真库级证实（tag=NULL）+ 旧候选证伪 — 2026-10-09

任务书 F 节 udmf 批量候选（`TASK_IPC_KV_VALIDATION_20260928.md` §F）在官方
完整树构建的真实库上完成验证。结果为**一证一伪**：

1. **旧候选（extras.head 不判空）证伪**——当前快照 `SetDataParameters` 已有
   `head == nullptr || size <= 0 || size > MAX_COLLECTION_SIZE` 前置 return。
2. **新候选（properties.tag 不判空）证实**——`FfiUDMFSetProperties` 对
   `tag=NULL` 的 `CUnifiedDataProperties` 发生 `std::string(nullptr)` 构造，
   `strlen(NULL)` SIGSEGV。**取值自 `FfiUDMFGetProperties` 本身的输出即触发**
   （getter 对空 tag 返回 `nullptr`），getter 输出不是合法 setter 输入，
   round-trip 自毁。

与 PR #97/#98 同树同构建链，授权 A-4（PR #63）覆盖。

## 环境与构建

- 官方完整树 `~/oh-full-20261003`；root-target
  `//foundation/distributeddatamgr/udmf/interfaces/cj:cj_unified_data_channel_ffi`，
  317/317 全绿。
- **ninja 图清障新经验**：`ninja -t targets all` 探针对本树 root
  `toolchain.ninja` 内的同文件重复规则**不报错**，真实构建才报。正确探针是
  **对实际目标的 dry-run**（`ninja -n <target>`，图解析路径与真实构建一致）。
  sweep_v3 以此为探针一轮清完（自盖章边为主）。工具入 `.cache/sweep_v3.py`。

### 构建溯源（工单表单字段）

| 字段 | 值 | 来源 |
|---|---|---|
| udmf 仓构建提交 | `a4882ad72459e9ae7b8373c681c0f4bafab7781f` | `.repo/projects/foundation/distributeddatamgr/udmf.git` 裸仓 HEAD |
| manifest 解析分支 | `master`（gitcode 远端 default revision） | `.repo/manifests/default.xml` |

## 结果（run2，`udmf_null_tag` 客户端，崩溃 case 置尾以获得归因标记）

| case | 输入 | 结果 |
|---|---|---|
| 0（对照） | extras 合法 1 项（I32）， tag=`"rt-tag"` | done，无崩溃 |
| 1（旧候选） | `extras.head=NULL, size=3`，tag 合法 | done，**无崩溃（证伪）** |
| 2（对照） | `extras.head=NULL, size=0`，tag 合法 | done，无崩溃 |
| 3（新候选） | extras 合法 1 项，**`tag=NULL`** | **SIGSEGV**（run_exit=139） |

### 崩溃归因（gdb + 未剥离产物符号化，一次成型）

```
#0  strlen ()
#1  std::char_traits<char>::length (__s=0x0)            char_traits.h:218
#2  basic_string<std::nullptr_t> (__s=0x0)              string:843
#3  FfiUDMFSetProperties (properties=...)               unified_data_ffi.cpp:134
```

- 崩溃点：`foundation/distributeddatamgr/udmf/interfaces/cj/src/unified_data_ffi.cpp:134`
  —— `prop->tag = Utils::MallocCString(properties.tag);`
- 根因链：`Utils::MallocCString` 形参为 `const std::string &`
  （`interfaces/cj/src/utils.cpp:18`），`char* NULL` 隐式构造
  `std::string(nullptr)` → `strlen(NULL)`。调用帧偏移 `0x1716f`
  （`libcj_unified_data_channel_ffi.z.so` 内，BASE `0x7ffff7bc0000`）。
- **round-trip 论据**：`FfiUDMFGetProperties`（同文件）对空存储 tag 返回
  `ret.tag = Utils::MallocCString(uni->tag)` → `nullptr`（MallocCString 对
  空 std::string 返回 nullptr）。即 getter 的合法输出直接喂回 setter 必崩。
- 符号化方法：gdb 内嵌 python 解析 `info proc mappings` 取库基址，
  `add-symbol-file lib.unstripped/... -o BASE` 后 bt——避免手工偏移算错。

### run1（`udmf_null_extras` 旧客户端）发现记录

run1 全部 case 的 tag 均为 NULL，case 0（合法对照）即崩——正是 run1 的
"对照崩溃"反常暴露了 tag 路径缺陷，驱动 run2 的矩阵重设计。run1 原样入包。

## 判读

- **真库级证实**：case=3 崩溃、case 0/2 对照干净、case 1 证伪旧候选——缺陷
  精确限定于 `tag == NULL`，与 extras 内容无关。
- 类型码勘误：`I32_TYPE=0`（`unified_data_parameter_parse.cpp:34`）；
  run1 客户端注释误写 `1`（实为 I64_TYPE），run2 已修正。结构体布局与
  `unified_data_impl.h` 逐字段核对一致，排除 ABI 错位解释。
- 库指纹：sha256
  `773867c9d7c381f8e323943f7920e5f7ca1c477c182c47e36949fa313213ee59`，
  BuildID `30239ec8b295bffe351d1c437d2aa1cf`，42 个 `T` 导出符号
  （`FfiUDMF*`）。
- 红线：隔离环境（bwrap）、无产品服务、自定义 x86_64_virt 构建配置。

## 证据包

`udmf-evidence-20261009.zip`（sha256
`a70accc94eefb4467d434a220b39cf39c78d35f35614e67d8cbc4a61faea14df`）：
run1 + run2 完整 evidence 目录（含 gdb-backtrace.txt）+ MANIFEST。

## 后续

- 候选升级（case.json + 工单，含 backtrace）按 E 组先例走 lenovo 侧任务书
  D 节流程；修复建议：`FfiUDMFSetProperties` 对 `properties.tag` 判空
  （`tag != nullptr ? Utils::MallocCString(...) : 空串语义`），或
  `MallocCString` 增加 `const char*` 判空重载。

## 边界

- 单库单入口（`FfiUDMFSetProperties`/`FfiUDMFGetProperties` 对）；udmf 其余
  FFI 导出未展开，按台账另行排批。
- x86_64_virt 跨平台构建 + musl 加载器运行；真机行为以工单侧复核为准。

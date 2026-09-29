# 真实 OpenHarmony 二进制可达性验证

静态命中和等价 ASan harness 只能证明代码形状存在。要把候选升级为真实二进制证据，需要完成下面三层绑定。

## 1. 绑定目标库和导出符号

构建完整 OpenHarmony 产品或组件后，确认目标库来自本次源码快照，并检查导出符号：

```sh
readelf -Ws out/<product>/生效路径/libcj_ipc_ffi.so | grep FfiRpcMessageSequenceImplWriteByteArray
readelf -Ws out/<product>/生效路径/libcj_distributed_kv_store_ffi.so | grep FfiOHOSDistributedKVStoreSingleKVStorePutBatch
sha256sum out/<product>/生效路径/libcj_*_ffi.so
```

`BUILD.gn` 已显示：

- IPC 目标：`foundation/communication/ipc/interfaces/innerkits/cj: cj_ipc_ffi`，源文件包含 `ipc_ffi.cpp` 和 `message_sequence_impl.cpp`；
- KV 目标：`foundation/distributeddatamgr/kv_store/interfaces/cj: cj_distributed_kv_store_ffi`，源文件包含 `distributed_kv_store_ffi.cpp` 和 `distributed_kv_store_impl.cpp`。

如果符号不存在，说明目标产品没有包含该 FFI 库，不能声称调用可达。

## 2. 在同一进程调用导出入口

IPC CJ FFI 的最小调用链不需要远程服务：

```text
FfiRpcMessageSequenceImplCreate()
→ FfiRpcMessageSequenceImplWriteByteArray(id, {data=null, len=1}, &err)
→ CJ_WriteByteArray()
```

控制组必须包括 `{data=null, len=0}` 和一个有效单字节数组。预期修复后的行为是返回参数错误，进程保持存活；当前候选的等价 harness 观察到 ASan 零地址 SEGV。

KV FFI 需要先建立真实句柄：

```text
FfiOHOSDistributedKVStoreGetSingleKVStore(...)
→ 返回有效 store id
→ FfiOHOSDistributedKVStoreSingleKVStorePutBatch(id, {head=null,size=1})
```

需要使用独立数据库目录和最小合法 `AppId/StoreId`。同时运行空数组、负数 size、有效单元素三组控制，记录返回值、信号和 ASan 栈。

## 3. 证明支持调用者和权限边界

二进制崩溃还不等于平台漏洞。需要继续确认：

- Cangjie/FFI 绑定是否把这些 C ABI 导出给普通应用；
- 调用者是否能构造 `data/head=null` 和任意 `len/size`；
- 目标库运行在哪个进程、UID 和沙箱权限下；
- 崩溃影响调用进程、系统服务还是仅测试进程；
- 同一输入在无 ASan 的发布构建中是否仍可重复。

只有目标库符号、支持调用链、稳定崩溃和影响边界都绑定到同一源码/构建快照，才能把候选升级为真实 OpenHarmony 漏洞报告。否则保持 `candidate/undetermined`。

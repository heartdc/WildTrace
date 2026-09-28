# FFI 边界审计（2026-09-22）

新增 `wildtrace-ffi-boundary` 离线规则，扫描 OpenHarmony C/C++ 源码中的“结构体裸指针字段 + size/length 字段 + 成员索引”组合。规则只产生 `candidate`，不执行目标代码、不调用模型，也不把 `guard_hint` 当成安全证明。

对 `C:\Projects\OpenHarmony-complete` 的 3,901 个 C/C++ 文件运行后得到 86 条分组候选。当前 KV 组件命中：

- `distributed_kv_store_impl.cpp:379`：`cArrEntry.head[i]`
- `distributed_kv_store_impl.cpp:428`：`cArrStr.head[i]`
- `distributed_kv_store_impl.cpp:537`：`cArrStr.head[i]`
- `distributed_kv_store_impl.cpp:1149`：`cArrStr.head[i]`

这些候选与 `kv-ffi-array-validation` 的 ASan 等价复现一致。其他命中需要根据真实对象类型、调用者和所有权逐条复核；同名字段可能来自不同结构体，因此扫描结果是工作队列，不是漏洞数量。

专项实现测试：4 passed。完整项目回归仍以现有 855 tests passed 记录为基线；本轮新增规则只重复执行了必要的专项测试和一次全树扫描。

# KV FFI 隔离验证提示词

在独立进程中验证 OpenHarmony 分布式 KV 的 FFI 数组输入校验。只调用 `FfiOHOSDistributedKVStoreSingleKVStorePutBatch`、`FfiOHOSDistributedKVStoreSingleKVStoreDeleteBatch` 及必要的合法初始化接口，依次测试合法单元素、`head=null,size=1`、`head=null,size=-1` 和空数组。启用 AddressSanitizer 或等价崩溃检测，记录返回值、退出信号和完整栈。使用独立测试数据库，不连接外部设备、不读取生产数据、不提交网络请求。验证结论只描述输入校验和可重复性；只有链接到真实 OpenHarmony 二进制并确认调用者可达后，才允许升级为平台漏洞候选或进入修复/披露决策。

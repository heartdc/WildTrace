# OpenHarmony IPC 深审记录（2026-09-22）

本记录对应 `.cache/triage-complete-20260922.json` 中的 IPC 人工复核候选。状态只表示当前审计进度，不表示漏洞确认。

## 已核查路径

### `foundation/communication/ipc/interfaces/innerkits/cj/src/message_sequence_impl.cpp`

`CJ_ReadByteArray`、`CJ_ReadShortArray`、`CJ_ReadIntArray`、`CJ_ReadLongArray` 及浮点数组读取函数都先读取数组长度，再调用 `CheckReadLength`，随后分配并按元素读取。`CheckReadLength` 会检查当前位置、剩余字节数以及 `arrayLength * typeSize`，长度来自 `uint32_t`，在当前目标平台的 `size_t` 上不会发生乘法截断。

`CJ_ReadStringArray` 和 `CJ_ReadRemoteObjectArray` 的检查粒度比实际分配对象小：前者按 4 字节元素检查但按指针大小分配，后者按 4 字节检查但分配 4 字节和 8 字节两组数组。当前证据更接近资源消耗和协议健壮性问题，尚未形成越界读写；需要结合 MessageParcel 最大容量和调用方权限继续确认。

### `foundation/communication/ipc/ipc/native/c/manager/src/serializer.c`

`ReadBoolVector`、`ReadInt16Vector`、`ReadInt32Vector` 等路径对元素数量执行 `MAX_IO_SIZE / sizeof(element)` 检查。`ReadInt8Vector` 和 `ReadUInt8Vector` 没有同样的显式上限判断，但乘法因子为 1，最终通过 `IoPopUnaligned` 读取剩余缓冲区；在当前静态证据下只能列为边界检查一致性候选，不能直接认定整数溢出或越界。它们应作为下一轮代码修复候选，统一和其他标量向量使用相同的上限策略。

### `foundation/communication/ipc/ipc/native/c/rpc/ipc_adapter/*`

DBinder 会对会话名长度检查后再执行 `len + 1` 分配，服务名结构体容量为 `SERVICENAME_LENGTH + 1`。当前发现的加一运算有明确的长度上限或来源为本地 `strlen`，未确认可控溢出。

## 当前结论

- 已确认漏洞：0
- 仍需人工复核：IPC 数组协议长度与 `MessageParcel` 容量关系、`ReadInt8Vector` 的统一上限策略、远程对象数组的资源消耗上限。
- 下一轮优先方向：检查 `ReadStringArray`/`CJ_ReadRemoteObjectArray` 的最大消息限制和权限边界，再检查分布式 KV 的相同长度模式是否存在未复用 `CheckReadLength` 的实现。

所有条目保持 `candidate`/`undetermined` 状态，未执行目标程序，也未生成 PoC 或漏洞确认报告。

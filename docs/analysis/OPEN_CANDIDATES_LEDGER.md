# 开放候选台账（回放验证浮出的未修复站点）

来源：三轮严格修复对验证（GT1 88b2edee / GT2 100402f0 / GT4 窗口对照）发现的
修复未覆盖站点。这些不是误报——扫描器判定与代码形态一致，修复确实没碰这些函数。

## 代理侧 RegisterObserver（12 站点，GT4）

`frameworks/inner/ipc/src/bluetooth_*_proxy.cpp` 的 `RegisterObserver` 对
`const sptr<I...Observer>& observer` 直接调 `observer->AsObject()` 无判空。
上游修复 432c8b3e 只给 inner/src 侧加了检查，代理侧始终未修。

| 文件 | 函数 | 形态 |
|---|---|---|
| bluetooth_a2dp_sink_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_a2dp_src_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_avrcp_ct_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_avrcp_tg_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_hfp_ag_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_hfp_hf_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_hid_host_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_host_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_map_mse_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_opp_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_pan_proxy.cpp | RegisterObserver | observer->AsObject() |
| bluetooth_spp_proxy.cpp | RegisterObserver | observer->AsObject() |

## hid_host 修复后残留（11 站点，GT1）

修复 88b2edee 只给 SetConnectStrategy 加了检查，以下函数仍有 unguarded
`proxy->` 解引用（`sptr<> proxy = GetRemoteProxy(...)` 局部变量）：

| 函数 | 变量 | 形态 |
|---|---|---|
| RegisterObserver | observer | param sptr, AsObject() |
| DeregisterObserver | observer | param sptr, AsObject() |
| HidHostGetReport | proxy | local sptr, 多次解引用 |
| HidHostSetReport | proxy | local sptr |
| HidHostGetSnoopReport | proxy | local sptr (如存在) |
| HidHostSetSnoopReport | proxy | local sptr |
| GetDeviceState | proxy | local sptr |
| Connect | proxy | local sptr |
| Disconnect | proxy | local sptr |
| GetConnectionDevices | profile | local sptr |
| SetConnectionStrategy | profile | local sptr |

## bluetooth_socket 修复后残留（6 站点，GT2）

修复 100402f0 只给 Connect 加了 pimpl 检查，以下函数仍有 unguarded：

| 函数 | 变量 | 形态 |
|---|---|---|
| GetRemoteDevice | pimpl | member, 1 deref |
| Unmarshalling | codecData | local, deserialization |
| DeregisterServerObserver | observer | param sptr |
| RegisterClientObserver | observer | param sptr |
| DeregisterClientObserver | observer | param sptr |
| RegisterServerObserver | observer | param sptr |

## 可达性裁定（2026-10-17，29 站点全部完成）

分析基线：`wt_btpre`（bluetooth @ 59cac79b）+ `/home/beichen/oh` 全量树中的
bluetooth_service master（gitcode @ 2e9e230）。方法：逐一追踪每个站点的全部调用方，
核对传入值的构造方式与判空守卫；仓库外调用方用全量树 grep（`GetRemoteProxy<IBluetooth`
/ `iface_cast<IBluetooth` / `RegisterObserver`）穷尽。

### 结论一：29 个台账站点全部 null 不可达，不具备工单价值

| 组 | 裁定 | 依据 |
|---|---|---|
| 代理侧 12 站点（RegisterObserver） | null 不可达 | 全部调用方在 `frameworks/inner/src/*` profile impl 内，observer 均为自建：throwing `new`（host/hid_host/opp/pan/hfp_ag）→ 非空；`new(std::nothrow)`（a2dp_snk/a2dp_src/avrcp_tg/map_mse）→ 均有 `CHECK_AND_RETURN` 且在 `RegisterFunc` 注册回调**之前**，null 时回调不注册；hfp_hf 传 `&serviceObserver_`（成员地址）恒非空。仓库外零调用方：location/call_manager/audio_hal 持有代理但不调 RegisterObserver |
| hid_host 11 站点 | 实质不可达 | 当前树外层 `HidHost::*` 方法全部 `CHECK_AND_RETURN_LOG_RET(proxy != nullptr)`；impl 层残留的 `Set/GetConnectStrategy` 无守卫，但外层包装已先验 proxy 非空（仅存外层取proxy→impl再取proxy 的 TOCTOU 窄竞态，且崩溃在应用自身进程）；observer 参数 = `innerObserver_`（throwing new）非空 |
| socket 6 站点（框架侧） | null 不可达 | `pimpl` 为构造函数 throwing `new` 初始化；`DeregisterClientObserver` 调用点（bluetooth_socket.cpp:107-116）proxy 与 observerImp_ 均判空；`observerImp_` 由 `Init()` 内 `new(std::nothrow)` + 使用前判空 |

### 结论二：分析过程中发现服务端新缺陷——工单候选 #19

`bluetooth_service`（系统进程）socket 服务端 `DeregisterServerObserver` 链路存在
**无权限要求的空指针解引用**，与 ipc/hiappevent 两张已提交工单同类（应用可达的
系统服务 SIGSEGV）：

```
bluetooth_socket_stub.cpp:38   {STUB_FUNC(DEREGISTER_SERVER_OBSERVER,
                                  DeregisterServerObserverInner, nullptr)}
                               ↑ 权限项 nullptr = 无权限要求（对比 CONNECT/LISTEN
                                 均要求 USE_BLUETOOTH + ACCESS_BLUETOOTH）
bluetooth_socket_stub.cpp:121-126  iface_cast(data.ReadRemoteObject()) 后无判空
                                  （同文件 RegisterClientObserverInner:133-145 三个
                                  参数全部判空，形成修复模式对照）
bluetooth_socket_server.cpp:52-55  socketObserverList_->RemoveObserver(
                                  observer->AsObject())  ← 空指针解引用点
```

攻击链：任意应用经 SAMGR 取蓝牙 socket SA 代理 → `SendRequest(DEREGISTER_SERVER_OBSERVER,
不含 observer 远端对象的 Parcel)` → 无权限拦截 → `ReadRemoteObject()` 返回空 →
服务端 `observer->AsObject()` SIGSEGV。同文件 `Listen`（server 侧 45 行）对
`param.observer` 判空后使用，可作修复参照。

注意：服务端 `DEREGISTER_CLIENT_OBSERVER` 分发实现为空操作（stub 直接回
`BT_NO_ERROR` 不读 Parcel），故仅 Server 侧这一条可走。

### 遗留事项

- [x] #19 候选运行时 PoC（2026-10-17 完成）：官方完整树靶向构建 `libbluetooth_server.z.so`，
      PoC 以攻击者形态 Parcel（正确 token + 省略 observer）驱动真实
      `BluetoothSocketServer::OnRemoteRequest(DEREGISTER_SERVER_OBSERVER)` →
      **exit 139（SIGSEGV）**，符号化归因 `bluetooth_socket_server.cpp:54:51`
      （`observer->AsObject()`）。一键复现：`tools/validation_cases/run_bt_dereg.sh`。
      证据包：`D:/cve_data/bt_server_dereg_observer/`（TICKET_DRAFT + evidence 16 项 +
      双版本修复补丁）
- [x] 上游核验：gitee master 服务端无守卫代码仍在（`observer->AsObject()` 原样），
      但 memberFuncMap_ 重构后 `DEREGISTER_SERVER_OBSERVER` 被二次赋值为
      `DeregisterClientObserverInner`（疑似 `DEREGISTER_CLIENT_OBSERVER` 键名手误），
      IPC 入口被意外掩盖——缺陷仍在，入口待上游修复键名后即恢复可达。报障版本：
      官方树 2e9e230（分发链完整）。gitcode master raw 不可达（返回门户页），待人工复核。

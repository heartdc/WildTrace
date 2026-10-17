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

## 下一步

- [ ] 代理侧 12 站点：调用方可达性分析（谁调 RegisterObserver？能否传 null？）
- [ ] hid_host 11 站点：同上（GetRemoteProxy 可返回 null 已由同文件 CHECK 证实）
- [ ] socket 6 站点：pimpl 构造函数证据核查
- [ ] 可达性确认后决定是否走工单（第 19-21 张）

# CJ FFI 数组转换族清扫报告（2026-09-28，第一线）

模式来源：IPC/KV 两个新发现候选的共同形态——FFI 边界 {指针,长度} 结构进无检查循环。
方法：manifest 全仓枚举（496）→ blobless 并行探测（63 仓有 CJ 源面）→ 类型自举
（26 种 CJ 数组结构）+ 函数级模式扫描（cjffi_scan.py，491 个 cj 源文件）。
输出 37 条 lead（32 条 NULL+长度双缺），**内置验证：扫描器独立复现已知 KV 候选
（distributed_kv_store_impl.cpp:374 CArrayEntryToEntries，案例记录 373/378 行）**。

## 候选分层（L4 初步追链后）

- **Tier A（同仓同族，链最短）**：kv_store 同文件另有 3 个同型转换——
  `CArrStrToVectorKey:424` / `CArrStrToVectorString:533` / `CArrayStrToVectorString:1144`
  （head[i] 无 NULL/无长度检查循环，与已受理候选完全同型）
- **Tier A-（导出链已闭合，且多一档负长度 UB）**：multimedia_av_session 9 个
  Inner* 转换——`FfiMultimediaAVSessionController*` 导出函数直接把 `CParameters*`
  透传进无检查链；其中 `InnerSetWantParamsArrayInt:167` 为
  `std::vector(intArr, intArr + head->size)` 负 size 迭代器下溢 UB（NULL 走另分支）
- **Tier B（跨仓克隆族）**：account_os_account / udmf / av_session 三仓存在同名
  `InnerWrapWantParams*`/`SetDataParameters` 拷贝族——任一成立则全族成立
- **Tier C**：bluetooth `CheckBleScanParams`、relational_store `CArrStrToVector`、
  graphic_2d `FfiEffectKitCreateColorPickerRegion`(CArrDouble)、webview 等（见附表）

## 下一步

1. Tier A/A- 逐条人工 L4 补完（调用链终态 + 触发前提）——本机 1 天
2. 交原构建机真库验证（与 IPC/KV 任务书同流程：av_session/kv_store 追加构建目标）
3. 证实者按新发现提交工单（先于官方修复，有提交窗口）

## 附：全量 lead 表

# CJ FFI 数组转换模式清扫——分诊报告（2026-09-28）

扫描范围：64 仓 / 491 个 cj 源文件；自举类型 26 种；lead 37 条（缺双检 32 条）。

内置验证：kv_store `CArrayEntryToEntries:374` = 已知 KV 候选（373/378 行）被扫描器独立复现 OK

> lead != 漏洞：需人工 L4 追 FFI 入口调用链，确认导出函数层无前置校验。

## multimedia_av_session（9）
- `frameworks/cj/src/cj_avsession_utils.cpp:149` `InnerSetWantParamsArrayString`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:167` `InnerSetWantParamsArrayInt`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:184` `InnerSetWantParamsArrayBool`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:201` `InnerSetWantParamsArrayDouble`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:274` `InnerSetWantParamsHashMap`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:290` `InnerWrapWantParamsString`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:308` `InnerWrapWantParamsT`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:437` `InnerWrapWantParamsFd`(CParameters) — NULL+长度双缺
- `frameworks/cj/src/cj_avsession_utils.cpp:498` `InnerWrapWantParamsArrayFd`(CParameters) — NULL+长度双缺

## account_os_account（5）
- `frameworks/appaccount/cj/src/appaccount_parameter_parse.cpp:163` `SetDataParameters`(CArrParameters) — NULL+长度双缺
- `frameworks/appaccount/cj/src/appaccount_parameter_parse.cpp:232` `InnerWrapWantParamsString`(CParameters) — NULL+长度双缺
- `frameworks/appaccount/cj/src/appaccount_parameter_parse.cpp:247` `InnerWrapWantParamsT`(CParameters) — NULL+长度双缺
- `frameworks/appaccount/cj/src/appaccount_parameter_parse.cpp:355` `InnerWrapWantParamsFd`(CParameters) — NULL+长度双缺
- `frameworks/appaccount/cj/src/appaccount_parameter_parse.cpp:372` `InnerWrapWantParamsArrayFd`(CParameters) — NULL+长度双缺

## notification_common_event_service（5）
- `interfaces/kits/cj/src/parameter_parse.cpp:161` `SetDataParameters`(CArrParameters) — NULL+长度双缺
- `interfaces/kits/cj/src/parameter_parse.cpp:233` `InnerWrapWantParamsString`(CParameters) — NULL+长度双缺
- `interfaces/kits/cj/src/parameter_parse.cpp:249` `InnerWrapWantParamsT`(CParameters) — NULL+长度双缺
- `interfaces/kits/cj/src/parameter_parse.cpp:363` `InnerWrapWantParamsFd`(CParameters) — NULL+长度双缺
- `interfaces/kits/cj/src/parameter_parse.cpp:380` `InnerWrapWantParamsArrayFd`(CParameters) — NULL+长度双缺

## distributeddatamgr_udmf（4）
- `interfaces/cj/src/unified_data_parameter_parse.cpp:183` `ParseParameters`(CArrParameters) — 缺长度检
- `interfaces/cj/src/unified_data_parameter_parse.cpp:67` `InnerWrapWantParamsString`(CParameters) — NULL+长度双缺
- `interfaces/cj/src/unified_data_parameter_parse.cpp:83` `InnerWrapWantParamsT`(CParameters) — NULL+长度双缺
- `interfaces/cj/src/unified_data_parameter_parse.cpp:158` `SetDataParameters`(CArrParameters) — NULL+长度双缺

## distributeddatamgr_kv_store（4）
- `frameworks/cj/src/distributed_kv_store_impl.cpp:374` `CArrayEntryToEntries`(CArrEntry) — NULL+长度双缺
- `frameworks/cj/src/distributed_kv_store_impl.cpp:424` `CArrStrToVectorKey`(CArrStr) — NULL+长度双缺
- `frameworks/cj/src/distributed_kv_store_impl.cpp:533` `CArrStrToVectorString`(CArrStr) — NULL+长度双缺
- `frameworks/cj/src/distributed_kv_store_impl.cpp:1144` `CArrayStrToVectorString`(CArrStr) — NULL+长度双缺

## hiviewdfx_hiappevent（2）
- `frameworks/cj/ffi/src/appevent_watcher_impl.cpp:31` `FreeCArrParameters`(CArrParameters) — 缺长度检
- `frameworks/cj/ffi/src/hiappevent_ffi.cpp:139` `AddParams2EventPack`(CArrParameters) — NULL+长度双缺

## window_window_manager（2）
- `interfaces/kits/cj/display_runtime/cj_display_manager.cpp:34` `SetDisplayObject`(RetStruct) — 缺长度检
- `interfaces/kits/cj/display_runtime/cj_display_manager.cpp:226` `SetDisplayPhysicalResolutionObject`(RetStruct) — NULL+长度双缺

## multimedia_player_framework（1）
- `frameworks/cj/metadatahelper/src/cj_avmetadataextractor.cpp:55` `CreateCustomInfo`(CCustomInfo) — 缺长度检

## resourceschedule_work_scheduler（1）
- `interfaces/kits/cj/work_scheduler/work_scheduler_ffi.cpp:479` `g_convertToCArrParameters`(CArrParameters) — 缺长度检

## communication_bluetooth（1）
- `frameworks/cj/ble/src/bluetooth_ble_impl.cpp:221` `CheckBleScanParams`(CArrNativeScanFilter) — NULL+长度双缺

## distributeddatamgr_relational_store（1）
- `frameworks/cj/src/relational_store_utils.cpp:520` `CArrStrToVector`(CArrStr) — NULL+长度双缺

## graphic_graphic_2d（1）
- `interfaces/kits/cj/effect_kit/effect_kit_ffi.cpp:135` `FfiEffectKitCreateColorPickerRegion`(CArrDouble) — NULL+长度双缺

## web_webview（1）
- `interfaces/kits/cj/src/webview_message_ffi.cpp:512` `FfiOHOSWebMessageExtImplSetArrayDouble`(CArrDouble) — NULL+长度双缺

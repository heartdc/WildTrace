#!/usr/bin/env python3
"""One-shot Gap-B backfill: distill trigger/attack/reproduction material from
the submitted bounty forms (D:/cve_data/submission_*) into cases/*/case.json.

Run from repo root:  python tools/backfill_gap_b.py
Idempotent: only sets fields that are absent. Honesty rule preserved —
source-level cases say source-level; runtime cases cite the observed matrix.
"""
import json
from pathlib import Path

CASES = Path(__file__).resolve().parent.parent / "cases"

TRIGGER = {
    "cjson_merge_alias":
        "patch 参数为待合并 target 的内部子节点（如经 cJSON_GetObjectItem(target, k) 取出的子树），"
        "cJSON_Delete(target) 先释放含 patch 的整树、cJSON_Duplicate(patch) 随后读取已释放节点；"
        "配置合并/动态 patch 类业务以取自 target 的节点为 patch 即触发，上游公告标注远程可发起。",
    "curl_native_ca_reuse":
        "同一主机先后两次 HTTPS 请求间混用 CURLSSLOPT_NATIVE_CA 开关（默认 CA → NATIVE_CA 或反向）；"
        "该选项仅 Schannel/GnuTLS 等特定 TLS 后端支持，运行级复现需对应后端环境"
        "（Linux 最小构建不触发，本案如实申报为源级）。",
    "ffmpeg_cfhd_transform2_width_oob":
        "带超宽 lowpass_width 的 CFHD transform-2 码流：cfhd.c:969/1010 两处平面尺寸校验"
        "未约束 lowpass_width*2 ≤ s->plane[plane].width，探测阶段即可触发堆越界写。",
    "ffmpeg_iamf_count_label_dos":
        "IAMF mix_presentation OBU 的 count_label 为极大 leb128 值（2^32-1 量级）而实际剩余载荷远小："
        "iamf_parse.c:864 读取后无 count_label > len - avio_tell(pbc) 校验直接 av_calloc。",
    "ffmpeg_rscc_short_deflate_uninit_leak":
        "RSCC 流 zlib 分支解压输出短于帧需求（len < pixel_size）：rscc.c 无尾部清零，"
        "帧尾保持未初始化（上游 cd1f545c/a5fe21a1 以 memset 补零修复）。",
}

ATTACK = {
    "cjson_merge_alias":
        "业务 JSON 处理路径调用 cJSONUtils_MergePatch 且 patch 来源于 target 内部子树："
        "攻击者构造 JSON 文档诱导业务以'取自 target 的子节点'为 patch 发起合并 → UAF；"
        "实际影响取决于调用方使用方式与堆布局。",
    "curl_native_ca_reuse":
        "应用在不同请求间对同一主机混用 NATIVE_CA 设置：OH 检出连接匹配逻辑未比较 native_ca_store"
        "（grep 零出现；上游 vtls_config.c:144 已修），第二个请求复用既有连接，"
        "证书校验语境与请求方指定 CA 来源不一致。",
    "curl_psl_supercookie":
        "目标使用 libcurl 且启用 USE_LIBPSL+cookie 引擎，访问主机名恰为公共后缀的服务端点"
        "（localhost 类本地服务/特殊内网域）；攻击者控制该主机响应下发 "
        "Set-Cookie: Domain=<公共后缀主机名> → cookie 以 .主机名 通配域入库，"
        "对同后缀任意子域可注入/读取（会话固定/跨子域跟踪），不直接代码执行。",
    "ffmpeg_cfhd_transform2_width_oob":
        "产品用 ffmpeg 解复用/探测不可信媒体（CFHD 系码流）：攻击者提供构造码流即触发越界写，"
        "无需特权，应用自动处理不可信输入时无需用户交互。",
    "ffmpeg_iamf_count_label_dos":
        "产品用 ffmpeg 解复用/解析不可信 IAMF 音频流（媒体处理服务、文件探测）："
        "攻击者提供构造 OBU → 巨量分配 → 内存耗尽拒绝服务。",
    "ffmpeg_nvdec_sep_ref_doublefree":
        "NVIDIA 平台产品用 ffmpeg NVDEC 硬解且码流走独立参考帧路径：攻击者以 crafted 视频流"
        "耗尽 decoder surface 池命中 sep_ref 错误分支（nvdec.c:612-616 goto fail）→ "
        "fail 标签对已移交 FrameDecodeData 的 cf 二次释放（double free）。",
    "ffmpeg_rscc_short_deflate_uninit_leak":
        "产品用 ffmpeg 解码不可信屏幕捕获视频（远程支持/录屏处理场景）："
        "攻击者提供短 deflate 输出的构造 RSCC 流 → 解码帧尾泄露未初始化堆内存。",
}

REPRO = {
    "cjson_merge_alias":
        "运行级（ASan）：OH third_party_cJSON 未改动源，clang -std=c11 -g -O1 "
        "-fsanitize=address,undefined 编译 poc_mergepatch.c；./poc_orig trigger → ASan "
        "heap-use-after-free READ size 4（释放点 cJSON.c:277，读点 cJSON.c:2802，退出码 1）；"
        "应用 patch.diff 重建重跑 → CASE_DONE（退出码 0）；control（独立 patch）两侧正常。"
        "2×2 矩阵记录见提交材料 submission_87933。",
    "curl_native_ca_reuse":
        "源级三侧对照（无运行级 PoC，如实申报）：a) 上游 curl master vtls_config.c:144 连接比较"
        "含 native_ca_store；b) OH 检出 grep -rn native_ca_store 仅 setopt.c 两处赋值与 urldata.h "
        "字段定义，连接匹配零出现；c) 官方受影响清单含 8.8.0（OH 快照基线）。"
        "运行级复现路径：Windows+Schannel 下同主机两请求切换 CURLSSLOPT_NATIVE_CA，"
        "CURLINFO_NUM_CONNECTS 观测复用差异。",
    "curl_psl_supercookie":
        "源码等价运行级（curl-8.8.0，OH lib/cookie.c 与其逐文件 diff 84 行等价）："
        "./configure --without-ssl --with-libpsl && make -C lib；clang -fsanitize=address,undefined "
        "-I<curl>/include poc.c <curl>/lib/.libs/libcurl.a -lpsl -lpthread -o probe；"
        "./probe psl-supercookie：原版 tailmatch=1（域字段 .localhost，漏洞行为）→ 应用 patch.diff "
        "重建 → tailmatch=0（修复生效）；non-psl-control 对照两侧均 1（无回归）。",
    "ffmpeg_cfhd_transform2_width_oob":
        "源级三侧对照：a) 上游 db05df9d/16b2049d 修复 diff（上游样本名 "
        "cfhd_transform2_output_width_oob.avi）；b) OH 检出 cfhd.c:969/1010 均无 "
        "lowpass_width*2 校验（修复前形态）；c) 与上游 n7.1.1 逐字节一致、官方清单含 7.1.1，"
        "两 diff 对 OH 检出 git apply --check 通过。运行级路径：按样本构造码流 ASan 构建下观测越界写。",
    "ffmpeg_dvbsub_parser_capacity_overflow":
        "源级三侧对照（运行级需构造使守卫溢出的 WTV/传输流输入，如实申报）：a) 上游 93f2a525 改写守卫；"
        "b) OH dvbsub_parser.c:106 仍为修复前三数相加形态；c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1，"
        "diff git apply --check 通过。运行级路径：可控尺寸 DVB 字幕流送入解析器观测 packet_buf 越界写。",
    "ffmpeg_floodfill_point_stack_oob":
        "源级三侧对照（同族运行级证据见 66036/66041 两案）：a) 上游 24c322fd 修复（样本名 "
        "8aj_floodfill_dynamic_size.pgm）；b) OH vf_floodfill.c 点栈分配仍在 config_input、"
        "filter_frame 使用帧尺寸；c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1。"
        "运行验证尝试如实记录：GRAY8 直连 graph 多组参数（512²/8192²/1x1→64²）未触发 ASan——"
        "7.1.1 分配含 4 倍余量，按上游样本构造非均匀图案拉满 DFS 栈深为后续路径。",
    "ffmpeg_hqdn3d_dynamic_size_oob":
        "运行级（ASan）：./poc_orig：buffer→hqdn3d→buffersink，第 1 帧 64x64 排空后直推 512x512 帧 → "
        "ASan heap-buffer-overflow WRITE size 2（写点 denoise_spatial vf_hqdn3d.c:98，越界 "
        "config_input 分配的 128 字节行缓冲末尾，退出码 1）；git apply patch.diff 重建 → "
        "变尺寸帧被拒绝（'Frame size changed without filter graph reinitialization'，修复生效，退出码 0）；"
        "control（两帧均 64x64）两侧正常（无回归）。",
    "ffmpeg_iamf_count_label_dos":
        "源级三侧对照：a) 上游 8670835 修复 diff；b) OH iamf_parse.c:864 无剩余字节校验；"
        "c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1、diff git apply --check 通过。"
        "运行级路径：构造极大 count_label 的 mix_presentation OBU，ulimit -v/容器内存上限下观测瞬时 OOM。",
    "ffmpeg_lcldec_zlib_tail_disclosure":
        "源级三侧对照（运行级需构造解压后短于帧尺寸的 LCL/ZLIB 流，如实申报）：a) 上游 e7cbfd1c "
        "两处返回路径补 memset；b) OH lcldec.c 两处均为修复前形态；c) 与 n7.1.1 逐字节一致、"
        "官方清单含 7.1.1、diff git apply --check 通过。运行级路径：膨胀输出小于帧期望尺寸的 zlib 流，"
        "MSan 观测输出帧未初始化字节。",
    "ffmpeg_nvdec_sep_ref_doublefree":
        "源级三侧对照（运行级需 NVIDIA GPU+NVDEC 环境，如实申报）：a) 上游 4c621747 修复 diff；"
        "b) OH nvdec.c:599 起 612-616/624-626 为修复前形态；c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1。"
        "运行级路径：--enable-cuda-nvcc 构建下 H.265 多参考帧流+低 surfaces 配置耗尽池，"
        "ASan/Valgrind 观测 nvdec_fdd_priv_free double-free。",
    "ffmpeg_quirc_resize_oob":
        "运行级（ASan）：./poc_orig linkgrow：buffer(gray8 64x64)→quirc→buffersink，第 1 帧排空后"
        "将 link 尺寸置 512x512（模拟重协商半途/上游直改 link），再推 512x512 帧 → ASan "
        "heap-buffer-overflow WRITE 512（quirc_resize 分配的 4096 字节缓冲末尾，写点 vf_quirc.c:102）；"
        "git apply upstream_fix_4da9812.diff 重建 → CASE_DONE；control 与 trigger-不变-link 对照两侧正常。",
    "ffmpeg_rscc_short_deflate_uninit_leak":
        "源级三侧对照：a) 上游 cd1f545c/a5fe21a1 修复（上游样本名 rscc_short_deflate_heap_disclosure）；"
        "b) OH rscc.c deflate 分支无 len<pixel_size 清零；c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1、"
        "diff git apply --check 通过。运行级路径：合法但短的 deflate 输出，MSan 观测 uninit 或对比零填充差分。",
    "ffmpeg_swaprect_temp_row_oob":
        "源级三侧对照（同族运行级证据见 66036/66041）：a) 上游 a7e38b61 修复（样本名 "
        "7aj_swaprect_odd17_nv12.nut——NV12 奇数 17 宽）；b) OH vf_swaprect.c:223 仍为首平面单因子分配；"
        "c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1。运行级路径：NV12+奇数宽+swaprect 参数覆盖色度平面，"
        "ASan 观测行交换路径 heap-buffer-overflow。",
    "ffmpeg_ty_ac3_trim_underflow":
        "源级三侧对照：a) 上游 de771bd5 修复 ty.c demux_audio 下溢；b) OH ty.c:576 仍为 pkt->size -= 2；"
        "c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1、diff git apply --check 通过。"
        "运行级路径：按上游样本 ty-s2-ac3-negative-size-single-file.ffconcat 构造"
        "（Series2 AC3 TY 流，ac3_pkt_size 累计逼近 768 且末包 size≤1），ASan/Valgrind 观测 negative-size-param。",
    "ffmpeg_wmaenc_extradata_padding":
        "源级三侧对照（运行级需下游按填充读 extradata 的路径，如实申报）：a) 上游 23227a44 补齐两处"
        "extradata 分配填充；b) OH wmaenc.c encode_init（约 67/74 行）仍为 av_malloc(4)/av_mallocz(10)；"
        "c) 与 n7.1.1 逐字节一致、官方清单含 7.1.1、diff git apply --check 通过。"
        "运行级路径：WMAV1/WMAV2 编码初始化后，ff_wma_init 等按填充读 extradata 的消费侧 ASan 观测越界 READ。",
    "openssl_ocb_oneshot_iv_discard":
        "运行级：./poc_orig：同一 (key, iv) 下 body 分别经 EVP_Cipher()（one-shot）与 "
        "EVP_CipherUpdate/Final（streaming）加密——S1（无 AAD，one-shot 为首次数据调用）原版 ct=DIFF "
        "tag=DIFF（one-shot 实际以 nonce-0 加密、丢弃调用方 IV）；S2（AAD 先 streaming）原版 SAME"
        "（佐证机理：仅 one-shot 为首次数据调用时 IV 被丢弃）；应用 patch.diff 重建 → 两场景全 SAME（修复生效）。",
    "hiappevent_ffi_watcher_null_filter":
        "真库运行级：libcj_hiappevent_ffi.z.so（官方完整树构建，sha256 bf8aa65e...f6636a，BuildID "
        "252096ef）dlopen 驱动 poc_hiappevent_watcher.c：case0 对照（合法 head, size=1）→ 错误码 "
        "11101001 不崩溃；case1（head=NULL, size=1）→ SIGSEGV（退出码 139）；两轮 ASLR gdb 复现 "
        "rip 落库内 file_offset 0x11c9a。完整记录 hiappevent-evidence-20261003.zip（sha256 a8ae123d...13c7a6）。",
    "ipc_cj_array_null_validation":
        "真库运行级：libcj_ipc_ffi.z.so 隔离构建 x86_64（IPC HEAD edc6f3ab，CJ 绑定与原仓 diff -qr 一致）"
        "dlopen 驱动 ipc_null_bytearray.c：对照（data=NULL len=0）→ write_error=0 正常返回；"
        "候选（data=NULL len=1）→ 立即 SIGSEGV（run.exit=139）；两次 ASLR gdb 复现 rip 落库内 "
        "file_offset 0x1ed9b。记录 docs/analysis/IPC_KV_REAL_LIBRARY_VALIDATION_20260928.md（PR #65）。",
    "kv_ffi_array_validation":
        "等价运行级（WSL Clang 21.1.8 ASan/UBSan，驱动 kv_null_entry.c）：两条转换路径 null head "
        "均 zero-page SEGV，对照组正常；未做真库链接（如实区分等价级与真库级）。",
    "udmf_ffi_setproperties_null_tag":
        "真库运行级：libcj_unified_data_channel_ffi.z.so（官方完整树构建，317/317 全绿，sha256 "
        "773867c9...213ee59）dlopen 驱动 tools/validation_cases/udmf_null_tag.c：case0-2 对照/证伪 "
        "不崩（含旧候选 extras.head=NULL 证伪）；case3（tag=NULL）→ SIGSEGV（run.exit=139）；"
        "gdb add-symbol-file 符号化 #0 strlen → #3 FfiUDMFSetProperties（unified_data_ffi.cpp:134）。"
        "evidence zip sha256 a70accc9...14df（run1+run2+MANIFEST）。",
}

TRIGGER_NATIVE = {
    "hiappevent_ffi_watcher_null_filter":
        "仓颉侧经 HiAppEvent 打点 API 注册 watcher 时，appEventFilters（CArrAppEventFilter）的 "
        "head 为 NULL 而 size > 0 的畸形组合进入嵌套过滤循环被直接解引用；"
        "对照组合法输入由 FFI 层参数校验拦截（错误码 11101001 不崩溃）。",
}

BRANCH_EVIDENCE = {
    "hiappevent_ffi_watcher_null_filter": {
        "master": {
            "verdict": "affected",
            "source_commit": "de94cb4d53f94afdbc75a5a7c46401f99bdcf17f",
            "reference": "docs/analysis/HIAPPEVENT_REAL_LIBRARY_CONFIRM_20261003.md（PR #97；"
                         "真库 sha256 bf8aa65e30c13782f54fa56b6d5e273a36425555865125a9bea6222943f6636a，"
                         "证据包 hiappevent-evidence-20261003.zip）",
        }
    },
    "ipc_cj_array_null_validation": {
        "master": {
            "verdict": "affected",
            "source_commit": "edc6f3ab",
            "reference": "docs/analysis/IPC_KV_REAL_LIBRARY_VALIDATION_20260928.md（PR #65；"
                         "隔离构建与原仓 diff -qr 一致，gdb 两轮 ASLR 复现 rip 落库内）",
        }
    },
}


def apply(case: str, fields: dict) -> bool:
    path = CASES / case / "case.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    changed = []
    for key, value in fields.items():
        if not record.get(key):
            record[key] = value
            changed.append(key)
    if changed:
        path.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n",
                        encoding="utf-8")
    return bool(changed), changed


def fields_for(case: str) -> dict:
    fields = {}
    if case in TRIGGER_NATIVE:
        fields["trigger_conditions"] = TRIGGER_NATIVE[case]
    elif case in TRIGGER:
        fields["trigger_conditions"] = TRIGGER[case]
    if case in ATTACK:
        fields["attack_path"] = ATTACK[case]
    if case in REPRO:
        fields["reproduction_commands"] = REPRO[case]
    if case in BRANCH_EVIDENCE:
        fields["branch_evidence"] = BRANCH_EVIDENCE[case]
    return fields


def main():
    total = 0
    for case in REPRO:
        ok, changed = apply(case, fields_for(case))
        total += len(changed)
        print(f"{'OK ' if ok else 'skip'} {case}: {','.join(changed) if changed else '-'}")
    print(f"backfilled fields: {total}")


if __name__ == "__main__":
    main()

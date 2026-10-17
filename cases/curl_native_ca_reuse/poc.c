/*
 * CVE-2026-80231 运行验证 PoC — third_party/curl HTTPS 连接复用未校验
 * NATIVE_CA 设置差异（weaker CA-store context 复用）
 *
 * 等价性：OH third_party_curl(f044ac3ac9, 8.8.0 快照) 的连接复用比较
 * match_ssl_primary_config()（lib/vtls/vtls.c:176）枚举了其余全部
 * ssl_primary_config 字段而独缺 native_ca_store（setopt.c 两处赋值、
 * urldata.h 字段定义均在，比较点零出现——见 case.json gap_evidence）。
 * 上游 master vtls_config.c:144 已补该字段比对；官方受影响版本清单含
 * 8.8.0。
 *
 * 触发原理：同一 easy handle 先后两次请求同一 HTTPS 主机，第二次翻转
 * CURLSSLOPT_NATIVE_CA。缺陷版：两条连接被判"配置相同"而复用——第二次
 * 请求在比其请求更弱的 CA 存储上下文中完成证书校验；修复版：配置不同
 * 不复用、重建连接。
 *
 * 用法：./poc_curl_native_ca [https-url]（默认 https://www.openharmony.cn）
 *
 * 判读（需 CURLSSLOPT_NATIVE_CA 生效的 TLS 后端：Windows/Schannel 或
 * GnuTLS 构建；Linux+OpenSSL 构建该选项不生效，程序会如实提示）：
 *   打印每次请求的 CURLINFO_NUM_CONNECTS：
 *     req1(default CA)      = 1 新建（两版一致）
 *     req2(翻转为 NATIVE_CA)= 0 复用（缺陷观测）/ = 1 重建（修复版）
 *     req3(control 同选项)  = 0 复用（两版一致，无回归）
 *
 * 环境门槛（如实申报）：报告方 Linux 最小构建无对应后端，不能触发运行级
 * 观测，本案以源级三侧对照申报（见 case.json）；本 PoC 提供该路径的完整
 * 可执行验证程序，供具备 Schannel/GnuTLS 环境的复核方一键运行。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

static size_t drop(char *ptr, size_t size, size_t nmemb, void *ud)
{
    (void)ptr; (void)ud;
    return size * nmemb;
}

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1] : "https://www.openharmony.cn";
    const curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
    printf("case=curl_native_ca backend=%s version=%s\n",
           vi->ssl_version ? vi->ssl_version : "none", vi->version);

    CURL *curl = curl_easy_init();
    if (!curl) return 3;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, drop);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    long steps[3] = {0, CURLSSLOPT_NATIVE_CA, 0};
    const char *labels[3] = {"req1_default_ca", "req2_native_ca_flipped", "req3_default_ca_control"};
    int failed = 0;
    for (int i = 0; i < 3; i++) {
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, steps[i]);
        CURLcode rc = curl_easy_perform(curl);
        long connects = -1;
        if (rc == CURLE_OK)
            curl_easy_getinfo(curl, CURLINFO_NUM_CONNECTS, &connects);
        else
            failed = 1;
        printf("case=curl_native_ca %s rc=%d(%s) num_connects=%ld\n",
               labels[i], (int)rc, curl_easy_strerror(rc), connects);
    }
    curl_easy_cleanup(curl);
    if (failed)
        printf("判读提示：存在失败请求——若 backend 为 OpenSSL 系则 NATIVE_CA 不生效，"
               "运行级判读需 Schannel/GnuTLS 环境（见文件头）；网络不可达同样会失败\n");
    return 0;
}

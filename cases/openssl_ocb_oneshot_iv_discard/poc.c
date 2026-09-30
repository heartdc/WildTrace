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

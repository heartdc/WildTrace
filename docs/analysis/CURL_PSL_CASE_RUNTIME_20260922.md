# curl PSL supercookie 运行级验证记录 — 2026-09-22

## 结论

CVE-2026-82209 的漏洞行为在等价代码上获得运行级观测，修复有效性同步验证。
矩阵 2×2 全部符合预期：

| 模式 | 原版 | +窄化补丁 |
|---|---|---|
| psl-supercookie | tailmatch=1（漏洞观测） | tailmatch=0（修复生效） |
| non-psl-control | tailmatch=1 | tailmatch=1（无回归） |

## 等价性依据（为何在上游 8.8.0 上验证）

OH 的 third_party_curl 工作树无法用上游 autoconf 构建：文件为多上游时代混搭
（doh.c 需 Curl_dyn_addn 而 dynbuf.c 为旧命名；request.c 存在但陈旧 Makefile
与 BUILD.gn 各执一词；curl_ntlm_wb.c 被删而 Makefile 仍引用）——仅 OH 自家
GN+SDK 工具链可编译（本机无 OHOS SDK）。

因此采用等价性路线：**OH lib/cookie.c 与上游 curl-8.8.0 逐文件 diff 共 84 行**，
差异为尾点修剪加固与少量格式差异；**两侧的 PSL 检查块同样缺少 tailmatch 清除
逻辑（即漏洞结构等价）**。验证在上游 8.8.0 发行版 tarball（自洽可构建）上进行，
窄化补丁（上游 95c1e891 核心五行）对两个上下文同样适用。

## 环境

- WSL Ubuntu 24.04（第二复现人环境，附录 B-2 登记待补）；clang 18.1.3；
  ASan+UBSan；仅回环网络（进程内 socket 服务器 + CURLOPT_RESOLVE）；libpsl 0.21.2。
- 构建：./configure --without-ssl --with-libpsl + 禁用全部无关协议。
- PoC：cases/curl_psl_supercookie/poc.c（公开 API；修正了对照模式的 host 选择）。

## 观测语义

CURLINFO_COOKELIST 的 Netscape 行域名字段前导点 = tailmatch。漏洞形态：
恶意服务器对 PSL 域主机（如 localhost）设置 Domain=该主机的 cookie，
被以 tailmatch 接受 => 匹配该后缀全部子域（supercookie）。修复后：接受但
tailmatch 被清除（仅精确主机匹配）。

## 边界

- 上游等价代码上的库级验证；OH 树直译构建受阻（GN 依赖），等价性以 diff 为证。
- 产品可达性 not_established；奖励计划提交由所有者人工执行。
- OH master 的缝隙窗口：上游修复 2026-08-28，OH 快照 20260819，未见回移提交。

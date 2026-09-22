# curl PSL supercookie 案例（CVE-2026-82209）— 中间形态第一案

**性质**：公开已知 CVE 在 OH master 的修复缝隙（非新发现）；依据
`docs/analysis/CURL_MIDDLEFORM_VERIFY_20260921.md` 的四层核验。

## 期望矩阵

| 构建 | psl-supercookie 模式 | non-psl-control 模式 |
|---|---|---|
| OH 原版（f044ac3） | `tailmatch=1`（**supercookie 被接受**，漏洞观测） | `tailmatch=1`（正常） |
| OH + patch.diff | `tailmatch=0`（supercookie 拒绝，修复生效） | `tailmatch=1`（**不得回归**） |
| psl-reject 对照（Domain=com 对 x.example.com） | 两版均拒绝（既有行为不变） | — |

机器信号：`CURLINFO_COOKIELIST` 输出的 Netscape 行首域名字段——前导点 =
tailmatch（`.localhost` 即漏洞形态）。PoC 以 `CASE_OK <mode> tailmatch=<0|1>`
输出结果，退出码 0/1/2 分别为符合预期/违反预期/传输错误（2 永不作判读）。

## 构建与运行（WSL/Linux，bubblewrap 内同 cJSON 案例）

```
# 前置：libpsl-dev；OH curl 树在 /src（只读）
clang -std=c99 -g -fsanitize=address,undefined -DUSE_LIBPSL \
  -I/src/include -I/src/lib -I/src <curl 源清单编译为静态库后> \
  /out/poc.c <libcurl.a> -lpsl -lm -o /out/probe
/out/probe psl-supercookie     # 原版期望 tailmatch=1；补丁版期望 0
/out/probe non-psl-control     # 两版均期望 1
```

注意：完整 libcurl 构建较 cJSON 重（建议用 OH 树自带构建脚本或最小化
`--disable-<多数协议> --with-libpsl` 配置）；harness 双删除等 cJSON 案例的
纪律同样适用（本 PoC 无显式清理钩子，cookie 引擎随 easy handle 结束）。

## 案例文件

- `case.json`：pin OH commit + cookie.c 摘要 + 上游修复/回归测试引用 + 对照组
- `poc.c`：公开 API、仅回环网络、单文件单线程服务器
- `patch.diff`：对 OH 旧结构的窄化适配（上游第二处防御性重排未纳入，见 notes）

## 边界

库级验证，产品可达性 not_established（OH 产品的 libcurl cookie 使用面待分析）；
提交奖励计划由所有者人工执行。

## 提交记录

- **2026-09-21 已提交**：工单号 **OHSA26-092226014**（submissionId
  228159005971714048，账号北辰522，状态"已提交"）。表单要点：类型=信息与
  隐私泄露类/敏感信息泄露；文件路径=lib/cookie.c / 代码行:1049；引入点
  =c140bd78（2016-03-02，`git log -S` 考证）；附件 5 件打包。提交文案存于
  `D:\cve_data\submission_82209\奖励计划表单v2_82209.md`。
- 下一步：跟进平台审核状态；第二案 CVE-2026-80231 文案已备好待提交。

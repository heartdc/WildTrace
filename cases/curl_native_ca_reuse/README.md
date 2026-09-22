# curl native CA 连接复用案例（CVE-2026-80231）— 中间形态第二案

**性质**：公开已知 CVE 在 OH master 的修复缝隙（非新发现）；与
CVE-2026-82209 同一缝隙窗口（上游 20260819 快照，2026-08 下旬修复批次
未回移）。**验证级别：源码级**（运行级复现需 Schannel/GnuTLS 后端，
报告时如实申报）。

## 证据三角

1. **上游已修**：master `lib/vtls/vtls_config.c:144` 连接配置比较含
   `(c1->native_ca_store == c2->native_ca_store)`。
2. **OH 缺失**：`lib/vtls/vtls.c:176` `match_ssl_primary_config()`
   逐字段比较清单枚举了其余全部字段，唯独无 `native_ca_store`
   （合法出现仅 setopt.c 赋值、urldata.h 定义、后端握手读取）。
3. **官方受影响清单含 8.8.0**（OH 快照版本基线）。

## 复核

`D:\cve_data\submission_82209\复核脚本_80231.sh <OH-curl根>` 一键判读
（已在 f044ac3 检出实测：比较缺失 → 缺陷结构成立）。

## 提交记录

- **2026-09-21 已提交**：工单号 **OHSA26-092209031**（submissionId
  228161199659814912，账号北辰522）。类型=组件通信与逻辑类（子类型
  留空，四个选项均不匹配 CWE-488）；文件路径=lib/vtls/vtls.c /
  代码行:176；引入点=148534db（2019-09-13，git -S 考证）。
- 与 82209（OHSA26-092226014）构成同窗口姊妹案，可互相引用跟进。

## 边界

源码级验证；实际可利用性取决于产品是否对同一主机混用 NATIVE_CA
设置。表单/附件文案存于 `D:\cve_data\submission_82209\`。

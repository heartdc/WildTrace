# WildTrace 本地演示流程

所有命令仅处理用户授权的本地源码和结果文件；不执行目标程序、不扫描网络。

1. 安装：`python -m pip install -e . --no-deps`
2. 扫描：`wildtrace <source_root> --output scan.json`
3. 证据校验：`python -m ohvul.verify scan.json`
4. 分支影响比较：`wildtrace-impact base.json revised.json`
5. 联合验证：`verify-joint checkpoint.json scan.json harness.json`
6. 合成性能基准：`wildtrace-perf --files 10 --lines 20`

候选数量、行哈希一致和性能结果不构成漏洞确认。影响报告和审核批次始终保留人工审核要求。不要将 API key、真实敏感数据或攻击载荷放入演示材料。

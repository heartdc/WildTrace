# WildTrace 本地演示流程

所有命令仅处理用户授权的本地源码和结果文件；不执行目标程序、不扫描网络。

1. 安装：`python -m pip install -e . --no-deps`
2. 扫描：`wildtrace <source_root> --output scan.json`
3. 证据校验：`python -m ohvul.verify scan.json`
4. 分支影响比较：`wildtrace-impact base.json revised.json`
5. 联合验证：`verify-joint checkpoint.json scan.json harness.json`
6. 合成性能基准：`wildtrace-perf --files 10 --lines 20`

候选数量、行哈希一致和性能结果不构成漏洞确认。影响报告和审核批次始终保留人工审核要求。不要将 API key、真实敏感数据或攻击载荷放入演示材料。

## WSL Clang 引擎候选扫描

适配器使用用户本地 WSL 中的 LLVM Clang Static Analyzer。单文件扫描：

```text
python -m ohvul.engine_cli <source-file> --source-root <source-root> --output engine.json
python -m ohvul.engine_cli <source-file> --source-root <source-root> --profile camera_app_engine_profile.json --output engine.json
```

显式文件清单扫描：

```text
python -m ohvul.engine_cli --files-from files.txt --source-root <source-root> --output engine.json
```

`files.txt` 每行一个相对源码根目录的路径；空行和 `#` 注释会被忽略。可选的本地知识库匹配必须同时提供：

```text
python -m ohvul.engine_cli <source-file> --source-root <source-root> \
  --knowledge-base local-kb.json --component <name> --version <version>
```

输出状态 `completed`、`partial` 和 `input_error` 分别表示完成、部分文件完成和输入上下文不可用。所有引擎结果都是 candidate；缺少构建头文件时不能解释为“未发现漏洞”。

## 候选评测

人工标注模板位于 `docs/design/engine_benchmark_template.json`。完成授权源码复核并填充快照摘要、组件、版本、CWE 和审核信息后，使用：

```text
wildtrace-engine-benchmark cases.json engine-result.json
```

评测器只输出候选级 TP/FP/FN、precision 和 recall；未完成人工复核的模板不能作为真实准确率依据。

也可以从保存的 schema 0.3 结果生成待复核草稿：

```text
wildtrace-engine-benchmark --bootstrap-output cases.json \
  --source-snapshot <sha256> --component <name> --version <version> engine-result.json
```

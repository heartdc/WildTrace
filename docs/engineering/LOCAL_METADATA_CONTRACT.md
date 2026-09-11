# 本地漏洞元数据匹配契约

## 输入与执行

CLI 可用 --vuln-db 指定本地 JSON 数组。每条记录必须包含非空字符串 id 和 component，version 为字符串或 null。畸形记录报错并停止，不静默丢弃。支持 UTF-8 BOM；无需网络。

## 决策

- 组件名采用不区分大小写的精确相等，没有模糊别名或生态推断。
- 双方版本均存在且字符串相等：matches 队列，match_status=exact_version_candidate。
- 目标或记录版本缺失、空白、unknown、unspecified、星号：unresolved 队列，match_status=unknown。
- 双方版本存在但不相等：不匹配该精确记录，不代表组件安全。
- 不推测通配符、版本范围或回移植补丁。相同版本也只能得到候选，仍需代码确认。

## 证据及兼容

matches 和 unresolved 都携带 evidence_id，CLI 汇总两个队列的证据。记录摘要包含原始记录对象以及匹配状态；校验器核对元数据 ID、CWE、摘要和完整来源记录；数据库数组摘要和来源标识也进入 EvidenceBundle。仍未保存数据库文件字节快照或数字签名。原有 JSON 顶层格式 0.3 保留，unresolved 为新增字段，消费方需显式读取。

## 测试与恢复

python -m unittest discover -s tests -v：11 项通过，包括未知版本、缺失版本、版本不同、损坏记录的负例。数据库文件字节摘要和输出覆盖保护已实现；下一步处理 FSM。未执行目标代码或生成载荷。

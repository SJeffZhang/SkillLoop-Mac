# Markdown 工具协议修复（2026-10-01）

补充 M6 保留两项 submitted 不完整结果：build_artifact 的 expected_version=1 违反 const 0；publish_artifact 的 artifact_digest 少一位。原始证据、配置和槽位不变。

本次将模型可见工具 schema 对齐实际协议：仅 build_artifact 固定 expected_version 为 0；validate/prepare/publish 的 artifact_digest 要求 sha256: 加 64 位小写十六进制，并提示逐字复制工具返回值。write_artifact 的版本比较语义保持原样。未放宽权威校验，未自动纠正模型参数。

两项新增回归测试先失败后通过；12 项相关测试通过。此修复验证工具定义，尚未证明模型运行改善。模型可能仍生成无效参数；正式实验需要新冻结配置和独立证据，不能覆盖旧结果。

# 正式资格存储 v2（源码修复，未运行验收）

完整 EvaluationAttestation、suite/plan、运行清单及逐任务审查引用只写入 Gate UID 21005 的私有目录与数据库。Controller 可读数据库只保存当前 campaign/source/config/generation 绑定、逐 subject 汇总判定、原 issued_at/expiry、资格凭据引用和批准绑定，不保存私有矩阵。

发行前重新计算实际评估记录的 Gate 与 RequiredRunManifest，并要求独立归档审查和当前 Proxy source 准入。先持久保存私有证明，再发布公开资格；发布中断后重复发行只能使用原证明和原 UTC，不续 TTL。消费持有实际 issuer 数据库只读事务及当前 Proxy 授权 guard，核对期限、撤销、来源与身份；Registry CAS 在此期间提交。

新正式部署使用 schema v2 的新数据目录。已有非空旧资格库不自动迁移、覆写或升级资格。源码检查通过不表示资格生命周期或完整项目已验收；尚未启动整轮实验。

# 最终 campaign Gate 生产调用（源码连接，未运行验收）

统一调度器在当前 Registry 私有 scope 下创建实际 Gate worker，先登记完整辅助成本和角色创建成本，再把实际 SpendingLedger 的一致读取结果交给 Gate。Gate 只在专属只读挂载中解析完整私有 Factory 与 session 库；Controller 不读取保护任务矩阵。

Gate 重新核对原名单、开发执行清单、实际模型生命周期、所有保护 session、逐任务 Evaluator/Gate/ArchiveGate、当前 source/批准、原时钟与已消费/未消费完整预算。根据这些事实重建 GateContext、CaseResult、RequiredRunManifest 和 GateResult。只有可发行的完整证据才调用 v2 资格发行器。原始 CIResult 与完整链留在 Gate 私有目录，公开结果只有冻结 PublicReport 与最小阶段完成信息；Reporter 读取 Gate 生成的真实报告。

尚未执行 Gate、发行资格或启动整轮。正式配置生成、依赖镜像锁、证据容量集成、加密归档恢复以及冻结规范/权限阻断仍待闭合。冻结 CLI 的 CIResult 与保护可见性要求还需要独立核对；不会将私有 suite/plan 或逐题结果直接交给 Controller 来凑齐 CLI 输出。

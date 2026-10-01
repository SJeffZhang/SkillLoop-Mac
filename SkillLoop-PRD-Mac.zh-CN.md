# SkillLoop Mac 实验 PRD

版本：Mac V1 · 2026-10-01 · 基础协议：API 4 / V2.2。

## 1. 目标与适用范围

本仓库 `SJeffZhang/SkillLoop-Mac` 是 `JiahaoTanXX/SkillLoop` 的 fork，用于记录 MacBook Pro（M5 Pro、48 GB）上的独立实验。DGX 的比赛成果与公网展示继续保留；DGX 历史模型结果不计入 Mac 模型配置的验收次数。

本文件是 [V2.2 PRD](SkillLoop-PRD-v2.2.zh-CN.md) 的 Mac 部署补充：业务契约、API 4 对象、四态判定、原始证据要求与独立 Gate 语义继续适用。涉及部署模型、工作负载隔离及资源预算时，以本文件和 [Mac 运行配置](specs/mac/runtime-profile.json) 为准。V2.2 的 DGX 部署规格及其摘要保持原样。

## 2. 已确定的部署方案

- 模型：macOS 原生 Ollama，使用 Metal 与 `qwen3.8:27b-mxfp8`，关闭 thinking，16K 上下文。每场实验固定版本、模型 manifest、tokenizer、template、采样参数与配置摘要。
- 容器：Docker Desktop ARM64 Linux VM。每个 agent 运行实例新建容器、独立工作卷与运行身份，不复用可写工作区。容器停止后，先一致性导出和核验，再清理临时状态。
- 权威状态：Proxy 与 SQLite 在 VM 内部私有卷；agent 不挂载数据库、完整历史库、题库、Docker socket 或宿主个人目录。
- 输入：保护阶段只提供当前实例的 Skill、输入和受限任务接口；业务发布由 Proxy 校验身份、任务绑定与授权。
- 网络：agent 与 scanner 使用独立网络命名空间，默认 `--network none`，仅经 VM 内受限 Unix socket 访问所需服务。只有受信模型 bridge 可连接 Mac Ollama；不向 agent 开放 Ollama 模型管理接口。
- 权限：非 root、独立 UID、只读 rootfs、零 capabilities、禁止提权、seccomp、独立 PID 命名空间；对 CPU、内存、进程数、临时空间、队列和磁盘设置显式预算。
- 模型状态：模型权重可以只读共享。开发与保护阶段使用独立服务生命周期、缓存和私有日志目录；切换阶段时停止服务并确认卸载，避免把新 agent 容器误当作模型缓存隔离。

Mac 配置不要求 AppArmor，也不增加 Ubuntu VM。容器提供经测试的进程、文件与接口隔离；多个容器仍共享 VM 内核，不能声称“完美隔离”或满足原 DGX 的 AppArmor 验收项。内核漏洞、恶意宿主管理员及硬件侧信道不在本轮实验的保护结论范围内。

## 3. 隔离准入与运行证据

正式保护测试前必须证明：

1. 不同运行的容器不能读取彼此工作卷、私有日志、题库与权威 SQLite。
2. 跨运行的 socket、run ID、任务 ID、grant 与旧凭据不能被复用；Proxy 通过内核 peer UID 与任务绑定拒绝越权。
3. agent 无直接外网或模型管理路由；受限 relay 只开放所需接口，实施请求大小、次数和超时限制。
4. agent 容器中仅有当前实例输入；factory 与 Gate 的私有卷不挂入 runtime 或 scanner。
5. 开发与保护模型生命周期切换、取消、重启和归档可从原始证据复核。
6. 三 profile 的实际工具序列、拒绝后恢复、最大输入、usage、峰值内存、时延及预算均有实测。

新建容器本身不是准入证据。未实施或未验证的项保持 pending；不足的单次结果为 inconclusive，确认失败始终保留。

## 4. 结果继承与实验顺序

M0–M5 继承 DGX 历史身份，不重新请求模型。M6 保存的候选、载荷、正常对照与确认失败作为新实验输入；同一配置已完成运行不覆盖、不重复计数。新 Mac 配置有自己的 campaign、deployment epoch 与运行账本。

| 阶段 | 工作与出门条件 |
| --- | --- |
| M6 | 复用候选与历史，按订单 42、退款 66、Markdown 48 次配对计划执行；先完成 scanner、预算与配置准入，再由独立 Mac Gate 复算。总计 156 次是待准入的新配置计划。 |
| M7 | 为合格 profile 建新私有 epoch；submitted 与 finalist 共用同一套件，每例三次，完成隔离证据、四态 Gate、attestation 与脱敏报告。 |
| M8 | 在 `SJeffZhang/skillloop-ci-test` 仅用合成 Skill，允许同一账户 `SJeffZhang` 创建测试仓库、分支或可用 fork 并提交 PR；通过 GitHub App 验证精确 SHA Checks、force-push、重复事件、配置变化、旧 worker 与续评。另一账户不是本地 Mac M8 的准入条件。真实 GitHub 运行证据不足时保持 pending；跨账户 fork 权限隔离单列为未验证，不阻断同账户范围验收。 |
| M9 | 三 profile 各完成完整 campaign 与需求验收索引，分别给出工程与业务结论。 |
| M10 | 对证实攻击做修补前后配对；演练取消、备份恢复、归档、磁盘与队列容量。恢复产生新 deployment epoch 并撤销旧资格。 |

每阶段冻结源码和配置后才执行正式模型调用。报告列出完整、不完整、确认失败和实际尝试数；业务改善只有在攻击效果减少且正常业务不退化时才能声明。

## 5. 仓库与证据保存

Git 保存源码、PRD、配置、脱敏报告和进度摘要。`local-data/`、模型、原始攻击 trace、题库、SQLite/WAL、密钥与个人环境配置不进入 Git。私有证据保留摘要清单、一致性备份和只读历史快照；报告更新不会修改 DGX 旧结论。

## 6. 当前状态

以下为截至 2026-10-01 的验证记录，不代表 M6–M10 已验收：

- DGX 全量导入：36,307 文件、17 个链接、593 个 SQLite 一致性备份已核验。
- 选定历史 M6 批次的 136 次实际尝试已逐运行独立复算，零复算错误、零模型调用；其中 132 次完整、8 次确认失败（两个维度可重叠）。这不是完整历史 M6 Gate 重验。
- Ollama 0.33.3 和 1,209 个模型 manifest/blob 条目已核验；模型 manifest 为 `464021588235c36e23bd48a480c6c306ed1fc1e0619e97998267494a1be68de4`。
- 三 profile 工具/拒绝恢复及约 14.3K 输入检查通过。完整 VM 正常业务诊断：订单、退款通过；Markdown 有模型参数错误的未完成尝试。
- 正式 M6 镜像 Linux 合约测试执行 194 项，4 项跳过、零失败；所有 agent 正式运行使用 network none、新容器和私有卷。
- Mac M6 已执行 156 次：154 项完整、2 项协议错误不完整。订单 Gate 通过并冻结；退款和 Markdown 因配对证据不完整为 inconclusive。原始 Skill 共 16 次确认失败，候选无确认失败。
- 订单 M7 已执行 24 次：23 项完整、1 项镜像权限错误的首槽保留为 unknown。新镜像修复权限后仅继续剩余槽位；独立复算零错误，Gate 为 inconclusive，不签发通过资格。保护模型为独立进程与日志，端口 11436，开发 11435 已停止。
- M8 GitHub App 身份、安装范围和权限已核验；采用同账户测试，真实 CI 场景尚待执行，保持 pending；M9 三条完整 campaign 均未达成。
- M10 开发阶段观察到订单 2 对、退款 4 对、Markdown 8 对攻击效果改善，正常任务无观测业务退化；排除两组不完整配对。已在独立 Linux 卷完成真实备份恢复、取消幂等/旧 fence 拒绝、旧 epoch 拒绝及归档校验；恢复实例使用新 epoch，旧资格失效。当前磁盘余量准入与队列次数、时钟、预算和重启防重复边界已验证；未做物理磁盘耗尽或持续负载测试。完整保护资格不足，不能宣称端到端 M10 验收通过。

详见 [迁移记录](docs/mac-migration.md) 与 [脱敏进度](milestones/mac-migration/progress.json)。


### 2026-10-01 M6 补充实验

工具定义已与严格资源 ID 格式对齐，并增加协议错误路径证据。新配置 `mac-m6-ollama-qwen38-mxfp8-supplemental-v1` 单独执行退款 66 项、Markdown 48 项配对矩阵和 4 项校准，保留旧矩阵全部证据与已消耗槽位。新结果仅由新配置独立 Gate 验收，不将旧结果合并为新配置重复项。已启动校准队列，15 分钟跟踪恢复；通过结论待实际结果复算。详见 [补充实验记录](milestones/mac-M6/supplemental-v1.json)。


退款 M7：24 项私有运行全部完整，独立 Gate 与 API4 必需运行清单、attestation 验证通过。验收继承 66 项 M6 开发证据，原 Skill 的开发失败保留；修补候选综合 Gate 为 pass。此结论限于 Mac 本地实验，GitHub App/正式 CI 仍 pending，未声明生产可用。Markdown M6 仍 inconclusive。

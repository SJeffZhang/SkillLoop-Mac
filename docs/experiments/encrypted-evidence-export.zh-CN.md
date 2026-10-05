# 加密证据导出生产连接（源码实现，未运行验收）

## 已实现的连续调用

`CampaignDispatcher.archive_role → 原预算准入 → 实际 Admin 密钥服务 → Gate 流式导出 → 独立 Gate 认证复核 → archive_close 辅助进程关闭`。

Controller 只读取管理员冻结的调度政策和 Gate 的不透明完成记录，不读取原始私有清单、解开的数据密钥或管理员私钥。实际容器使用固定模块、UID、只读源挂载、无网络、无额外 capability 和关闭的容器日志；创建、启动、等待和关闭均保留原操作记录。辅助进程关闭只删除原容器，不删除卷、密钥、密文或原证据。

## 加密与密钥归属

- 原始证据由 Gate 在授权的只读快照内枚举、检查实际文件所有者并重新计算字节摘要。
- 使用 `cryptography` 的 AES-256-GCM 流式加密；每个新导出生成独立随机数据密钥和 96 位 nonce。规范化头部作为 AAD，包括 campaign、部署身份、操作引用、原清单、依赖锁和管理员公钥身份。
- 数据密钥使用管理员 RSA-3072 公钥和 OAEP-SHA256 包装。RSA 仅用于包装随机数据密钥；证据正文仍采用计划要求的 AES-256-GCM。
- 私钥只持久存于 Admin UID 21010 的 0700 目录、0600 文件。Gate 不挂载该目录。
- 独立复核进程通过实际 SO_PEERCRED 认证的专属 Admin UDS 取得临时数据密钥。管理员服务只处理密钥包装，不挂载证据、不读取正文；临时密钥不写日志、stdout 或 Controller 记录。
- 复核重新计算原证据流摘要，认证全部密文和完整 GCM tag 后比较。未经认证的明文不会被交付给恢复处理者。

实现依据：[cryptography GCM 接口](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)、[RSA OAEP 接口](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)。加密算法由成熟库提供，没有自制密码算法或明文降级。

## 依赖与失败行为

生产入口必须读取管理员冻结的 Linux-aarch64 依赖锁，包含 cryptography、cffi、pycparser、typing_extensions 的准确版本、wheel 摘要及完整安装文件摘要。运行前核对实际平台、版本、全部文件、模块加载位置及原生后端；额外包文件、未锁定 bytecode、影子模块或依赖缺失均拒绝启动。

当前尚未生成该 Linux 镜像的完整 wheel/安装文件锁，也未安装或构建新镜像；宿主环境存在的 cryptography 不计 Linux 就绪证据。

导出前检查原预算内的全部输出上限和真实磁盘 free floor。导出不生成明文临时副本。半成品、超时和未知创建保留原件与 intent；原操作拒绝覆盖或重新加密。独立复核不能修改密文。成功加密不能触发源证据删除。

## 仍需连接的完整 campaign 运维

本生产连接只证明所选冻结清单的加密导出与复核。所有完成记录明确 `campaign_coverage_complete=false`、`deletion_authorized=false`。它不能替代：

1. 全 campaign 必需证据与失败历史的完整清单生产和覆盖 Gate。
2. 加密输出、快照峰值与实际 campaign 容量租约的同一所有权链。
3. 将已实现的 Gate 资格撤销和 Registry CAS 接入完整归档政策生产者，并冻结 campaign inactive 状态。
4. 完整覆盖、撤销、导出复核均匹配后才签发的公开 ArchiveManifest/ArchiveResult。
5. 新 deployment epoch 的认证解密、各角色恢复及全部旧凭据失效。

修复期未启动模型、容器、扫描或第一整轮；语法检查不计运行验收。上述缺项未闭合前不创建实验定时任务，不声明完整归档、完整项目验收或 production_ready。

## 整轮任务索引和归档前资格撤销

Final Gate 在私有 vault 写入 `PrivateCampaignArchiveObligations`，保存全部实际审查过的开发和保护任务引用、ExecutionRecord、Task Gate、Archive Gate、原收据和原清单摘要。索引保留未进入最终名单的开发候选，不只保留当前资格的 subject。该索引不进入公共报告；任务链齐全仍不等于原始 campaign 文件覆盖齐全。

正式调度新增 `qualification_withdraw → registry_withdraw`：Gate 从本部署的原资格库核对准确 campaign/generation/source/config/epoch 绑定，在实际事务中撤销原资格，并返回稳定的撤销记录。原始资格、issued_at、expiry 和私有证明继续保留。重放不会续期。

Controller 随后读取 Gate 所有的撤销完成记录，并在 Registry 事务中再次读取实际 issuer 的 revoked 行；仅将仍关联该 campaign 的 eligible active entry 改为 revoked，保存原操作结果。新 active campaign 不受旧 campaign 的撤销更新影响。两库操作不宣称跨系统原子提交：Gate 已撤销但 Registry 尚未更新时，资格消费仍由实际 issuer 拒绝。

撤销记录均为 `deletion_authorized=false`。完整原始文件覆盖、inactive 状态冻结、密文审查、容量所有权和删除授权仍须接通；目前不能删除证据。以上均为源码实现和静态审查，未执行实际角色或整轮实验。

## 加密复核中的独立任务字节覆盖

加密政策现在必须指向只读源清单内的原 Final Gate 证据及私有归档义务索引。独立复核在完整认证密文后，重新读取实际源文件、检查所有者与稳定字节，并独立重建每个任务的 ExecutionRecord、评估、Task Gate、Archive Gate 和持久归档收据绑定。

每份收据列出的全部原始文件必须按相对路径、字节数和摘要出现在同一加密源清单中；同一收据的多个副本也分别核验。包括未入最终名单的开发候选。遗漏任务、原始输出、Proxy 快照或文件字节均拒绝覆盖审查。该核对由正式加密复核入口直接调用，不需要人工脚本接力。

私有覆盖结果仍明确列出尚未取得权威快照绑定的全局类别：source/批准历史、发现/候选原始历史、工厂/session 权威库、资格/Registry 快照、操作恢复/资源所有权、归档/恢复生命周期。任务字节齐全不会消除这些缺项，也不会产生删除授权或完整 campaign 归档通过结论。下一步须由各实际所有者生产这些一致快照并建立不可由调用者自报的绑定。

## 工厂权威库和 Final Gate 原事实保全

Final Gate 将实际审查过的整轮 manifest、开发 assignment、开发证据、名单、模型生命周期、原 spending snapshot 和 Evaluator 快照收据按独立文件保存在私有 vault，并在原 Gate 证据中绑定摘要。新增文件须计入新冻结预算，不能追加到已运行活动或旧封闭目录。

加密复核要求这些原事实文件全部匹配。同时必须包含 Evaluator 自己生产的原一致快照与 `authority.sqlite`，重新核对数据库字节摘要、完整性、工厂 epoch、最终 subject、完整保护计划，以及每个已完成 session 的原 request/entry/ExecutionRecord。缺失或未知会话拒绝通过；不会重新抽题或派发。

这使工厂/session 权威库类别取得实际审查路径。其余 source/批准历史、发现/候选原始历史、资格/Registry 快照、操作/资源所有权、归档/恢复生命周期仍明确未覆盖。因此完整 campaign 归档、删除授权和实验启动条件仍未满足。

## Source 与批准历史权威投影

ProxyService 可在新冻结部署中配置 `source_archive_directory`，通过 Admin UID 21010 → Proxy UID 21003 的摘要命名只读请求目录交接。每个 campaign 只允许一个原快照请求。请求须绑定实际 Proxy 部署、配置、原截止时间、导出上限和 Proxy/Gate 专属输出目录；创建目录和原预算成本仍须由正式部署/计划生产者预先冻结。

Proxy 从同一实际 SQLite 事务读取全部该 campaign 的 source 授权及 package bytes、原批准对象、领域、工厂批准操作、批准撤销操作和事件、计划版本，以及冻结 catalog。结果先持久写入权威库再发布给 Gate；重启只恢复原结果，不重新采集更新后的事实。投影不读取 task resources，不开放业务库给 Controller。

Final Gate 必须读取该实际 Proxy 投影，重新验证每个包、subject、manifest、Admin 授权及批准领域，并在当前 authority guard 内将全部 source 与 live projection 精确对照。批准撤销分别验证原对象和实际撤销操作/事件，不把撤销后的 revision 改写进原批准对象。原投影及其摘要随后保全在 Gate 的私有事实链。

独立加密审查再次核对 source 包与批准历史，并要求清单内包含 Proxy UID 21003 / Gate GID 21005 的原投影。缺少原投影时，Gate 的语义副本不能代替实际所有者证据。源历史投影目录须只挂载给 Proxy 与 Gate；加密读取扩大的是这一已授予 Gate 的只读投影，不是 Proxy 原业务数据库。

这些为源码连接，尚未部署或运行。发现/候选原始过程、资格/Registry、资源所有权、归档与恢复的全局快照及完整冻结部署仍需补齐，不能据此声明全 campaign 归档完整。

快照请求可提前预置，但 Proxy 必须等到实际私有交接在同一业务库提交 `evaluator_protected_campaigns` 后才采集；该状态已阻止后续 source/开发计划准入。未到达此状态时只等待，不导出部分名单，也不使服务失败。快照记录保护计划摘要，Final Gate 和归档审查再与原工厂计划精确核对。

### 发现与修补原始证据读取一致性

Gate 的静态报告、语义报告和 Patcher 原始请求/响应读取统一检查实际授予的 UID/GID、目录 0750、文件 0640、单硬链接与容量上限，并比较读取前后及当前路径的 inode、大小、mtime、ctime。读取期间变化的字节不得进入独立评估。此修改只完成生产读取连接；原始历史复制、完整尝试清单与加密归档覆盖仍未闭合，未执行运行实验。

### 候选应用的原始输入保全

Application Gate 在独立重建合法候选后，将实际审查的 Controller assignment、Patcher proposal、session policy、原始 request/response 保存为按字节摘要寻址的 Gate 副本。复制前重新比较原审查对象，使用原调度 policy 的 maximum_evidence_bytes 并留出元数据空间；不足时拒绝，原部分副本保留。名单冻结 Gate 逐份核对实际副本的权限、原始大小和字节摘要后才接纳应用结果。

这只覆盖成功应用的五份原始输入，不包含被拒绝、unknown 或未完成的全部发现/候选尝试；all_attempt_history_complete 仍为 false。加密归档的完整历史覆盖类别保持未闭合，未进行模型或运行实验。

### 名单 Gate 保存发现原件

名单 Gate 现在保全本次 assignment、每个适用 subject 的静态扫描原始报告、SourceSnapshot、扫描 receipt 和独立 review，并通过语义审查调用者保全实际 semantic assignment、discovery、逐请求/响应和原始报告。候选 Gate 保存的原始副本也进入同一名单证据目录。所有输入复制前与审查对象或原始字节摘要比较，副本摘要清单绑定在 FormalDevelopmentRosterEvidence 内。

新 roster 调度可冻结最多 256MiB 的实际证据容量，仍按原 manifest 预收费；这只扩大新部署可配置上界，不变更旧预算。实际容量不足会拒绝，保留部分证据。最终 Gate→加密归档的逐副本核对及所有失败/未知尝试登记仍待接通，all_attempt_history_complete 保持 false。上述为源码修复，未启动运行实验。

### 最终 Gate 与加密归档复核名单原件

最终 campaign Gate 逐字节核对名单原件，并将去重副本保存到 Gate 私有结果卷，供既有加密导出使用。复制上限必须同时匹配 Admin 冻结的角色环境、正式调度步骤与原 SpendingLedger 请求成本；不匹配或超限拒绝，部分副本保留，不复用旧活动预算。新部署生产者仍需配置该冻结环境项。

加密归档独立审查现在要求每个名单原件摘要都对应实际 Gate 私有副本，并核验实际权限、大小与字节。仅 reviewed_discovery_bytes_present 能由此得到；全部失败/unknown 尝试历史尚未接通，完整历史类别、campaign_coverage_complete 与 deletion_authorized 继续为未闭合/false。未执行运行实验。

### 撤销后资格库的实际保全

正式资格撤销 worker 在实际撤销提交后，使用当前原 SpendingLedger 的 resource_archive_restore 成本保存资格元数据库与私有 proof 库的一致 SQLite backup。备份逐页检查容量、原截止时间，核验数据库版本、部署身份和目标 campaign 的实际 revoked 行/原 proof 绑定；写入 Gate 私有卷并保留完整字节摘要。部分备份失败保留原件，不延长原 clock 或重新发行资格。

加密归档 Gate 现在必须找到这份实际 owner snapshot，并重开两份原数据库核验完整性、目标绑定与撤销状态。公共撤销完成只返回 snapshot 摘要，不暴露原 proof。Registry 快照、操作/资源 owner 历史和新 epoch 恢复仍未闭合；不据此允许删除证据。未运行实验。

### Registry 撤销 fence 与原数据库归档

Registry 使用已提交的 RegistryArchiveWithdrawal 原操作结果阻断该 campaign 的新开发、保护派发、promote 与同身份重新准入，不新增可由调用者自行填写的 archived 标志。正式调度增加 registry_snapshot action：读 Admin 冻结策略，核对原撤销操作及原 clock，预收原预算后，对 Controller 实际 Registry 做有界一致 backup。备份归 Controller 所有，仅以 21005 组只读授予 Gate；原可写数据库权限不改。

加密归档 Gate 重开实际 Registry 副本，核对原 campaign 绑定、撤销操作，以及与 Gate 资格撤销摘要的对应关系。只有两类实际数据库都验证才可认为本归档的资格/Registry 快照类别已覆盖；完整 campaign 覆盖与删除仍 false。生产者路由/挂载和完整运行验证仍需完成。

### 新 epoch 的认证历史恢复入口

正式 archive_role 调度增加 restore worker。恢复首先要求完整独立 campaign 归档审查通过，再完整认证 AES-GCM ciphertext；第二次认证解密时按封装内 inventory 重建原件，逐文件实际分配容量、核对字节、保留 2GiB free floor 并 fsync。路径穿越、重复/大小写冲突、容量不足、ciphertext 变化和部分恢复均拒绝完成，原件与部分新目录保留。

恢复目录必须为空且使用不同 deployment epoch，全部历史原件进入 Gate 私有惰性证据库，不能作为运行数据库挂载。旧批准、Lease、grant、session、attestation 不自动激活，必须由新部署 Admin 重新准入。此入口不能替代新部署生产者和业务状态重建；完整覆盖仍缺操作/资源与失败/unknown 历史，因此目前会在完整审查门槛拒绝恢复，未进行恢复实测。

### Linux 加密 wheel 锁与正式入口构建

已从官方 PyPI 获取 Python 3.12/Linux-aarch64 的四个实际 wheel，公开锁记录真实版本、文件名与 SHA256：cryptography 50.0.2、cffi 2.1.1、pycparser 3.0、typing_extensions 4.16.0。wheel 二进制保留私有部署准备目录，不提交 Git；下载未运行模型或实验。

新 whole-flow Dockerfile 使用独立加密安装目录、离线 require-hashes/no-deps/no-compile 安装，并由 Linux 专属生产者记录安装后的完整实际文件清单。归档角色 PYTHONPATH 接入该批准目录，运行时仍逐文件核验。构建同时安装 pyproject 的正式 skillloop console entry。镜像尚未构建，BASE_IMAGE 必须由最终冻结构建流程提供精确已批准摘要；wheel 已落实不等于 installed lock、完整入口或 runtime 已通过。

### 正式入口的结果绑定职责修正

完整 route 的 stage history 仅 Controller 持有，因此 OperatorFinalResultBinding 由 Controller 在核验实际角色输出后产生，独立保存到 Controller-owned 只读公共授权目录。业务结果本身仍由 route 声明的实际角色持有；CIResult/HardenResult 必须来自 Gate，调度器不能生成。原操作恢复同时读取实际角色结果与 Controller 的已完成 stage journal，逐摘要核对 request、route、结果 producer UID 和完整步骤链。新部署必须为 result_binding_path 配置 Controller 所有权；旧冻结 route/目录不改。

### 操作恢复库与开发失败原件保全

OperatorService 将自身实际 OperatorOperationStore 交给正式 dispatcher；operation_archive action 读取 Admin 冻结策略，预收原预算后保存实际操作 SQLite backup 与声明的 Controller/Generator/Patcher/Gateway 历史字节。逐文件核对原所有权、权限、大小、读取稳定性和目录变化；未知、失败、accepted/running 状态按原记录保留。保护角色库被排除，不扩大 Controller 私有读取权限。空 spending.lock 仅保留元数据，不修改原锁权限。

加密归档审查要求实际操作快照和每份历史副本均进入 inventory，并重开操作库验证原 epoch、请求、route、ticket 和状态。此链还不能证明物理 evidence lease、穷尽所有模型尝试或完整删除/恢复边界，相关类别保持未闭合。未启动组件或整轮实验。

### 归档审查内存与撤销后的入口边界

Gate 对数据库和二进制原件改为 1MiB 分块核验，每块检查原预算截止时间，不再将最大 256MiB 的数据库副本整体读入内存。核验结束还检查当前路径与已读取文件的 inode、时间和大小，拒绝读取期间替换路径。JSON 元数据继续按原上限解码。

Registry 的名单冻结和原 campaign 绑定入口也核对已提交的 archive withdrawal；已关闭的身份不能再冻结名单或重新绑定。Registry 快照在消耗预算和写入意图之前核对原 configuration/epoch，快照之后再次核对。只进行了源码及语法审查，未运行实验；完整物理容量和归档恢复仍需接通。

### 原件读取的完整路径核验

实际操作历史复制、加密 inventory、加密内容写入和独立 campaign 审查共用逐层 openat/O_NOFOLLOW 读取。每一层目录禁止 symlink，读取前后核对 inode、mtime/ctime、大小、权限、owner 和 link count，结束时重新从完整路径打开并比较，防止原 fd 不变但路径已被替换。加密 inventory 还检查扫描期间目录是否变化；操作 SQLite backup 完成后复核实际容量上限。原件变化即拒绝完成，部分副本保留。未运行实验。

### 实际导出和恢复文件提前分配

Durable task 复制、AES-GCM 输出及惰性历史恢复在写入内容前，对即将保存真实证据的原 inode 执行 posix_fallocate；核对实际 blocks/size、所有权、2GiB free floor，并 fsync。加密输出另外核对写入位置等于预计算的完整封装长度。没有支持的实际分配能力或空间不足时拒绝写入完成，部分文件保留；不创建无关占位文件、不降级稀疏文件。

这是这些实际输出文件的提前分配，尚不等同于完整 campaign 所有角色共享的 2GiB 预留、并发容量或紧急空间链。正式资源验收仍未闭合。未进行组件实验或整轮运行。

### 原操作的已提交前缀恢复

OperatorService 重启时先恢复原最终结果；若没有最终结果，则由 Controller 核对原 route/request 身份、连续的 started/completed 成对记录和完整结果摘要。只有剩余步骤全部没有 started 记录、没有提前或部分最终投影，才保存恢复证明并将同一个操作恢复为 accepted。原 worker 跳过已完成步骤，claim 仍检查原截止时间；不替换 ticket、任务、预算或时钟，也不在启动恢复中同步等待数小时执行。

任一步已有 started 却没有 completed、缺失前缀、变更摘要或部分最终投影，仍保留 unknown_requires_recovery，不能重新派发。此变更只通过源码及语法检查，崩溃/响应丢失场景仍待完整轮次验证。

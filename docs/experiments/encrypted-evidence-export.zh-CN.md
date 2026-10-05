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

全部步骤已有连续成对提交记录、但最终绑定尚未完成时，也可恢复同一操作的收尾。已有 Controller 结果或绑定只在逐字节对象一致时复用，不覆盖；实际角色结果仍从原 producer 读取。修正 Gate/Reporter 结果分支未导入发布函数的问题，Controller 只发布自己的完整步骤绑定，不生成 Gate 结论。部分最终投影且尚有未执行业务步骤的情况继续保持 unknown。未运行实验。

### 正式 admin export 的真实结果生产

AES-GCM 独立 Gate 审查完成后，从实际 ciphertext、原 inventory 和原 export intent/receipt 创建时间生成冻结 API4 ArchiveManifest，保存为 Gate-owned 只读结果。正式 admin export route 可以绑定该 manifest，再由 Controller 发布自己的步骤绑定。manifest 只证明冻结 CLI 所要求的 verified encrypted export，不宣称完整 campaign 验收、资格恢复或允许删除；coverage/deletion 仍独立保留未闭合状态。

Admin 通用 role_command 不再发送尚无业务实现的 Proxy export/archive/restore RPC。路由准入先拒绝这种断开的调用路径，导出必须走实际 archive_role export→review；archive/restore 的完整资源和新部署收尾仍需实现。未改冻结 RPC enum，未运行实验。

### 长期角色数据与临时任务卷分离

统一部署原来把所有长期角色库放入最多 2GiB tmpfs，而 FormalStorageStore 在同一 FS 要求 2GiB free floor 加 DB/WAL 预分配，正式 Proxy 必然无法准入。新内部部署 manifest 必须明确 storage_backend=local_persistent，并单列 provisioning_bytes（初始化配置、目录和元数据上限）；不再把 tmpfs 大小当作真实 evidence reserve，也不把整个共享卷的额度重复计入初始化成本。

部署实际核对 Docker local volume 的 Options/epoch，bootstrap 在首次写入前核对实际持久 FS free floor 和完整初始化预算。原每任务有界 tmpfs、Keeper 和临时证据保全流程独立保留；长期数据仍按原角色子目录权限授权。只对新部署身份生效，旧 manifest/卷不迁移、不重启。整个 campaign 的共享物理预留和释放仍未闭合，provision completion 明确 campaign_capacity_verified=false。未构建或运行新部署。

统一角色准入还要求除独立冻结 Scanner 以外的生产角色使用当前 whole-round 精确 image；拒绝重复环境变量名或不合法环境条目，避免已冻结 source/image 与实际角色配置分离。Scanner 仍由自己的 scanner lock/实际报告链复核。未运行部署验证。

### 原资源清理的丢失响应恢复

Docker 客户端保存实际 HTTP 状态，传输超时与明确 404 分开处理。保护辅助进程、原 Runtime/Keeper/任务卷以及加密归档角色清理保存逐资源删除意图；仅在原意图存在且身份一致时，以真实 inspect 404 核实删除。资源仍存在时重读原 image、配置、挂载和停止状态，再继续同一清理；不重新派发任务、不强制删除运行进程，也不让容器删除隐式带走证据卷。

Operator 重启可接续已开始的 archive_close 原清理意图，然后核对已提交前缀再排队原未开始的尾部。归档清理恢复保留原 started_at、deadline 和预算，过期仍输出 inconclusive_expired_budget_closure。保护业务投递未知继续阻断；这不是任意 started 阶段重试。上述代码只经源码、语法和 diff 检查，仍待整轮真实故障验证。

### 统一11角色配置的 Admin 生产路径

新增 whole_deployment_producer，经既有 Admin role_command 的 produce-deployment 内部委托，按一份冻结声明产生全部11角色的实际 Engine 配置。入口、UID、权限、网络、CPU、PID、FD、日志和只读根由生产代码统一设置；挂载、source/image、私有范围、目录和配置文档在写 manifest 前经过同一部署校验。该生产者只创建配置，不制造批准、私有任务或生命周期证据；Controller 继续用 WholeRoleDeployment 消费产出的 manifest。

Controller 的 Docker socket 增加显式 engine_socket_gid 绑定；只有 Controller 可获得该组和精确 /engine.sock 挂载。正式 Controller 入口检查实际 socket 类型、组、组读写权限和无其他用户权限，拒绝靠偶然继承权限启动。配置中的 ControllerCampaignDeployment 必须与统一声明绑定一致。旧冻结 manifest 不修改。完整 route/任务材料与真实物理容量仍需接通，未启动实验。

### 操作状态的完整追加历史

新部署 OperatorOperationStore 使用版本2，接收、claim、完成、失败、原未开始尾部恢复及到期拒绝均在更新当前状态的同一 SQLite 事务追加 sealed transition。每条记录绑定原 epoch、operation、前一摘要、实际 UTC 和真实结果摘要；UPDATE/DELETE trigger 禁止改写已追加历史。重放原 ticket 不追加伪事件。旧版本数据库拒绝作为新部署使用，旧冻结数据库不迁移。

实际操作 backup 生产者和独立加密 archive Gate 都逐条重建允许的状态转换、摘要链、时间及当前行/结果一致性。失败和未知状态不能由当前状态快照替代或删除。此变更尚未证明完整物理容量、全尝试目录或运行恢复通过；只有源码与语法检查，整轮未启动。

### 开发任务原收尾的连续恢复

开发任务通过独立 Task Gate 和 Archive Gate 后，retirement 保存原 Runtime、Keeper、Evaluator、Gate、Archive Gate 及任务卷的完整身份。再次进入只重开原归档审查和清理意图，逐资源核对停止状态、配置、image、挂载及删除记录；明确 404 只在原删除意图之后用于确认删除，不重新生成归档或运行模型。

正式 execute_admitted 对已保存清理意图后的连接丢失/超时保存原失败类型，并接续同一清理一次。清理结果记录原开始 UTC、截止时间、120秒原预留及实际耗时；超时收尾即便删除完成也保留 inconclusive，不能作为完整开发任务成功。其他未知投递或缺少完整独立审查仍阻断。只检查了源码、语法和 diff，尚未运行真实故障实验。

### 长实验期间的取消/撤销通道

Operator 将普通串行执行与取消/撤销控制分开。控制 route 在服务准入时必须只有一条 proxy_controller 步骤，并严格匹配冻结 cancel_run/revoke_approval；只有实际 Admin 可以提交。控制通道最多一个待处理/运行操作，不占用16个普通操作的队列，不能派发模型或 campaign。两个通道的 claim 和状态历史仍用同一个权威 SQLite 事务，普通实验仍只有一个 running。

关闭服务后若原 worker 未完成，保留 service lock fd 到进程退出，防止 endpoint 关闭后新服务误以为已清理而并行接管原 Runtime。tokenizer 和原证据继续保留。上述源代码检查不等同于并发/满队列/取消实测，完整物理紧急容量仍需整链接通。

### Campaign 取消与资格消费的共同业务 fence

正式 Admin cancel 经实际 Admin→Controller→冻结 cancel_run 委托，使用 Controller 自己保存的原 Lease/业务 closure 元数据解析 run 和实际已知 fence；不读取私有题库。内部 reason 明确绑定目标 campaign，Proxy 在同一 SQLite 事务保存 campaign cancellation、递增原 run fence，并取消其他已准入 active/finalizing run。普通任务停止仍只作用于自身，不把每个正常任务收尾误当 campaign 取消。未来 reserve/start 和业务工具均拒绝已取消 campaign。

Proxy 的只读 live authority 投影携带实际取消记录。私有 Factory/session/当前任务交接、名单 Gate、campaign Gate、资格签发和资格消费均必须提供精确 campaign 身份；取消后不签发、不消费。Controller 的生产 route 增加内部 campaign_digest 绑定，派发新步骤前检查实际投影；证据保全、撤销、归档和已提交结果读取继续可用。原任务在 Admin 已提交取消后收尾，只复用完全匹配的原 run_cancelled 事件，不重复递增 fence。

没有原 Lease（包括启动投递未知）的情况不能伪造 run 或 CancellationResult；当前明确阻断，尚需补齐启动前取消生产连接。并发 fence 变化仍以 CAS 拒绝处理，不自动创建第二次请求。取消时原 OCI/辅助进程的立即停止和完整资源释放仍需统一调度整链接通。仅做 AST、调用方和 diff 检查；未运行取消竞态、模型或完整轮次，不能宣布运行验收。

### 正式 campaign 调用独立模型生命周期 Gate

增加 lifecycle_review 调度步骤，使用统一11角色部署中的真实 Gate 入口 review_lifecycle。Controller 只读 Admin 的调度政策和 Gate 的 OpaqueNativeLifecycleReviewCompletion；Admin 的原宿主 start/stop/log、Evaluator 私有 Factory 库、完整生命周期 review 与 Gateway grant 均不跨入 Controller。Gate 必须先独立完成原进程、真实 UTC、空缓存、完整日志及开发停止→保护全新启动核验，才发布不透明完成状态。

生命周期 Gate 的原创建、预算、进程和 reviewed/removing 记录进入 Controller 私有 journal。成功后只删除已经停止的 Gate 容器，明确保留共享持久证据卷和 Keeper；删除响应丢失只能凭原 removing 与完整 reviewed 身份继续清理，不能再次审查或启动模型。原开始时间、截止和预留不重置，超时仍 inconclusive。失败只停止精确原 Gate 并保全私有诊断。此连接还需要正式 Admin 宿主生命周期生产/导入及完整部署包配置，不能以其源码存在宣布整链就绪。未启动 Gate、模型或实验。

### 原操作数据库的实际容量和紧急记录空间

新部署 OperatorOperationStore 版本3在实际 SQLite 文件中分配可复用的16MiB页空间，以实际 page_count/freelist_count 留出2MiB紧急余量。普通准入不能占用该余量；取消/撤销请求另限制8KiB，且继续保留末端结果记录空间。所有历史仍追加保留。版本2及旧冻结库拒绝迁移，不改旧证据。初始化实际FS要求2GiB free floor与数据库/rollback临时峰值，检查真实磁盘块分配；没有另建占位 reserve 文件。

OperatorService 在原 whole-round ledger 中先消费60秒、32MiB初始化/峰值槽，再初始化操作库；重启只核对原消费记录、时钟和政策，不补槽。正式部署生产者要求同一 campaign/epoch/deadline/storage policy。操作库快照和独立 archive Gate 都验证实际版本3与物理政策。控制消息统一262144字节上限，正式结果为响应包装预留空间，避免已提交大结果永远无法返回。

此修改只解决实际操作数据库的预留和压力收尾源码路径；不代表每 campaign 2GiB证据写入链、整轮完整容量或磁盘满验收已经完成。没有创建SQLite、运行压力测试或启动实验。


### 业务一致快照的临时容量

Proxy 在实际已取消 run 之后，通过 SQLite VACUUM INTO 直接生成一致、无空闲页的快照，不再为每个任务先复制业务库的全部预留空页。原业务库的实际页预留不变。生成前检查实际源页数，以两倍完整源文件页容量作为保守临时上界并保留2GiB真实FS余量；进度回调限制原时间、余量和目标容量。输出只在实际 integrity、原取消 fence、原准入 receipt、完整逻辑内容摘要及文件 fsync 核验后交给 Evaluator/Gate。部分文件保留且不自动重试。

Evaluator/Gate 与重启恢复共同检查导出方法、原页容量、峰值上界、真实紧凑页数和完整字节摘要。此处的FS准入和一致导出仍不是全 campaign 物理资源所有权链；后续需把峰值纳入同一实际租约、实际磁盘容量和整轮预算。旧冻结镜像/证据未改。仅做源码与AST检查，未执行SQLite、故障或整轮实验。


### 整轮 profile 与原账本绑定

每个 Operator 服务只接纳当前部署 campaign 或不涉及 campaign 的只读/管理 route；三个 profile 必须串行使用各自实际准入的部署、原时钟和账本。完整开发 phase 在首次 victim 投递前再次核对已持久 whole-round campaign 绑定，禁止某 route 消耗A的预算却交付B的任务。Operator 在任何物理页分配或消费初始化槽之前先验证全部 route 和原8小时截止；无效配置不产生数据库副作用。

统一部署生产者按 Controller 实际只读 volume/subpath/target/嵌套挂载解析配置文档，确认每条 route 确实存在且具备 Admin→Controller 文件授权，不能把宿主路径或被覆盖的配置当成可用入口。上述为源码连接检查；完整三个 campaign 的生产配置、串行启动与恢复仍需接通并实际整轮验证。


### Admin/Reporter 原辅助进程收尾

统一 campaign 的 role_command 现在先消费对应阶段的完整 worker/收尾/证据槽，另保留原部署 role-create 的60秒成本，然后发布真实委托、启动原 Admin/Reporter、读取原结果并核验原 OCI 配置和停止状态。只有结果文件与实际成功退出一致、Keeper仍存活，才提交 reviewed/removing 并删除原停止容器；共享证据卷和Keeper不删除。Controller journal记录原开始/截止/总预留及清理结论。

restart只能在原 removing 已存在时继续同一辅助进程的退休；实际404必须有原删除意图，Config/Image/HostConfig/Mounts及原结果全部核对。投递、创建或执行未知不能重跑命令。原终端空间或时间超限保留 inconclusive，失败只停止精确已观察原进程并保全输出。内部route增加closure_seconds/maximum_evidence_bytes/journal_directory以冻结成本和恢复位置，公共17 CLI/RPC/权限不变。仅源码、AST和diff检查，未启动辅助进程或实验。


### 同一部署内的冻结角色入口

11角色UID和权限保持固定。统一生产者可以为同一角色一次性冻结 entry_variants：每项具有明确允许的生产模块、完整OCI配置、只读/写挂载和配置环境。所有变体逐项应用原完整身份、cap、网络和私有卷边界审查；未知模块或改变角色UID均拒绝。生命周期 Gate、最终 campaign Gate、资格撤销和语义发现已改为选择精确已冻结入口。未冻结所需入口时阻断，不重写原部署或目录。

同一 role/operation 已有创建记录时，要求原 create intent 的完整配置与当前精确入口一致，再核验实际 OCI；不能把旧入口容器冒充另一个入口。原 provision completion 必须匹配同一 manifest，原 Keeper实际身份及存活状态也要一致。各入口仍独立消费原创建/worker/收尾槽，没有增加模型并发或替换未知投递。此连接只做跨调用与AST检查，完整配置包及实际部署验收仍未开始。

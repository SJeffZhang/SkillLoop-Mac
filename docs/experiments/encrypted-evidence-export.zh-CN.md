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

# 批准 manifest 与任务资源准入组件

`ApprovedPackageLoader` 从可信 controller 配置取得 SourceSnapshot → manifest 精确摘要白名单。它复核完整包文件字节、当前 loader profile、固定 manifest 字段、family/profile/frontmatter、明确选中的 reference 与安全资源 ID。当前 package-relative manifest 路径属于 native import profile；历史 example manifest 与已通过身份保持原样。

`ProxyStore.stage_imported_task` 是可信进程内 setup API：先验证 subject 和选中的 skill resources，再复用真实 SQLite stage_task。未选包文件不自动注册。包文件数量与任务资源数量独立计算；capability 编译器现在拒绝超过 32 个任务资源。没有新增冻结 RPC method，原 stage_task 签名不变。

新 Linux 活动实际完成三 profile 六项任务、12 个准入负例和 24 次 UDS 读取。同名 input:notes 在不同 task 中返回各自 bytes，三项恰好 32 资源的注册成功，33 资源拒绝。选中指令/reference 可读，未选 reference 的注册与工具读取拒绝；foreign UID 与 wrong task 拒绝。完整 Git 字节、API4 对象及 SQLite 一致备份有独立核验。原 harness 失败、两项已注册旧任务和审查 CAP 名称断言均保留；旧 epoch 没有重启。

范围只到真实准入及注册工具投影。共用可信测试 OCI 挂载全部 fixture Git 仓库，因此不称完整 runtime 文件系统隔离。可信 root harness 的四项身份 setup capabilities 不是生产角色权限验收。源码/manifest pins 是 controller 配置及返回元数据，尚未形成 authority 持久资格记录；选中材料到 AgentAdapter 的 transport/token 预检、完整控制角色服务、remote family methods、17 CLI、正式 R33/R36 和 M1–M10 仍缺。production_ready=false。

脱敏证据：milestones/mac-full-acceptance/approved-loader-resource-summary-v1.json；总矩阵 v15。

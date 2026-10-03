# Mac 角色控制读取服务组件

新增 opt-in `skillloop.role_service`，从冻结 RPC 合同建立 11 个角色 UID 与方法映射。可信本地操作员为独立 SQLite 存储配置读取授权，六个实际客户端角色通过独立 UDS 和 Linux SO_PEERCRED 访问指定对象。没有新增冻结 RPC 方法。

40 条真实 RPC：20 接受、20 拒绝。覆盖原结果重放、角色专属操作查询、错误参数与 UID、私有证据越权、角色伪报、真实 UTC 到期、撤销及代际变化。两份数据库一致，8 个持久操作、8 个读取授权。客户端未挂载数据库或 Docker socket，实际 capability 为零、seccomp 和 no-new-privileges 生效、外网拒绝。

组件功能独立审查通过。原活动 3600 秒时钟在独立审查及清理前已经到期，因此整个活动保持 inconclusive；未延长原时钟、未使用剩余槽位或重跑 RPC。以独立 600 秒退役计划保存源码并清理两个专属容器与两个卷，keeper 自然退出为 0。

对象是明确的合成可见性 fixture；不是实际完整私有资格证据。完整 CLI、写路径、11 角色集成、run/fence/session 发行链、资源耗尽、资格签发与撤销生命周期仍需验收。完整 R42、M1–M10 与 production_ready 均未通过。

第一份原始 24 小时资格证明于真实 UTC 2026-10-03 06:54:34 观察到 consumption_expired；第二份需 UTC 12:16:20 后观察。没有签发新证明或调用模型。

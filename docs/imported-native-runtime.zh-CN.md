# 注册包到原生模型 Runtime 的集成组件

ProxyStore migration 2 将 SourceSnapshot、manifest、selected-resource pins 与新 task 的资源注册写入同一个 SQLite 事务。它表达可信 controller 的准入，完整资格签发和撤销生命周期仍未完成。旧冻结数据库与旧 source/image 没有被修改。

AgentAdapter.run_imported 通过现有认证 Proxy 读取 TaskBinding 注册的指令/reference，核对完整 bytes digest，再送入真实模型上下文。reference 的内容参与原生 tokenizer 的完整 chat-template/tools 预检；超限 51,014 tokens 在 HTTP 前拒绝。新 runtime 使用独立 network-none/read-only/capdropALL 容器，没有完整包、Git 仓库、authority DB 或 Docker socket 挂载。

实际 orders 输出在 v5 独立核验；v5 的 refunds 在 prepare 后 lease 到期，留下未消费 grant、零发布，Markdown 未启动，原 Gate 仍 inconclusive。v6 用两个 fresh task/source 身份，仅运行 refunds 与 Markdown。每个 runtime 启动前由 UID21001 经原有 controller start_run UDS RPC 获取 lease，两个新任务通过，三份成功 scope 的完整 golden bytes/唯一 publication/outbox/consumed grant、逐轮实际 native token 计数和持久 pins 分别核验。不是同 epoch 的正式三 profile Gate。

早期 v1/v2 初始化和源码权限失败、v3 evidence 目录 UID 失败、v4 timeout 传参导致的一次模型 unknown 均保留。v3/v4 没有活跃 keeper，最后 tmpfs mount 退出使 authority 原始 DB 丢失，证据严格 incomplete；不以新任务修补原 Gate。v5/v6 在写入前启动只读 keeper，所有一致 DB/模型上下文/日志导出和独立审查后才释放。

完整角色 registry、CLI/控制服务、family 远端业务方法、正式资格链/R33/42 runtime operations/M1–M10 仍未验收；production_ready=false。公开 evidence 为 milestones/mac-full-acceptance/imported-native-runtime-summary-v1.json 与总矩阵 v16，私有 raw 不上传。

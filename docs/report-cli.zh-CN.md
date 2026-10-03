# Mac report CLI 接入组件

生产入口 `python -m skillloop report --campaign <digest> [--format=json]` 使用冻结命令合同，调用现有 report 角色控制服务的 read_public_projection，不增加 RPC 方法。部署由可信操作员设置 SKILLLOOP_REPORT_SOCKET_DIR；真实内核要求客户端 UID 21009、服务 UID 21003。客户端限制响应字节数，严格核验 PublicReport 类型与摘要，仅向 stdout 输出一个 JSON 对象和 LF。

新 source/config/epoch 下完成 12 条真实 Linux CLI：3 次正常输出（默认格式、显式 JSON、重复读取）和 9 次拒绝，覆盖错误 campaign、非报告角色 UID、缺参数、非法 digest/格式/未知 flag、缺 endpoint 配置/不存在 socket、实际撤销角色后的读取。返回 0/64/74/77 与冻结错误合同匹配。12 个客户端实际 Docker inspect 核对只读文件系统、无外网、cap-drop ALL、no-new-privileges、1 GiB/CPU 2/pids 64，只挂载只读角色 sockets。

一致 SQLite 原库与备份保存 3 个操作，无业务写入。完整 2760 秒预留预算含 2 个 aggregate OCI 槽（1 实际、1 未用）、镜像/设置/审查/终端；原 3600 秒时钟内实际 183.813 秒闭合。独立审查后 keeper 停止 exit 137，两个专属容器与卷、12 个客户端均精确移除。

本活动公开投影是明确 synthetic fixture，未证明真实业务 campaign report 发行链。未安装全局 skillloop 命令；其余 CLI、恶意服务响应负例、run/fence/session/qualification、资源耗尽与完整 R36/R42 仍缺。M1–M10 和 production_ready 保持 false。

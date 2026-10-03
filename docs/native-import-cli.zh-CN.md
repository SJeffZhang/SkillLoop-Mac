# Git 对象导入 CLI 组件

入口：`python -m skillloop import --git-repo /trusted/repo --commit <40位SHA> --skill-path skills/example`。成功时 stdout 仅一个严格 API4 SourceSnapshot JSON 对象和换行。错误诊断写 stderr；语法/非法引用 64、权限 77、I/O 74、繁忙/超时 75。

该入口只读取提交对象，不 checkout、不运行 hook/filter/包脚本、不下载 submodule 或 LFS。验证 commit/tree/blob 的实际 Git SHA、普通 Markdown 文件、安全 ASCII 包路径、大小写冲突、固定五键 frontmatter，以及 32 文件、4 KiB 单文件、128 KiB 整包界限。快照文件清单与 Skill 摘要按路径排序；完整 loader profile 摘要区分此实现和历史 loader。工作区内容与 Git replacement refs 不参与导入。

可选 `--operation-id` 使用可信操作员配置的 `SKILLLOOP_CONTROL_DIR` 私有目录：同 ID/同参数跨进程返回原结果，参数变化拒绝。此组件的本地 journal 不代表完整控制服务的角色授权。

依赖受信任的 `/usr/bin/git`。本次 Mac 29 条真实 CLI 调用及独立对象重构通过；当前 Linux runtime/scanner 镜像均缺 Git，首次 Linux 导入返回 74，原失败保留。Linux 导入仍待新明确依赖身份验收。

这是新增生产组件，尚未接入批准 reference 选择、运行资源与模型 token 预检，也未完成全部角色、17 CLI、42 条 operations 或 M1–M10。没有安装全局 `skillloop` 命令。完整记录见 `milestones/mac-full-acceptance/native-git-import-cli-summary-v1.json`，总矩阵 v13；production_ready=false。

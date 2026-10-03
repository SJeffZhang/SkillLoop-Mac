# Git 对象导入 CLI 组件

入口：`python -m skillloop import --git-repo /trusted/repo --commit <40位SHA> --skill-path skills/example`。成功时 stdout 仅一个严格 API4 SourceSnapshot JSON 对象和换行。错误诊断写 stderr；语法/非法引用 64、权限 77、I/O 74、繁忙/超时 75。

该入口只读取提交对象，不 checkout、不运行 hook/filter/包脚本、不下载 submodule 或 LFS。验证 commit/tree/blob 的实际 Git SHA、普通 Markdown 文件、安全 ASCII 包路径、大小写冲突、固定五键 frontmatter，以及 32 文件、4 KiB 单文件、128 KiB 整包界限。快照文件清单与 Skill 摘要按路径排序；完整 loader profile 摘要区分此实现和历史 loader。工作区内容与 Git replacement refs 不参与导入。

可选 `--operation-id` 使用可信操作员配置的 `SKILLLOOP_CONTROL_DIR` 私有目录：同 ID/同参数跨进程返回原结果，参数变化拒绝。此组件的本地 journal 不代表完整控制服务的角色授权。

历史 v1 使用受信任的 `/usr/bin/git`：Mac 29 条真实 CLI 调用通过，原 Linux 缺 Git 导入失败永久保留。新 loader profile v2 使用 Python 标准库读取本地 SHA1 对象，不需要 Git 可执行文件；支持 loose、pack v2/v3、index v2、OFS 和同 pack REF delta，校验对象 OID、CRC 和 pack/index SHA。逐目录 fd 与 O_NOFOLLOW 拒绝链接，文件类型、字节量、delta 深度、缓存和期限有明确边界；外部 alternates、promisor 和 thin delta 拒绝。格式依据 [Git pack 规范](https://git-scm.com/docs/gitformat-pack) 与 [loose object 规范](https://git-scm.com/docs/gitformat-loose)。

新独立 Linux image 中 Git 实际不存在，24 条真实 CLI 记录（12 成功、12 拒绝）通过；三 profile 的 loose/OFS/REF、六个实际 SKILL delta、32×4096 最大包、有效外层校验的损坏 delta 与 cycle、真实 SQLite 重启幂等均有原始证据及独立 native Git 字节核验。pack v3、大 offset、索引极限和深度容量等声明变体尚未全部实测。原失败未重跑，新增活动预算、镜像、源码与完整导出独立闭合，资源已清理。

这是新增生产组件，尚未接入批准 reference 选择、运行资源与模型 token 预检，也未完成全部角色、17 CLI、42 条 operations 或 M1–M10。没有安装全局 `skillloop` 命令。完整记录见 `milestones/mac-full-acceptance/native-git-import-cli-summary-v1.json`，新 Linux 组件见 `milestones/mac-full-acceptance/linux-git-object-import-summary-v1.json`，总矩阵 v14；production_ready=false。

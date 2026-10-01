# M8：同账户 GitHub CI 测试

## 账户与仓库

采用用户批准的同账户模式：GitHub 账户为 `SJeffZhang`，合成测试仓库为 `SJeffZhang/skillloop-ci-test`。允许该账户创建测试分支、PR，或在 GitHub 支持的仓库关系下使用其 fork。实际仓库关系必须核验并记录；不能把同库分支 PR 标为跨仓库 fork PR。

App ID 为 5150265，Installation ID 为 166888069。已验证 Checks 写入、Contents/PR 读取权限，安装范围仅含测试仓库。私钥路径及令牌保留本机私有配置，不进入文档或 Git。

## 必需验收场景

- GitHub App 对实际 PR 的精确 head SHA 创建和更新 Checks。
- force-push 后，旧 SHA 结果不得作为新 SHA 的资格。
- 重复事件处理保持幂等。
- 配置变化、旧 worker、取消与续评保持配置身份和执行栅栏。
- 每个场景保存可独立复算的事件、SHA、配置与 Checks 收据；合成 Skill 才可进入公开仓库。

## 通过条件与范围

不要求另一个 GitHub 账户。上述场景完整且证据一致后，可声明同账户 M8 范围通过；缺少运行证据仍为 pending。跨账户 fork 的权限与凭据隔离单列为未验证，不阻断同账户范围验收，也不能由同账户结果推断通过。

历史 DGX 与其他配置的验收不被此范围变更覆盖。文档方案已批准不等于实验已经通过。

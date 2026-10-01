# SkillLoop 当前 PRD

本 fork 用于 `SJeffZhang/SkillLoop-Mac` 的 Mac 实验。

当前入口为 [Mac 实验 PRD](SkillLoop-PRD-Mac.zh-CN.md)，连同 [V2.2 基础 PRD](SkillLoop-PRD-v2.2.zh-CN.md)、[V2.2 规范附件](specs/v2.2/README.md) 和 [Mac 运行配置](specs/mac/README.md) 阅读。Mac 部署模型、隔离方式与预算采用 Mac 补充；业务与证据判定继续遵守 V2.2。

历史版本：[V2.1](SkillLoop-PRD-v2.1.zh-CN.md)、[V2.0](SkillLoop-PRD-v2.0.zh-CN.md)。DGX 历史结论独立保留。


## M8 同账户测试方案

M8 允许使用同一账户 `SJeffZhang` 创建测试仓库、分支或可用 fork 并发起 PR，不要求另一个账号作为准入条件。真实 GitHub App Checks 与事件场景必须取得独立验收证据；跨账户 fork 权限隔离不在此次同账户测试覆盖内，单独记录为未验证。详见 [M8 测试说明](docs/wiki/M8-same-account-testing.md)。

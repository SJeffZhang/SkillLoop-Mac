# Mac验收规范补充提案 v1（待用户决定）

目标部署：Mac ARM64 原生 Ollama/Metal 模型后端，Linux aarch64 Docker 执行业务与隔离角色。现有DGX历史及冻结v2.2规范全部保留。本提案尚未生效，不授予任何阶段通过或production资格。

## 提案A：新增Mac DeploymentLock变体

原 `specs/v2.2/operations/control.schema.json` 的 DeploymentLock.platform 仅允许 `linux-aarch64-dgx-spark`，并强制 driver_version/cuda_version 非空字符串。当前已授权Mac runtime profile使用Metal，不具备CUDA；填入DGX或伪造CUDA值不能建立真实身份。

建议新增独立版本化Mac补充schema及明确的验证路由，platform为 `macos-arm64-native-ollama-linux-aarch64-oci`；模型后端字段显式为Metal，OS/模型提供器/容器运行时版本和实际锁均记录。CUDA字段在此变体中为明确的null（不以字符串NA冒充版本），原DGX变体及验证保持原样。新的Mac变体仍严格拒绝额外字段、错误角色/部署epoch/摘要，不接受通用宽松fallback。

模型manifest/tokenizer、scanner安装依赖/rules/离线情报、每条CalibrationReport真实原始记录、峰值内存与最高输入、工具解析/拒绝恢复/隔离/生命周期、预算与审批等全部验收门槛保留。无法实证的字段或条款继续inconclusive/blocked。硬件专属条款必须逐条明确Mac对应及实际证据，不能因平台变化自动豁免。发布和runtime行为需新source/config/epoch/manifest后实际实测。

需要决定：允许这一显式Mac规范变体作为本次M1–M10验收目标的身份合同；不把本提案本身当验收通过。

## 提案B：冻结R36文字冲突的独立勘误

冻结CLI合同及core decision.CODES约定 needs_contract=3、inconclusive=4；现有acceptance.json的R36文字及operations.schema.json部分const将3/4交换。实现已对齐CLI/core，并有90专项实测，但不能同时满足两份互相冲突的规范。

建议独立版本化勘误明确 CLI/core 为本次验收退出码：pass=0、fail=1、needs_contract=3、inconclusive=4；保留原冻结文件及冲突证据，运行/验收适配必须显式引用勘误，不偷偷改写历史。完整17CLI行为和R36真实runtime验收仍需实施。

需要决定：采用CLI/core的3/4定义作为规范冲突解决依据；不以专项测试视为全部CLI完成。

## 当前结论

A/B均待用户范围决定；其它不依赖此决定的真实验收继续。M1–M10尚未全部验收，production_ready=false。

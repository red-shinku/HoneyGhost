# Changelog

记录面向用户与部署的可见变更。格式参考 Keep a Changelog，版本号遵循语义化版本；
0.x 不承诺跨版本兼容。

## [Unreleased]

None

## [v0.1.0] - 2026-11-05

### Added

- 基础功能：
  - 对系统调用事件和文件访问事件的捕获。
  - Process、Role、Context 的维护。系统内维护进程树；支持自动发现容器服务或 systemd unit 服务；Context 的语义和规则目前不完备。  
  - 提供 CLI 工具查询系统状态，支持以 pid、roleID、contextID、rolelabel、eventtype 为键输出运行时事件流。  
  - 支持编写角色名单，令系统根据黑白名单机制捕获所指角色的事件。  
- 启动时预检目标内核：要求 ≥ 5.8、BTF 与 tracefs，不满足时逐项报错并退出。

### Changed

- `agent.Dockerfile` 改为基于 builder 镜像，不再在镜像内编译 userver。
- 版本信息由 `-DHNG_VERSION`、`-DHNG_COMMIT`、`-DHNG_BUILD_DATE` 注入，Makefile 自动传参。

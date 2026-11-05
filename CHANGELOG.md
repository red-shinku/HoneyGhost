# Changelog

记录面向用户与部署的可见变更。格式参考 Keep a Changelog，版本号遵循语义化版本；
0.x 不承诺跨版本兼容。

## [Unreleased]

### Added

- `hng_agent --version` 输出版本、提交与构建时间。
- `make package` 生成 `hghost` 与 `containerd-bridge` 的发布包及 `SHA256SUMS`。
- `make image` 本地构建两个容器镜像；`make test-go` 现在也覆盖 `containerd-bridge`。
- `deploy/ci/builder.Dockerfile`：预构建的构建工具链镜像，CI 与本地构建共用。
- 启动时预检目标内核：要求 ≥ 5.8、BTF 与 tracefs，不满足时逐项报错并退出。

### Changed

- `agent.Dockerfile` 改为基于 builder 镜像，不再在镜像内编译 userver。
- 版本信息由 `-DHNG_VERSION`、`-DHNG_COMMIT`、`-DHNG_BUILD_DATE` 注入，Makefile 自动传参。

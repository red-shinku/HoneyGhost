#!/bin/sh
# 由 proto/role_containerd_bridge.proto 重新生成 Go 侧协议代码。
#
# C++ 侧由 CMake 在构建时生成，Go 侧产物入库（internal/protocol/*.pb.go），
# 以便目标机不需要装 protoc 就能 go build。
#
# 依赖：protoc 与 protoc-gen-go（go install google.golang.org/protobuf/cmd/protoc-gen-go@latest）
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

protoc -I "$root/proto" \
    --go_out="$here" \
    --go_opt=module=honeyghost/containerd_bridge \
    "$root/proto/role_containerd_bridge.proto"

gofmt -l "$here/internal/protocol"

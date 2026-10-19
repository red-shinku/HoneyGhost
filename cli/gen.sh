#!/bin/sh
# 由 proto/ 下的协议文件重新生成 Go 侧代码到 internal/gen/。
#
# 依赖：protoc、protoc-gen-go 1.36.x、protoc-gen-go-grpc（与 grpc-go 版本配套）。
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

protoc -I "$root/proto" \
    --go_out="$here" --go_opt=module=honeyghost/cli \
    --go-grpc_out="$here" --go-grpc_opt=module=honeyghost/cli \
    --go_opt=Mfile_event.proto=honeyghost/cli/internal/gen/hng \
    --go_opt=Msyscall_event.proto=honeyghost/cli/internal/gen/hng \
    --go_opt=Mcli_service.proto=honeyghost/cli/internal/gen/hng/clisv \
    --go-grpc_opt=Mfile_event.proto=honeyghost/cli/internal/gen/hng \
    --go-grpc_opt=Msyscall_event.proto=honeyghost/cli/internal/gen/hng \
    --go-grpc_opt=Mcli_service.proto=honeyghost/cli/internal/gen/hng/clisv \
    "$root/proto/file_event.proto" \
    "$root/proto/syscall_event.proto" \
    "$root/proto/cli_service.proto"

gofmt -l "$here/internal/gen"

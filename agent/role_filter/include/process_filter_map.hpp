#ifndef HNG_PROCESS_FILTER_MAP_HPP_
#define HNG_PROCESS_FILTER_MAP_HPP_

#include <memory>
#include <system_error>
#include <vector>
#include "agent/event_data/include/process.hpp"

namespace hng {

/* 独占写接口：调用在名单维护线程上；操作须幂等，不可抛异常。
 * 返回错误时维护器保留待同步差异，下次刷新重试。
 */
class ProcessFilterMap {
   public:
    virtual ~ProcessFilterMap() = default;
    virtual std::error_code allow(Process process) noexcept = 0;
    virtual std::error_code erase(Process process) noexcept = 0;
};

/* 复制 fd（CLOEXEC），不接管传入 fd。三类探针各有一份 map，向全部同步。
 * 构造校验 ABI、空表；错误抛 std::system_error。只允许一个维护器写这些 map。
 * 无 libbpf 依赖，直接使用 Linux bpf syscall。
 */
std::unique_ptr<ProcessFilterMap> make_bpf_process_filter_map(
    const std::vector<int>& map_fds);

}  // namespace hng
#endif

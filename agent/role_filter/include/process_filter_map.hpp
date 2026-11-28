/**
 * @file
 * @brief 进程过滤 map 的独占写接口和 Linux 后端工厂。
 * @author inless427
 */
#ifndef HNG_PROCESS_FILTER_MAP_HPP_
#define HNG_PROCESS_FILTER_MAP_HPP_
#include <memory>
#include <system_error>
#include <vector>
#include "agent/bpf_loader/include/bpf_map.hpp"
#include "agent/event_data/include/process.hpp"

namespace hng {
/**
 * @brief 名单消费线程独占使用的 map 后端。
 * @details 实现必须幂等且不抛异常；错误由维护器记录并在后续刷新重试。
 */
class ProcessFilterMap {
   public:
    virtual ~ProcessFilterMap()                              = default;
    /**
     * @brief 向所有后端表写入进程忽略项。
     * @param[in] process 完整的 PID 与启动时间身份。
     * @return 成功时为空错误码；失败时可能已有部分表写入成功。
     */
    virtual std::error_code ignore(Process process) noexcept = 0;
    /**
     * @brief 从所有后端表撤销进程忽略项；不存在也视为成功。
     * @param[in] process 要撤销的完整进程身份。
     * @return 成功时为空错误码；失败时可能已有部分表删除成功。
     */
    virtual std::error_code erase(Process process) noexcept  = 0;
};

/**
 * @brief 为各探针的 map 创建统一写入后端。
 * @details 为每个 view 创建 BpfMapWriter；Writer 复制 fd 并设置 CLOEXEC，
 * map ABI 与空表校验由 BpfMapWriter 完成。
 * @param[in] maps 非空的借用 map 视图列表；视图在调用期间必须有效。
 * @return 独占拥有 Writer 与 fd 副本的后端。
 * @throws std::system_error 空列表、fd 无效、ABI 不符、表非空或内核调用失败。
 * @pre 同一组 map 只允许一个维护器写入。
 * @see BpfMapWriter
 */
std::unique_ptr<ProcessFilterMap> make_bpf_process_filter_map(
    std::vector<BpfMapView> maps);
}  // namespace hng
#endif

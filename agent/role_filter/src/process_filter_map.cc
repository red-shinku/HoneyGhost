/**
 * @file
 * @brief 基于 BpfMapWriter 的多探针过滤名单同步。
 * @author inless427
 */
#include "agent/role_filter/include/process_filter_map.hpp"
#include "agent/bpf_loader/include/bpf_map_writer.hpp"
#include "kernel/include/role_filter_types.h"
#include <linux/bpf.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <system_error>
#include <vector>

static_assert(sizeof(hng_role_filter_key) == 16);
static_assert(offsetof(hng_role_filter_key, start_time) == 8);

namespace hng::detail {
/** @brief 独占拥有 Writer 的名单 map 写入后端。 */
class BpfProcessFilterMap final : public ProcessFilterMap {
   public:
    explicit BpfProcessFilterMap(const std::vector<BpfMapView>& views)
    {
        if (views.empty())
            throw std::system_error(EINVAL, std::generic_category(),
                                    "BpfMapView is empty");
        const BpfMapSpec expected{BPF_MAP_TYPE_HASH, sizeof(hng_role_filter_key),
                                  sizeof(std::uint32_t),
                                  HNG_ROLE_FILTER_MAX_ENTRIES};
        writers_.reserve(views.size());
        for (const BpfMapView& view : views) {
            writers_.push_back(BpfMapWriter::create(view, expected,
                                                    BpfMapWriter::Options{true}));
        }
    }
    std::error_code ignore(Process process) noexcept override
    {
        if (!process.pid || !process.pid_start_time)
            return {EINVAL, std::generic_category()};
        const hng_role_filter_key key{process.pid, 0, process.pid_start_time};
        const std::uint32_t value = 1;
        std::error_code first;
        for (const auto& writer : writers_) {
            const std::error_code error = writer->update(&key, &value);
            if (error && !first) first = error;
        }
        return first;
    }
    std::error_code erase(Process process) noexcept override
    {
        if (!process.pid || !process.pid_start_time)
            return {EINVAL, std::generic_category()};
        const hng_role_filter_key key{process.pid, 0, process.pid_start_time};
        std::error_code first;
        for (const auto& writer : writers_) {
            const std::error_code error = writer->erase(&key);
            if (error && error.value() != ENOENT && !first) first = error;
        }
        return first;
    }

   private:
    std::vector<std::unique_ptr<BpfMapWriter>> writers_;
};
}  // namespace hng::detail
namespace hng {
std::unique_ptr<ProcessFilterMap> make_bpf_process_filter_map(
    std::vector<BpfMapView> maps)
{
    return std::make_unique<detail::BpfProcessFilterMap>(maps);
}
}  // namespace hng

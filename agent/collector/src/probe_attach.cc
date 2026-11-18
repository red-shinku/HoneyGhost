/**
 * @file probe_attach.cc
 * @brief 采集器的可选探针挂载设施实现
 */
#include "agent/collector/src/probe_attach.hpp"

#include "agent/util/include/log.hpp"
#include "agent/util/include/tracefs.hpp"

#include <cerrno>
#include <cstring>
#include <string_view>

namespace hng::detail {

namespace {

/// @brief tracepoint 程序 section 的固定前缀
constexpr std::string_view kTracepointPrefix = "tracepoint/";

/**
 * @brief 从程序 section 拆分 tracepoint 的组名与事件名
 * @param section 程序 section 名
 * @param group 输出：组名
 * @param event 输出：事件名
 * @return section 形如 tracepoint/<group>/<event> 且两段均非空时为 true
 */
bool parse_tracepoint_section(std::string_view section, std::string_view& group,
                              std::string_view& event)
{
    if (section.substr(0, kTracepointPrefix.size()) != kTracepointPrefix) {
        return false;
    }
    section.remove_prefix(kTracepointPrefix.size());
    const std::size_t separator = section.find('/');
    if (separator == std::string_view::npos) {
        return false;
    }
    const std::string_view parsed_group = section.substr(0, separator);
    const std::string_view parsed_event = section.substr(separator + 1);
    if (parsed_group.empty() || parsed_event.empty() ||
        parsed_event.find('/') != std::string_view::npos) {
        return false;
    }
    group = parsed_group;
    event = parsed_event;
    return true;
}

}  // namespace

int skip_missing_tracepoints(bpf_object* obj,
                             const std::filesystem::path& tracefs_root)
{
    if (!obj) {
        return 0;
    }
    if (tracefs_root.empty()) {
        HNG_LOG_WARN(
            "tracefs root is unavailable; tracepoint probes stay enabled");
        return 0;
    }

    int skipped          = 0;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, obj)
    {
        const char* section = ::bpf_program__section_name(program);
        if (!section) {
            continue;
        }
        std::string_view group;
        std::string_view event;
        if (!parse_tracepoint_section(section, group, event)) {
            continue;
        }
        if (tracepoint_present(tracefs_root, group, event)) {
            continue;
        }
        if (::bpf_program__set_autoload(program, false) != 0) {
            HNG_LOG_ERROR("cannot disable autoload for probe {}: {}", section,
                          std::strerror(errno));
            continue;
        }
        ++skipped;
        HNG_LOG_WARN("tracepoint {}/{} is absent; disabling probe {}", group,
                     event, section);
    }
    if (skipped > 0) {
        HNG_LOG_INFO("disabled {} tracepoint probe(s) absent from {}", skipped,
                     tracefs_root.string());
    }
    return skipped;
}

int attach_programs(bpf_object* obj, std::vector<bpf_link*>& links)
{
    if (!obj) {
        return 0;
    }

    int failures         = 0;
    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, obj)
    {
        if (!::bpf_program__autoload(program)) {
            continue;
        }
        const char* section = ::bpf_program__section_name(program);
        const char* label   = section ? section : "<unknown>";
        bpf_link* link      = ::bpf_program__attach(program);
        if (!link) {
            ++failures;
            HNG_LOG_WARN("probe {} attach failed: {}", label,
                         std::strerror(errno));
            continue;
        }
        links.push_back(link);
    }
    if (failures > 0) {
        HNG_LOG_WARN("attached {} probe(s), {} failed", links.size(), failures);
    }
    return failures;
}

}  // namespace hng::detail

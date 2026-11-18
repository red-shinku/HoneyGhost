/**
 * @file collector_skeleton_stub.hpp
 * @brief 采集器专用骨架替身；验证资源归属与回调，不参与生产构建。
 */
#ifndef HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#define HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

struct bpf_map {
    int fd;
};
inline int bpf_map__fd(const bpf_map* map) { return map ? map->fd : -EINVAL; }
using ring_callback = int (*)(void*, void*, std::size_t);
struct ring_buffer {
    int map_fd;
    int epoll_fd;
    ring_callback callback;
    void* context;
};

inline bool hng_test_open_failure      = false;
inline bool hng_test_load_failure      = false;
inline bool hng_test_attach_failure    = false;
inline bool hng_test_ring_failure      = false;
inline bool hng_test_bad_cleanup_order = false;
inline int hng_test_live_skeletons     = 0;
inline int hng_test_live_rings         = 0;
inline int hng_test_live_links         = 0;
inline int hng_test_next_fd            = 100;
inline int hng_test_last_filter_fd     = -1;
inline int hng_test_last_event_fd      = -1;
inline std::optional<int> hng_test_event_fd_override;
inline std::optional<int> hng_test_filter_fd_override;
inline int hng_test_open_calls             = 0;
inline int hng_test_load_calls             = 0;
inline int hng_test_attach_calls           = 0;
inline int hng_test_detach_calls           = 0;
inline int hng_test_link_destroy_calls     = 0;
inline int hng_test_set_autoload_calls     = 0;
inline int hng_test_ring_calls             = 0;
inline int hng_test_consume_calls          = 0;
inline int hng_test_consume_successes      = 0;
inline int hng_test_consume_error          = -EIO;
inline std::size_t hng_test_consume_budget = 0;
inline bool hng_test_deliver_payload       = false;
inline void* hng_test_payload              = nullptr;
inline std::size_t hng_test_payload_size   = 0;
inline int hng_test_callback_result        = 0;
inline ring_buffer* hng_test_last_ring     = nullptr;
inline std::vector<ring_buffer*> hng_test_rings;

/// @brief 按 section 注入挂载失败，用于验证单个探针失败不影响其余
inline std::vector<std::string> hng_test_attach_failure_sections;

inline ring_buffer* ring_buffer__new(int fd, ring_callback callback,
                                     void* context, void*)
{
    ++hng_test_ring_calls;
    if (hng_test_ring_failure || fd < 0) return nullptr;
    auto* buffer = new ring_buffer{fd, hng_test_next_fd++, callback, context};
    hng_test_rings.push_back(buffer);
    ++hng_test_live_rings;
    hng_test_last_ring = buffer;
    return buffer;
}

inline void ring_buffer__free(ring_buffer* buffer)
{
    if (!buffer) return;
    hng_test_rings.erase(
        std::remove(hng_test_rings.begin(), hng_test_rings.end(), buffer),
        hng_test_rings.end());
    if (hng_test_last_ring == buffer) hng_test_last_ring = nullptr;
    --hng_test_live_rings;
    delete buffer;
}

inline int ring_buffer__consume_n(ring_buffer* buffer, std::size_t budget)
{
    if (++hng_test_consume_calls > 16)
        throw std::runtime_error("consume did not stop");
    hng_test_consume_budget = budget;
    if (budget == 0) return 0;
    if (hng_test_deliver_payload) {
        hng_test_callback_result = buffer->callback(
            buffer->context, hng_test_payload, hng_test_payload_size);
        if (hng_test_callback_result) return hng_test_callback_result;
        return 1;
    }
    if (hng_test_consume_successes-- > 0) return 1;
    return hng_test_consume_error;
}

inline int ring_buffer__consume(ring_buffer* buffer)
{
    return ring_buffer__consume_n(buffer, static_cast<std::size_t>(-1));
}

inline int ring_buffer__epoll_fd(const ring_buffer* buffer)
{
    return buffer ? buffer->epoll_fd : -1;
}

// ============================================================
// BPF 对象、程序与链接替身
// ============================================================

struct bpf_program {
    std::string section;
    bool autoload = true;
    bool attached = false;
};

struct bpf_object {
    std::vector<bpf_program> programs;
};

struct bpf_link {
    bpf_program* program;
    int id;
};

inline bpf_object* hng_test_last_object = nullptr;

inline std::vector<bpf_link*> hng_test_links;

inline bpf_program* bpf_object__next_program(const bpf_object* obj,
                                             bpf_program* prev)
{
    if (!obj || obj->programs.empty()) return nullptr;
    auto* mutable_obj = const_cast<bpf_object*>(obj);
    if (!prev) return &mutable_obj->programs.front();
    const auto index =
        static_cast<std::size_t>(prev - mutable_obj->programs.data()) + 1;
    if (index >= mutable_obj->programs.size()) return nullptr;
    return &mutable_obj->programs[index];
}

#define bpf_object__for_each_program(pos, obj)                               \
    for ((pos) = bpf_object__next_program((obj), nullptr); (pos) != nullptr; \
         (pos) = bpf_object__next_program((obj), (pos)))

inline const char* bpf_program__section_name(const bpf_program* program)
{
    return program ? program->section.c_str() : nullptr;
}

inline bool bpf_program__autoload(const bpf_program* program)
{
    return program && program->autoload;
}

inline int bpf_program__set_autoload(bpf_program* program, bool autoload)
{
    ++hng_test_set_autoload_calls;
    if (!program) return -EINVAL;
    program->autoload = autoload;
    return 0;
}

inline bpf_link* bpf_program__attach(const bpf_program* program)
{
    ++hng_test_attach_calls;
    if (!program || hng_test_attach_failure) return nullptr;
    if (std::find(hng_test_attach_failure_sections.begin(),
                  hng_test_attach_failure_sections.end(),
                  program->section) != hng_test_attach_failure_sections.end()) {
        return nullptr;
    }
    auto* link =
        new bpf_link{const_cast<bpf_program*>(program), hng_test_next_fd++};
    hng_test_links.push_back(link);
    ++hng_test_live_links;
    link->program->attached = true;
    return link;
}

inline int bpf_link__destroy(bpf_link* link)
{
    if (!link) return -EINVAL;
    ++hng_test_link_destroy_calls;
    hng_test_links.erase(
        std::remove(hng_test_links.begin(), hng_test_links.end(), link),
        hng_test_links.end());
    link->program->attached = false;
    --hng_test_live_links;
    delete link;
    return 0;
}

// ============================================================
// 骨架 program 清单
// ============================================================

/// @brief 按骨架名返回其程序 section 清单
inline const std::vector<std::string>& hng_test_program_sections(
    std::string_view skeleton)
{
    static const std::vector<std::string> files = {
        "tracepoint/syscalls/sys_enter_openat",
        "tracepoint/syscalls/sys_enter_open",
        "tracepoint/syscalls/sys_enter_creat",
        "tracepoint/syscalls/sys_enter_openat2",
    };
    static const std::vector<std::string> networks = {
        "tracepoint/syscalls/sys_enter_connect",
        "tracepoint/syscalls/sys_enter_sendto",
        "tracepoint/syscalls/sys_enter_sendmsg",
    };
    static const std::vector<std::string> syscalls = {
        "kprobe/wake_up_new_task",
        "tracepoint/sched/sched_process_exit",
        "tracepoint/syscalls/sys_enter_execve",
        "tracepoint/syscalls/sys_enter_execveat",
        "tracepoint/syscalls/sys_enter_setuid",
        "tracepoint/syscalls/sys_enter_setgid",
        "tracepoint/syscalls/sys_enter_capset",
        "tracepoint/syscalls/sys_enter_unshare",
        "tracepoint/syscalls/sys_enter_setns",
        "tracepoint/syscalls/sys_enter_open",
        "tracepoint/syscalls/sys_enter_openat",
        "tracepoint/syscalls/sys_enter_openat2",
        "tracepoint/syscalls/sys_enter_creat",
        "tracepoint/syscalls/sys_enter_unlink",
        "tracepoint/syscalls/sys_enter_link",
        "tracepoint/syscalls/sys_enter_rename",
        "tracepoint/syscalls/sys_enter_renameat",
        "tracepoint/syscalls/sys_enter_renameat2",
        "tracepoint/syscalls/sys_enter_mmap",
        "tracepoint/syscalls/sys_enter_mprotect",
        "tracepoint/syscalls/sys_enter_connect",
        "tracepoint/syscalls/sys_enter_socket",
        "tracepoint/syscalls/sys_enter_bind",
        "tracepoint/syscalls/sys_enter_ptrace",
        "tracepoint/syscalls/sys_enter_bpf",
    };
    if (skeleton == "files_collector") return files;
    if (skeleton == "networks_collector") return networks;
    if (skeleton == "syscalls_collector") return syscalls;
    static const std::vector<std::string> empty;
    return empty;
}

inline std::vector<bpf_program> hng_test_make_programs(std::string_view skeleton)
{
    std::vector<bpf_program> programs;
    for (const std::string& section : hng_test_program_sections(skeleton)) {
        programs.push_back(bpf_program{section, true, false});
    }
    return programs;
}

/** @brief 每个骨架使用不同的 fd，只检查它自己关联的 ringbuf 的销毁顺序。 */
#define HNG_TEST_SKELETON(name, ring)                                             \
    struct name {                                                                 \
        bpf_map ring##_storage{                                                   \
            hng_test_event_fd_override.value_or(hng_test_next_fd++)};             \
        bpf_map filter_storage{                                                   \
            hng_test_filter_fd_override.value_or(hng_test_next_fd++)};            \
        bpf_map failures_storage{hng_test_next_fd++};                             \
        struct {                                                                  \
            bpf_map* ring;                                                        \
            bpf_map* hng_role_filter;                                             \
            bpf_map* reserve_failures;                                            \
        } maps;                                                                   \
        bpf_object* obj = nullptr;                                                \
        name() : maps{&ring##_storage, &filter_storage, &failures_storage}        \
        {                                                                         \
            hng_test_last_event_fd  = ring##_storage.fd;                          \
            hng_test_last_filter_fd = filter_storage.fd;                          \
            obj                  = new bpf_object{hng_test_make_programs(#name)}; \
            hng_test_last_object = obj;                                           \
        }                                                                         \
    };                                                                            \
    inline name* name##__open()                                                   \
    {                                                                             \
        ++hng_test_open_calls;                                                    \
        if (hng_test_open_failure) return nullptr;                                \
        auto* result = new name;                                                  \
        ++hng_test_live_skeletons;                                                \
        return result;                                                            \
    }                                                                             \
    inline int name##__load(name* skeleton)                                       \
    {                                                                             \
        ++hng_test_load_calls;                                                    \
        if (!skeleton) return -EINVAL;                                            \
        return hng_test_load_failure ? -EINVAL : 0;                               \
    }                                                                             \
    inline int name##__attach(name*)                                              \
    {                                                                             \
        ++hng_test_attach_calls;                                                  \
        return hng_test_attach_failure ? -EINVAL : 0;                             \
    }                                                                             \
    inline void name##__detach(name* p)                                           \
    {                                                                             \
        if (!p) return;                                                           \
        ++hng_test_detach_calls;                                                  \
    }                                                                             \
    inline void name##__destroy(name* p)                                          \
    {                                                                             \
        if (!p) return;                                                           \
        for (const auto* buffer : hng_test_rings) {                               \
            if (buffer->map_fd == p->maps.ring->fd)                               \
                hng_test_bad_cleanup_order = true;                                \
        }                                                                         \
        if (hng_test_last_object == p->obj) hng_test_last_object = nullptr;       \
        delete p->obj;                                                            \
        --hng_test_live_skeletons;                                                \
        delete p;                                                                 \
    }                                                                             \
    inline name* name##__open_and_load()                                          \
    {                                                                             \
        name* skeleton = name##__open();                                          \
        if (!skeleton) return nullptr;                                            \
        if (name##__load(skeleton) != 0) {                                        \
            name##__destroy(skeleton);                                            \
            return nullptr;                                                       \
        }                                                                         \
        return skeleton;                                                          \
    }
HNG_TEST_SKELETON(files_collector, file_access_events)
HNG_TEST_SKELETON(syscalls_collector, syscall_events)
HNG_TEST_SKELETON(networks_collector, network_events)
#undef HNG_TEST_SKELETON
#endif

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
#include <vector>

struct bpf_map { int fd; };
inline int bpf_map__fd(const bpf_map* map) { return map ? map->fd : -EINVAL; }
using ring_callback = int (*)(void*, void*, std::size_t);
struct ring_buffer {
    int map_fd;
    ring_callback callback;
    void* context;
};

inline bool hng_test_open_failure = false;
inline bool hng_test_attach_failure = false;
inline bool hng_test_ring_failure = false;
inline bool hng_test_bad_cleanup_order = false;
inline int hng_test_live_skeletons = 0;
inline int hng_test_live_rings = 0;
inline int hng_test_next_fd = 100;
inline int hng_test_last_filter_fd = -1;
inline int hng_test_last_event_fd = -1;
inline std::optional<int> hng_test_event_fd_override;
inline std::optional<int> hng_test_filter_fd_override;
inline int hng_test_open_calls = 0;
inline int hng_test_attach_calls = 0;
inline int hng_test_ring_calls = 0;
inline int hng_test_poll_calls = 0;
inline int hng_test_poll_successes = 0;
inline int hng_test_poll_error = -EINTR;
inline int hng_test_poll_timeout = 0;
inline bool hng_test_deliver_payload = false;
inline void* hng_test_payload = nullptr;
inline std::size_t hng_test_payload_size = 0;
inline int hng_test_callback_result = 0;
inline ring_buffer* hng_test_last_ring = nullptr;
inline std::vector<ring_buffer*> hng_test_rings;

inline ring_buffer* ring_buffer__new(int fd, ring_callback callback, void* context, void*)
{
    ++hng_test_ring_calls;
    if (hng_test_ring_failure || fd < 0) return nullptr;
    auto* buffer = new ring_buffer{fd, callback, context};
    hng_test_rings.push_back(buffer);
    ++hng_test_live_rings;
    hng_test_last_ring = buffer;
    return buffer;
}

inline void ring_buffer__free(ring_buffer* buffer)
{
    if (!buffer) return;
    hng_test_rings.erase(std::remove(hng_test_rings.begin(), hng_test_rings.end(), buffer),
                        hng_test_rings.end());
    if (hng_test_last_ring == buffer) hng_test_last_ring = nullptr;
    --hng_test_live_rings;
    delete buffer;
}

inline int ring_buffer__poll(ring_buffer* buffer, int timeout)
{
    // 防止 collect 忽略错误时把整个测试挂死。
    if (++hng_test_poll_calls > 16) throw std::runtime_error("poll did not stop");
    hng_test_poll_timeout = timeout;
    if (hng_test_deliver_payload) {
        hng_test_callback_result = buffer->callback(buffer->context, hng_test_payload,
                                                  hng_test_payload_size);
        if (hng_test_callback_result) return hng_test_callback_result;
    }
    if (hng_test_poll_successes-- > 0) return 1;
    return hng_test_poll_error;
}

/** @brief 每个骨架使用不同的 fd，只检查它自己关联的 ringbuf 的销毁顺序。 */
#define HNG_TEST_SKELETON(name, ring) \
struct name { \
    bpf_map ring##_storage{hng_test_event_fd_override.value_or(hng_test_next_fd++)}; \
    bpf_map filter_storage{hng_test_filter_fd_override.value_or(hng_test_next_fd++)}; \
    struct { bpf_map* ring; bpf_map* hng_role_filter; } maps; \
    name() : maps{&ring##_storage, &filter_storage} { \
        hng_test_last_event_fd = ring##_storage.fd; \
        hng_test_last_filter_fd = filter_storage.fd; \
    } \
}; \
inline name* name##__open_and_load() { \
    ++hng_test_open_calls; \
    if (hng_test_open_failure) return nullptr; \
    auto* result = new name; \
    ++hng_test_live_skeletons; \
    return result; \
} \
inline int name##__attach(name*) { \
    ++hng_test_attach_calls; \
    return hng_test_attach_failure ? -EINVAL : 0; \
} \
inline void name##__destroy(name* p) { \
    if (!p) return; \
    for (const auto* buffer : hng_test_rings) { \
        if (buffer->map_fd == p->maps.ring->fd) hng_test_bad_cleanup_order = true; \
    } \
    --hng_test_live_skeletons; \
    delete p; \
}
HNG_TEST_SKELETON(files_collector, file_access_events)
HNG_TEST_SKELETON(syscalls_collector, syscall_events)
HNG_TEST_SKELETON(networks_collector, network_events)
#undef HNG_TEST_SKELETON
#endif

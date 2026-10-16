/**
 * @file
 * @brief 采集器资源和事件回调测试使用的骨架替身，不参与生产构建。
 */
#ifndef HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#define HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#include <cerrno>
#include <cstddef>

struct bpf_map { int fd; };
inline int bpf_map__fd(const bpf_map* map) { return map->fd; }
using ring_callback = int (*)(void*, void*, std::size_t);
struct ring_buffer { ring_callback callback; void* context; };
inline bool hng_test_open_failure = false, hng_test_attach_failure = false;
inline bool hng_test_ring_failure = false, hng_test_bad_cleanup_order = false;
inline int hng_test_live_skeletons = 0, hng_test_live_rings = 0;
inline void* hng_test_payload = nullptr;
inline std::size_t hng_test_payload_size = 0;
inline int hng_test_callback_result = 0;

inline ring_buffer* ring_buffer__new(int, ring_callback callback, void* context, void*)
{
    if (hng_test_ring_failure) return nullptr;
    ++hng_test_live_rings;
    return new ring_buffer{callback, context};
}
inline void ring_buffer__free(ring_buffer* buffer)
{
    if (buffer) { --hng_test_live_rings; delete buffer; }
}
inline int ring_buffer__poll(ring_buffer* buffer, int)
{
    if (hng_test_payload)
        hng_test_callback_result = buffer->callback(buffer->context, hng_test_payload,
                                                  hng_test_payload_size);
    return -EINTR;
}

/** @brief 生成固定 fd 的测试骨架，并跟踪申请和释放。 */
#define HNG_TEST_SKELETON(name, ring, id) \
struct name { \
    bpf_map ring##_storage{id}; \
    bpf_map filter_storage{id + 1}; \
    struct { bpf_map* ring; bpf_map* hng_role_filter; } maps; \
    name() : maps{&ring##_storage, &filter_storage} {} \
}; \
inline name* name##__open_and_load() { \
    if (hng_test_open_failure) return nullptr; \
    ++hng_test_live_skeletons; return new name; \
} \
inline int name##__attach(name*) { return hng_test_attach_failure ? -EINVAL : 0; } \
inline void name##__destroy(name* p) { \
    if (p) { \
        if (hng_test_live_rings) hng_test_bad_cleanup_order = true; \
        --hng_test_live_skeletons; delete p; \
    } \
}
HNG_TEST_SKELETON(files_collector, file_access_events, 100)
HNG_TEST_SKELETON(syscalls_collector, syscall_events, 200)
HNG_TEST_SKELETON(networks_collector, network_events, 300)
#undef HNG_TEST_SKELETON
#endif

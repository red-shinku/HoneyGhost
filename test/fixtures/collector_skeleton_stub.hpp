#ifndef HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#define HNG_TEST_COLLECTOR_SKELETON_STUB_HPP_
#include <cerrno>
#include <cstddef>

struct bpf_map { int fd; };
inline int bpf_map__fd(const bpf_map* m) { return m->fd; }
struct ring_buffer {};
using ring_callback = int (*)(void*, void*, std::size_t);
inline bool hng_test_attach_failure = false;
inline bool hng_test_ring_failure = false;
inline int hng_test_live_skeletons = 0;
inline int hng_test_live_rings = 0;
inline ring_buffer* ring_buffer__new(int, ring_callback, void*, void*)
{
    if (hng_test_ring_failure) return nullptr;
    ++hng_test_live_rings; return new ring_buffer;
}
inline void ring_buffer__free(ring_buffer* b) { if (b) { --hng_test_live_rings; delete b; } }
inline int ring_buffer__poll(ring_buffer*, int) { return -EINTR; }

#define HNG_TEST_SKELETON(name, ring, id) \
struct name { \
    bpf_map ring##_storage{id}; \
    bpf_map filter_storage{id + 1}; \
    struct { bpf_map* ring; bpf_map* hng_role_filter; } maps; \
    name() : maps{&ring##_storage, &filter_storage} {} \
}; \
inline name* name##__open_and_load() { ++hng_test_live_skeletons; return new name; } \
inline int name##__attach(name*) { return hng_test_attach_failure ? -EINVAL : 0; } \
inline void name##__destroy(name* p) { if (p) { --hng_test_live_skeletons; delete p; } }

HNG_TEST_SKELETON(files_collector, file_access_events, 100)
HNG_TEST_SKELETON(syscalls_collector, syscall_events, 200)
HNG_TEST_SKELETON(networks_collector, network_events, 300)
#undef HNG_TEST_SKELETON
#endif

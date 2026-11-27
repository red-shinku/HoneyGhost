/**
 * @file test_bpf_public_header.cc
 * @brief BPF map 公共头可在没有 libbpf 与骨架的环境中独立编译。
 */

#include "agent/bpf_loader/include/bpf_map.hpp"
#include "agent/bpf_loader/include/bpf_map_reader.hpp"
#include "agent/bpf_loader/include/bpf_map_writer.hpp"

#ifdef __LINUX_BPF_H__
#error "bpf public headers must not include linux/bpf.h"
#endif

#ifdef __LIBBPF_BPF_H
#error "bpf public headers must not include bpf/bpf.h"
#endif

#ifdef __LIBBPF_LIBBPF_H
#error "bpf public headers must not include bpf/libbpf.h"
#endif

#include <type_traits>

static_assert(std::is_move_constructible_v<hng::BpfMapWriter>);
static_assert(std::is_move_assignable_v<hng::BpfMapWriter>);
static_assert(!std::is_copy_constructible_v<hng::BpfMapWriter>);
static_assert(!std::is_copy_assignable_v<hng::BpfMapWriter>);

static_assert(std::is_move_constructible_v<hng::BpfMapReader>);
static_assert(std::is_move_assignable_v<hng::BpfMapReader>);
static_assert(!std::is_copy_constructible_v<hng::BpfMapReader>);
static_assert(!std::is_copy_assignable_v<hng::BpfMapReader>);

int main() { return 0; }

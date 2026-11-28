/**
 * @file bpf_program_group.cc
 * @brief 多个 BPF 程序加载器的生命周期编排实现。
 */

#include "agent/bpf_loader/include/bpf_program_group.hpp"

namespace hng {

void BpfProgramGroup::add(BpfProgramLoader& loader)
{
    loaders_.push_back(&loader);
}

bool BpfProgramGroup::prepare_all()
{
    for (BpfProgramLoader* loader : loaders_) {
        if (!loader->prepare()) {
            return false;
        }
    }
    return true;
}

bool BpfProgramGroup::attach_all()
{
    for (BpfProgramLoader* loader : loaders_) {
        if (!loader->attach()) {
            detach_all();
            return false;
        }
    }
    return true;
}

void BpfProgramGroup::detach_all() noexcept
{
    for (BpfProgramLoader* loader : loaders_) {
        loader->detach();
    }
}

std::vector<BpfProgramStats> BpfProgramGroup::stats() const
{
    std::vector<BpfProgramStats> snapshot;
    snapshot.reserve(loaders_.size());
    for (const BpfProgramLoader* loader : loaders_) {
        snapshot.push_back(loader->stats());
    }
    return snapshot;
}

}  // namespace hng

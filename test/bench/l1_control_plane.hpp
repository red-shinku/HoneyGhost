/**
 * @file l1_control_plane.hpp
 * @brief 控制面 L1 替身与按语料播种
 * @details
 * 供 engine 与 cli 段共用：进程、角色、context 三个维度的内存替身，以及按
 * 语义事件语料播种的辅助函数。替身不加锁、不拥有线程，只服务引擎线程的
 * 读写；播种必须在该引擎线程启动前完成。
 */

#ifndef HNG_TEST_BENCH_L1_CONTROL_PLANE_HPP_
#define HNG_TEST_BENCH_L1_CONTROL_PLANE_HPP_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "agent/control_plane/include/context_service.hpp"
#include "agent/control_plane/include/process_service.hpp"
#include "agent/control_plane/include/role_service.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/syscall_event.hpp"

namespace bench {
namespace l1 {

/// @brief 进程注册通知替身：只计数
class FakeProcessJoin final : public ProcessJoinService {
   public:
    std::uint64_t registered   = 0;  ///< register_pid 次数
    std::uint64_t unregistered = 0;  ///< unregister_pid 次数

    void register_pid(hng::event_head) override { ++registered; }
    void unregister_pid(hng::Process) override { ++unregistered; }
};

/// @brief 进程镜像更新通知替身：只计数
class FakeProcessUpdate final : public ProcessUpdateService {
   public:
    std::uint64_t updates = 0;  ///< update_exe_image 次数

    void update_exe_image(hng::Process, std::string) override { ++updates; }
};

/**
 * @brief 进程查询替身
 * @details 只服务事件路径的 lookup；按 (pid, pid_start_time) 命中，返回种子
 *          时写入的镜像。resolve 与 stats 返回空。
 */
class FakeProcessLookup final : public ProcessLookupService {
   public:
    void seed(hng::Process process, std::string exe)
    {
        hng::ProcessMessage message;
        message.pid            = process.pid;
        message.pid_start_time = process.pid_start_time;
        message.exe            = std::move(exe);
        images_[process]       = std::move(message);
    }

    std::optional<hng::ProcessMessage> lookup(hng::Process process) const override
    {
        const auto it = images_.find(process);
        if (it == images_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<hng::Process> resolve(std::uint32_t) const override
    {
        return std::nullopt;
    }

    ProcessManagerStats stats() const override { return {}; }

   private:
    std::unordered_map<hng::Process, hng::ProcessMessage> images_;
};

/// @brief 角色继承通知替身：只计数
class FakeRoleJoin final : public RoleJoinService {
   public:
    std::uint64_t binds = 0;  ///< bind_to_role 次数

    void bind_to_role(hng::Process, hng::Process) override { ++binds; }
};

/**
 * @brief 角色查询替身
 * @details pid → roleID；role(id) 总是返回 "role-label-<id>"，其余查询返回空。
 */
class FakeRoleLookup final : public RoleLookupService {
   public:
    void seed(std::uint32_t pid, std::uint32_t role_id)
    {
        role_of_pid_[pid] = role_id;
    }

    std::optional<std::uint32_t> lookup(hng::Process process) const override
    {
        const auto it = role_of_pid_.find(process.pid);
        if (it == role_of_pid_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<hng::Role> role(std::uint32_t role_id) const override
    {
        return hng::Role{role_id, "role-label-" + std::to_string(role_id)};
    }

    std::optional<hng::Process> main_process(std::uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Role> roles() const override { return {}; }

    std::vector<hng::Role> supervised_roles() const override { return {}; }

    std::vector<hng::Role> ignore_roles() const override { return {}; }

    std::optional<hng::role::RoleIdentity> identity(std::uint32_t) const override
    {
        return std::nullopt;
    }

    std::vector<hng::Process> members(std::uint32_t) const override { return {}; }

    RoleManagerStats stats() const override { return {}; }

   private:
    std::unordered_map<std::uint32_t, std::uint32_t> role_of_pid_;
};

/**
 * @brief context 查询 / 登记 / 更新替身
 * @details lookup 命中种子或引擎线程登记的 map；register_context 记入；
 *          其余空操作或空返回。表只由引擎线程写，主线程只在 run() 前读。
 */
class FakeContextService final : public ContextLookupService,
                                 public ContextJoinService,
                                 public ContextUpdateService {
   public:
    struct Key {
        hng::Process process;
        bool operator==(const Key& other) const
        {
            return process == other.process;
        }
    };
    struct KeyHash {
        std::size_t operator()(const Key& key) const
        {
            return std::hash<hng::Process>{}(key.process);
        }
    };

    void seed(hng::Process process, std::uint32_t context_id)
    {
        contexts_[Key{process}] = context_id;
    }

    std::optional<std::uint32_t> lookup(hng::Process process) const override
    {
        const auto it = contexts_.find(Key{process});
        if (it == contexts_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<std::uint32_t> lookup_extra(hng::Process) const override
    {
        return std::nullopt;
    }

    std::vector<std::uint32_t> contexts_by_attr(hng::contextattr) const override
    {
        return {};
    }

    std::optional<ContextProcessSet> members(std::uint32_t) const override
    {
        return std::nullopt;
    }

    ContextManagerStats stats() const override { return {}; }

    void register_context(hng::Process process, ContextDeriveDecision decision,
                          ContextParentRef) override
    {
        ++register_calls;
        contexts_[Key{process}] = decision.contextID;
    }

    void register_extra_context(hng::Process, std::uint32_t,
                                hng::contextattr) override
    {
    }

    void unregister_context(hng::Process process) override
    {
        contexts_.erase(Key{process});
    }

    void bind_to_ctxroot(hng::Process, ContextParentRef) override {}

    void set_attr(hng::Process, std::uint32_t, hng::contextattr) override {}

    std::uint64_t register_calls = 0;  ///< register_context 次数

   private:
    std::unordered_map<Key, std::uint32_t, KeyHash> contexts_;
};

/// @brief 种子过程与结果计数
struct SeedCounts {
    std::uint64_t processes = 0;  ///< 去重后的进程数
    std::uint64_t roles     = 0;  ///< 写入角色归属的进程数
    std::uint64_t contexts  = 0;  ///< 写入 context 归属的进程数
};

/// @brief 按哈希决定该进程是否在 --settled 比例内落定
inline bool settled_by_hash(std::size_t hash, double ratio)
{
    if (ratio >= 1.0) {
        return true;
    }
    if (ratio <= 0.0) {
        return false;
    }
    return static_cast<double>(hash % 1000) < ratio * 1000.0;
}

/**
 * @brief 按 settled 比例为语料中出现过的进程播种角色替身
 * @param[in] events 语义事件
 * @param[in] settled 角色归属落定比例
 * @param[in,out] role_lookup 角色查询替身
 * @return 实际播种的进程数
 * @note 进程身份取 (pid, pid_start_time)，同身份只处理一次；pid 为 0 的森林根
 *       不参与种子。L1 与 L2 共用本函数，角色替身的行为保持一致。
 */
inline std::uint64_t seed_role_substitutes(
    const std::vector<hng::syscall_semantic_data>& events, double settled,
    FakeRoleLookup& role_lookup)
{
    std::unordered_set<hng::Process> seen;
    std::uint64_t seeded = 0;
    for (const hng::syscall_semantic_data& event : events) {
        const hng::Process process{event.head.pid, event.head.pid_start_time};
        if (process.pid == 0 || !seen.insert(process).second) {
            continue;
        }
        const std::size_t hash = std::hash<hng::Process>{}(process);
        if (!settled_by_hash(hash, settled)) {
            continue;
        }
        role_lookup.seed(process.pid, static_cast<std::uint32_t>(hash % 8) + 1);
        ++seeded;
    }
    return seeded;
}

/**
 * @brief 用 corpus 出现过的进程给 L1 替身做种子
 * @param[in] events 语义事件
 * @param[in] settled 角色与 context 归属落定比例
 * @param[in,out] process_lookup 进程查询替身
 * @param[in,out] role_lookup 角色查询替身
 * @param[in,out] context_service context 替身
 * @param[out] counts 种子计数
 * @note 进程镜像对所有进程写入；角色与 context 按 settled 比例写入，未写入的
 *       查询不到，走未落定路径。pid 为 0 的森林根不参与种子。
 */
inline void seed_services(const std::vector<hng::syscall_semantic_data>& events,
                          double settled, FakeProcessLookup& process_lookup,
                          FakeRoleLookup& role_lookup,
                          FakeContextService& context_service, SeedCounts& counts)
{
    std::unordered_set<hng::Process> seen;
    for (const hng::syscall_semantic_data& event : events) {
        const hng::Process process{event.head.pid, event.head.pid_start_time};
        if (process.pid == 0 || !seen.insert(process).second) {
            continue;
        }
        ++counts.processes;
        process_lookup.seed(process,
                            "/usr/bin/proc-" + std::to_string(process.pid));
        const std::size_t hash = std::hash<hng::Process>{}(process);
        if (!settled_by_hash(hash, settled)) {
            continue;
        }
        context_service.seed(process, static_cast<std::uint32_t>(hash % 16) + 1);
        ++counts.contexts;
    }
    counts.roles = seed_role_substitutes(events, settled, role_lookup);
}

}  // namespace l1
}  // namespace bench

#endif  // HNG_TEST_BENCH_L1_CONTROL_PLANE_HPP_

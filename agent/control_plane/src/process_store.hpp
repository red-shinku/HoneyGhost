/**
 * @file process_store.hpp
 * @brief 控制平面进程树与墓碑的存储层
 * @details
 * 持有实进程分片、虚拟根分片、墓碑表与落地计数，负责注册、注销、镜像更新与
 * 退役规则；不持队列与线程、不发通知，可独立单测。
 * @author red_shinku
 * @date 2026.10.24
 */

#ifndef HNG_PROCESS_STORE_HPP_
#define HNG_PROCESS_STORE_HPP_

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <variant>

#include "agent/control_plane/include/process_stats.hpp"
#include "agent/event_data/include/process.hpp"
#include "agent/util/include/tombstone_table.hpp"

/**
 * @brief 进程树结构的分片，使用读写锁管理一个分片
 * @details map 单键 PID，值 Process
 */
struct ProcessShard {
    // mutable，在 const 函数中锁变量允许修改
    mutable std::shared_mutex smtx;
    std::unordered_map<uint32_t, hng::ProcessMessage>
        process;  ///< PID -> Process
};

/**
 * @brief 虚拟根进程的 map 键
 */
struct VProcessKey {
    uint32_t pid;
    uint64_t pid_start_time;

    bool operator==(const VProcessKey& other) const
    {
        return other.pid == pid && other.pid_start_time == pid_start_time;
    }
};

/**
 * @brief 虚拟根进程的 map 分片
 */
struct VProcessShard {
    struct KeyHash {
        std::size_t operator()(const VProcessKey& k) const
        {
            return std::hash<uint32_t>{}(k.pid) ^
                   (std::hash<uint64_t>{}(k.pid_start_time) << 1);
        }
    };
    mutable std::shared_mutex smtx;
    std::unordered_map<VProcessKey, hng::ProcessMessage, KeyHash> vprocess;
};

/// @brief 进程存储层接收的关系修复配置
/// @details 默认值可直接运行；测试通过覆盖参数注入假时钟与小容量、短寿命。
struct ProcessStoreOptions {
    hng::TombstoneOptions tombstones;  ///< 已退出进程墓碑表
    /// 当前时间来源，必须是单调时钟
    std::function<hng::RelationTimePoint()> now = [] {
        return std::chrono::steady_clock::now();
    };
};

/// @brief 一次落地的结果：只承载 Store 之外需要处理的动作
struct ProcessChange {
    enum class Kind : uint8_t {
        NONE,    ///< 幂等重放、墓碑拒收、镜像未命中
        ADDED,   ///< 新实例已进入实进程树（含替换同 pid 的旧实例）
        REMOVED  ///< 退出已落地（含未登记身份的迟到退出）
    };
    Kind kind = Kind::NONE;
    std::optional<hng::Process> exited;  ///< 需下发 on_process_exited 的身份
    hng::Process child{};                ///< Kind::ADDED 时供角色继承
    hng::Process parent{};               ///< 该子进程的父进程；pid 为 0 仍转交
};

/**
 * @brief 进程树、虚拟根与墓碑的存储层
 * @details
 * 持有 32 路实进程分片、32 路虚拟根分片、墓碑表与落地计数，负责注册、注销、
 * 镜像更新与退役规则。
 *
 * 写入口只由 ProcessManager 的消费线程调用，一次落地对应一个写方法：写表并
 * 计数，返回前清理过期墓碑；未产生结果的拒收与幂等路径同样清理。查询入口可被
 * 任意线程并发调用。
 *
 * Store 不发通知、不碰队列；需要调用方处理的身份经返回值交出。
 *
 * 锁序：每个分片一把读写锁，按 pid 哈希落到对应分片；墓碑表自持一把互斥锁，
 * 是叶子锁，持分片锁时不取墓碑锁，持墓碑锁时不取分片锁；单次落地最多持一把
 * 分片锁，退役与父计数都在释放分片锁之后。
 * @see ProcessStoreOptions
 * @see ProcessChange
 */
class ProcessStore {
   public:
    /// @param options 墓碑表与时钟
    explicit ProcessStore(ProcessStoreOptions options = {});

    /// @brief 注册一个进程
    /// @param msg 进程记录；身份为 pid + pid_start_time
    /// @return 新身份插入或替换同 pid 的旧实例时为 ADDED，并带上子、父身份；
    ///         同身份重放与命中墓碑的迟到 ADD 为 NONE
    /// @note pid 复用时旧实例的退役在内部完成：其墓碑先于返回写入，身份经
    ///       exited 交出
    ProcessChange add(hng::ProcessMessage msg);

    /// @brief 注销一个进程
    /// @param p 进程身份
    /// @return 恒为 REMOVED；exited 为本次身份，未登记与重复退出同样返回
    /// @note 有实记录时先退役（转虚根、父计数递减），无记录时只写墓碑；
    ///       两种情况墓碑都先于返回写入
    ProcessChange remove(hng::Process p);

    /// @brief 更新进程的镜像路径
    /// @param p 进程身份
    /// @param exe 镜像路径
    /// @note 先匹配实进程树，未命中再匹配虚拟根；都不命中则丢弃
    /// @note 同 pid 的新实例不会命中旧实例的更新
    void update_image(hng::Process p, std::string exe);

    /**
     * @brief 按 pid + pid_start_time 查询进程
     * @details 先查实进程树，未命中再查虚拟根（父进程已退出的后台进程）。
     * @return 命中时为该记录，否则为空
     */
    std::optional<hng::ProcessMessage> lookup(hng::Process p) const;

    /// @brief 按 pid 反查进程实体；实进程树优先，其次取虚拟根中该 pid 的最新实例
    /// @return pid 为 0 或未命中时为空
    std::optional<hng::Process> resolve(uint32_t pid) const;

    /// @brief 该身份是否已有未过期的墓碑
    /// @note 命中但已过期的墓碑会被就地清除
    /// @note 只回答“已知退出”，不要求证明存活；未知身份返回 false
    bool is_exited(hng::Process p) const;

    /// @brief 异常态观测快照
    /// @note 计数只读原子量；tombstone_depth 另取墓碑表锁
    ProcessManagerStats stats() const;

   private:
    // 进程树分片数量
    static constexpr size_t kShardCount = 32;

    ProcessStoreOptions options_;

    // 墓碑表与进程树是两套独立的锁；持本锁时不得做进程树操作
    mutable std::mutex tombstone_mutex_;
    mutable hng::TombstoneTable<hng::Process, std::monostate> tombstones_;

    // 消费线程写、任意线程读，故为原子
    std::atomic<uint64_t> pid_reused_{0};
    std::atomic<uint64_t> stale_add_{0};
    std::atomic<uint64_t> parent_missing_{0};

    // 维护一组进程树的分片，PID 通过哈希落到对应的分片中
    // 该数据结构是频繁访问的，局部的共享锁一定程度上优化了访问
    std::array<ProcessShard, kShardCount> ptree_shard;

    // 存储虚拟根进程节点
    // 即那些已经退出，但其创建的子进程仍在运行的进程。
    // 这些进程的 pid + starttime 组合会被保留，用于子进程追溯
    std::array<VProcessShard, kShardCount> vptree_root;

    // 返回 PID 的所属分片位置
    size_t shard_index(uint32_t pid) const
    {
        return std::hash<uint32_t>{}(pid) % kShardCount;
    }

    /**
     * @brief 实际将新的 PID 节点插入实进程树
     * @details 操作是幂等的：同 pid 已存在时，只有 start_time 不一致才替换旧
     *  实例；旧实例按退役路径处理。
     * @param data 进程记录
     * @return 插入或替换时为 ADDED；幂等重放与墓碑拒收为 NONE
     * @note 身份已有墓碑时整条 ADD 丢弃，只计 stale_add：不插入、不更新父计数
     * @note 旧实例的墓碑先于返回写入
     */
    ProcessChange addPID(hng::ProcessMessage&& data);

    /**
     * @brief 实际删除实进程树节点
     * @details
     *  删除时，根据子进程计数，判断是否需要
     *  保留该 Process 为虚拟根节点。
     *  只要 PID 从 ptree_shard 中实际删除，其父进程的孩子计数就会递减
     * @param p 进程身份
     * @return 恒为 REMOVED，exited 为本次身份
     * @note 未命中记录时只写墓碑；重复退出幂等
     */
    ProcessChange deletePID(hng::Process p);

    /// @brief 实际更新进程镜像路径
    /// @details 先按身份匹配实进程树，未命中再匹配虚拟根；都不命中则丢弃
    void update_exe_image_(hng::Process p, std::string exe);

    /**
     * @brief 退役一条已从实进程树取下的进程记录
     * @details 有实子进程时转入虚拟根，待其实子进程全部退出后删除记录；否则
     *  直接删除。两种情况都递减其父进程的孩子计数。
     * @param old 已从 ptree 取出的记录，含其孩子计数
     * @return 被退役进程的身份
     * @note 调用方须已释放分片锁：本函数会写虚拟根、改父计数
     * @note 墓碑在本函数内写入，先于身份返回，也先于调用方发出的退出通知
     */
    hng::Process retire(hng::ProcessMessage&& old);

    /**
     * @brief 递增父进程的引用计数
     *  父进程存活时更新其 ptree 计数,已退出时回退更新虚拟根计数;
     *  内部自行加独占锁,线程安全
     * @note 递增时 pid 为 0（森林根）或父身份两处都未命中则不计任何计数，
     *       后者另计 parent_missing
     */
    void update_child_count_add(hng::Process p);

    /// @brief 递减父进程的引用计数
    /// @details 父进程存活时更新其 ptree 计数，已退出时回退更新虚拟根计数；
    ///          内部自行加独占锁
    void update_child_count_decrease(hng::Process p);

    /**
     * @brief 递减虚拟根进程的引用计数,计数归零后清理虚拟根节点
     *  内部自行对虚拟根所属分片加独占锁,线程安全;
     *  目标进程不在虚拟根中时静默放弃更新
     */
    void update_vroot_child_count_decrease(hng::Process p);

    /// @brief 当前时间；options_.now 为空时取 steady_clock
    hng::RelationTimePoint now() const;

    /// @brief 记录 p 已退出；同身份未过期的首条墓碑优先
    void add_tombstone_(hng::Process p);

    /// @brief 清除过期墓碑
    void expire_tombstones_();
};

#endif  // HNG_PROCESS_STORE_HPP_

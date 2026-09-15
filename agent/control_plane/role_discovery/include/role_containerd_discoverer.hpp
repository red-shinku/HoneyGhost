/**
 * @file role_containerd_discoverer.hpp
 * @brief containerd 角色发现器：经翻译进程发现容器角色的加入、退出与主进程更换
 * @details
 * 监测点是本模块的另一个进程（containerd_bridge，Go 编写）经 Unix socket 送来
 * 的协议消息，见 proto/role_containerd_bridge.proto。文件内含三层，自下而上：
 *  - 纯数据层：ContainerAttributes / ContainerdObservation / ContainerdMessage，
 *    与 protobuf 无关的消息表示，可直接构造；
 *  - ContainerdBridgeTranslator：消息 → 状态表动作。纯逻辑、不持有连接，
 *    单元测试直接喂入消息序列；
 *  - ContainerdRoleDiscoverer：连接、分帧解码与 run / stop 生命周期。
 * 头文件只用生成类型的前置声明，不含 protobuf 头。
 *
 * 与 systemd 源的形状差异：快照是穿过流来的，故「建流」与「快照」在 C++ 侧
 * 合并成「连接 → 持续读」。连接本身就是源：断开即重连、即新会话、即全量快照
 * 与对账。
 * @author red_shinku
 * @date 2026.9.13
 */

#ifndef HNG_ROLE_CONTAINERD_DISCOVERER_HPP_
#define HNG_ROLE_CONTAINERD_DISCOVERER_HPP_

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "agent/control_plane/role_discovery/include/role_discoverer.hpp"
#include "agent/control_plane/role_discovery/include/role_event_sink.hpp"
#include "agent/control_plane/role_discovery/include/role_observation.hpp"
#include "agent/control_plane/role_discovery/include/role_signal_table.hpp"
#include "agent/event_data/process.hpp"

namespace hng {
namespace role_bridge {
class Frame;
}  // namespace role_bridge
}  // namespace hng

namespace hng {
namespace role {

/**
 * @brief 容器的身份信息
 * @details 协议里切出来的字段在 C++ 侧的表示。除实例键外全部落入属性字典供下游
 * 使用；container_name 与 image 另作类型键的来源。
 */
struct ContainerAttributes {
    std::string container_id;         ///< 实例键
    std::string container_namespace;  ///< containerd namespace，即源内子范围
    std::string pod_uid;              ///< 以下四项来自 CRI 标签，非 k8s 容器为空
    std::string pod_name;
    std::string pod_namespace;
    std::string container_name;
    std::string image;                          ///< 镜像引用
    std::map<std::string, std::string> labels;  ///< 其余标签原样透传
};

/**
 * @brief 一条观察
 * @details remove 为 true 时只有 container_id 有意义：源侧在容器退出后已经查不到
 * 属性，退出事件的载荷由状态表回查缓存补齐。
 */
struct ContainerdObservation {
    bool remove               = false;  ///< 退出观察
    /// 该项是否由快照段枚举得来
    /// @details false 表示它是快照段内到达、被缓冲到段收场之后才放行的流内项。
    /// 段内出现 false 即帧序违约：枚举观察与流内观察的提交顺序由消息到达顺序
    /// 决定，段内停止的角色会被读成加入，产出永不修正的幽灵角色。
    bool in_snapshot          = false;
    uint32_t pid              = 0;  ///< 主进程锚点的 pid
    std::int64_t timestamp_ns = 0;  ///< 源侧时刻
    ContainerAttributes attributes;
};

/**
 * @brief 一条协议消息
 * @details 已脱离 protobuf 类型，可脱离帧构造。
 */
struct ContainerdMessage {
    enum class Kind {
        SNAPSHOT_BEGIN,  ///< 快照段开场
        OBSERVATION,     ///< 一次观察
        SNAPSHOT_END     ///< 快照段收场
    };

    Kind kind = Kind::OBSERVATION;
    std::string source;                   ///< SNAPSHOT_BEGIN：后端标注，只进日志
    std::string backend_version;          ///< SNAPSHOT_BEGIN：后端版本，只进日志
    std::vector<std::string> namespaces;  ///< SNAPSHOT_BEGIN：本段完整枚举的范围
    uint32_t declared_count = 0;          ///< SNAPSHOT_END：源侧声明的条目数
    ContainerdObservation observation;    ///< OBSERVATION
};

/// 解码一条协议帧
/// @param frame 已解析的协议帧
/// @param[out] message 解码结果
/// @return 帧不属于本协议（三个消息都没填）时返回 false，调用方记日志跳过
bool decode_frame(const hng::role_bridge::Frame& frame,
                  ContainerdMessage& message);

/**
 * @brief 容器过滤策略
 * @details 与阶段 03 的 unit 过滤同层，都在喂状态表之前。过滤是静态配置，只在
 * 重启时变，重启即清表，因此被过滤掉的容器不会留下幽灵条目。
 */
struct ContainerFilter {
    /// 纳入的 namespace，空表示不按 namespace 过滤
    std::vector<std::string> namespace_whitelist;
    /// 排除的 Pod：agent 自身容器由其 Pod UID 排除
    std::vector<std::string> exclude_pod_uids;

    /// 该容器是否纳入发现
    bool matches(const ContainerAttributes& attributes) const;
};

/**
 * @brief 发现器外部 IO 的注入点
 * @details 留空时由 ContainerdBridgeTranslator 填入真实实现（读 /proc 与
 * cgroupfs）。单元测试注入替身，以便断言精确锚点且不依赖真实进程。
 */
struct ContainerProbe {
    /// 读进程，空则读 /proc/<pid>/stat 字段 22
    std::function<std::optional<hng::Process>(uint32_t pid)> read_process;
    /// 读进程所属 cgroup 的绝对路径，空则读 /proc/<pid>/cgroup 再拼挂载点
    std::function<std::string(uint32_t pid)> read_cgroup_path;
    /// 枚举 cgroup 内全部进程，空则用 RoleCgroupReader::read
    std::function<std::vector<hng::Process>(const std::string& cgroup_path)>
        read_members;
};

/**
 * @brief 翻译层产出的一步动作
 * @details 由发现器按序在状态表上执行。顺序不可打乱：段内到达的流内观察必须
 * 排在 end_snapshot() 之后，否则段内停掉的角色会被陈旧的行读成加入。
 */
struct ContainerCommand {
    enum class Kind {
        BEGIN_SNAPSHOT,  ///< 开段
        SUBMIT,          ///< 喂一个观察量
        END_SNAPSHOT     ///< 结算
    };

    Kind kind = Kind::SUBMIT;
    std::vector<std::string> scope;  ///< BEGIN_SNAPSHOT：本段完整枚举的范围
    RoleObservation observation;     ///< SUBMIT
    bool settle             = true;  ///< END_SNAPSHOT：本段是否可信到可以结算
    uint32_t declared_count = 0;     ///< END_SNAPSHOT：源侧声明的条目数
    uint32_t received_count = 0;     ///< END_SNAPSHOT：本侧实收的条目数
};

/**
 * @brief 一批协议消息翻译出的结果
 */
struct ContainerTranslation {
    std::vector<ContainerCommand> commands;  ///< 要按序执行的动作
    std::vector<std::string> violations;     ///< 帧序违约的描述，供调用方记日志
};

/**
 * @brief 协议消息 → 状态表动作的翻译器
 * @details 维护待补锚点队列与段内状态，按过滤策略把每条观察转成进入、离开或
 * 未知观察量。快照段以 begin / end 动作表达，由发现器落到状态表上。
 *
 * 锚点补齐失败没有出口：既不能读成「不存在」（幻影退出），也不能静默丢弃——丢弃
 * 会让该容器既不加入也不退出，在下次结算前完全不可见。故失败入队重试，段内同时
 * 喂一条未知观察量使其免于被对账清除，由下一个快照段兜底。
 *
 * 非线程安全，由持有它的发现器线程独占访问。
 */
class ContainerdBridgeTranslator {
   public:
    /// @param filter 容器过滤策略
    /// @param probe IO 注入点，留空字段用真实实现
    explicit ContainerdBridgeTranslator(ContainerFilter filter = {},
                                        ContainerProbe probe   = {});

    /// 喂入一条协议消息
    ContainerTranslation on_message(const ContainerdMessage& message);

    /// 重试待补锚点队列，产出补齐成功者的加入观察量
    ContainerTranslation retry_pending();

    /// 连接断开时清掉段内状态
    /// @details 未走完的段不结算，其已见标记一并作废。待补锚点队列保留：容器
    /// 可能仍然存活，下一个快照段会重新送出它，届时再补锚点。
    void reset_segment();

    /// 待补锚点队列的当前长度
    std::size_t pending_anchors() const { return pending_.size(); }

   private:
    /// 组装加入观察量；锚点取不到时为空
    std::optional<RoleObservation> build_enter(
        const ContainerAttributes& attributes, uint32_t pid) const;
    /// 锚点补齐失败：入队并（段内）产出未知观察量
    void defer_anchor(const ContainerAttributes& attributes, uint32_t pid,
                      ContainerTranslation& out);

    /// 一个待补锚点项
    struct PendingAnchor {
        ContainerAttributes attributes;  ///< 属性齐备，只缺锚点
        uint32_t pid = 0;
        bool seen    = false;  ///< 本轮快照段是否又见到了它
    };

    ContainerFilter filter_;
    ContainerProbe probe_;
    std::map<std::string, PendingAnchor> pending_;  ///< 实例键 → 待补锚点项

    bool in_snapshot_ = false;                ///< 是否处于快照段内
    std::vector<std::string> segment_scope_;  ///< 当前段完整枚举的范围
    uint32_t segment_received_ = 0;           ///< 本段实收的枚举项数
};

/**
 * @brief 结算健康度
 * @details 「不结算」这个后果只在 C++ 侧成立，故可观测点在这一侧。持续作废会
 * 静默退化成「只喂不结算」——没有这些量就看不出「再也没结算过」：单看次数会漏掉
 * 「作废后立刻重试成功」，而危险的是后者。
 */
struct SettlementStats {
    uint64_t settlements = 0;  ///< 成功结算的段数
    uint64_t voids       = 0;  ///< 开了场却没收到收场的段数
    uint64_t anomalies   = 0;  ///< 帧序与条目计数违约次数
    std::int64_t since_last_settlement_ms =
        -1;                           ///< 距上次成功结算的时长，从未结算为 -1
    std::size_t pending_anchors = 0;  ///< 待补锚点队列长度
};

/**
 * @brief containerd 角色发现器
 * @details 生命周期：调用方在某个线程里调用 run()（阻塞），从任意线程调用
 * stop() 使其返回；本类不持有 std::thread，也不产生后台线程。析构前须已
 * run() 返回。
 *
 * 源不可用（翻译进程未起、socket 未就绪）时报告一次并转入带封顶的指数退避
 * 重试，期间不产出任何事件，run() 仍阻塞至 stop()。
 */
class ContainerdRoleDiscoverer : public RoleDiscoverer {
   public:
    /**
     * @brief 构造配置
     */
    struct Config {
        /// 翻译进程的 Unix socket 路径
        std::string socket_path = "/run/honeyghost/containerd-bridge.sock";
        ContainerFilter filter;  ///< 容器过滤策略
        ContainerProbe probe;    ///< IO 注入点
        /// 重连退避的起始值与上限
        std::chrono::milliseconds backoff_base{200};
        std::chrono::milliseconds backoff_max{30000};
        /// 待补锚点队列的重试周期
        std::chrono::milliseconds anchor_retry_interval{200};
    };

    /// @param sink 事件出口，须比本对象活得久
    /// @param config 构造配置
    ContainerdRoleDiscoverer(RoleEventSink& sink, Config config);
    ~ContainerdRoleDiscoverer() override;

    ContainerdRoleDiscoverer(const ContainerdRoleDiscoverer&)            = delete;
    ContainerdRoleDiscoverer& operator=(const ContainerdRoleDiscoverer&) = delete;

    /// 阻塞运行，直到 stop() 被调用
    /// @note 只能调用一次；返回后不再产出任何事件
    void run();

    /// 请求 run() 返回
    /// @note 幂等、可从任意线程调用；在 run() 之前调用时 run() 立即返回
    void stop();

    /// 把事件转发给构造时注入的事件出口
    /// @note 本文件内只有一处调用本方法，见 emit
    void publish(const RoleEvent& event) override;

    /// 取结算健康度
    /// @note 可从任意线程调用
    SettlementStats settlement_stats() const;

   private:
    /// 连接翻译进程
    /// @return 连上返回 true；socket 未就绪或路径非法时报告并返回 false
    bool connect();
    /// 拆掉连接；未连接时无副作用
    void detach();
    /// 连接 → 持续读，直到 stop()；断开即回到连接
    void loop();
    /// 读一帧、解码并处理
    /// @return 连接仍可用返回 true；断开或帧不可读返回 false
    bool read_and_handle();
    /// 把一条已解码的消息落到状态表上
    void handle(const ContainerdMessage& message);
    /// 按序执行一批动作
    void execute(const ContainerTranslation& translation);
    /// 单一出口：把一条跃迁产出交给事件出口
    /// @details 发现器内的产出（submit 与 end_snapshot 的结算）一律经此转发，
    /// publish 只被这一处调用，end_snapshot 的产出不另立通路
    void emit(const RoleEvent& event);
    /// 退避等待，可被 stop() 打断
    void backoff_wait(int& attempt);
    /// 从连接的 socket 读满 n 字节
    bool read_exact(void* buffer, std::size_t length);

    RoleEventSink& sink_;  ///< 事件出口，构造时注入，不接管其生命周期
    Config config_;
    ContainerdBridgeTranslator translator_;
    RoleSignalTable table_;
    int fd_              = -1;
    int wakeup_fd_       = -1;
    /// 本会话是否已以快照段开场
    bool session_opened_ = false;
    /// 当前是否有未结算的段
    bool segment_open_   = false;
    std::atomic<bool> stop_requested_{false};
    std::atomic<uint64_t> settlements_{0};
    std::atomic<uint64_t> voids_{0};
    std::atomic<uint64_t> anomalies_{0};
    std::atomic<std::int64_t> last_settlement_ns_{-1};
    /// 待补锚点队列长度，由 run 线程更新、任意线程读取
    std::atomic<std::size_t> pending_anchors_{0};
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_CONTAINERD_DISCOVERER_HPP_

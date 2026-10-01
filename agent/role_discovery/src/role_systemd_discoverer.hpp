/**
 * @file role_systemd_discoverer.hpp
 * @brief systemd 角色发现器：节点上 unit 的加入、退出与主进程更换
 * @details
 * 经 systemd bus（sd-bus）订阅 org.freedesktop.systemd1，把 unit 的存活性观察
 * 交给 hng::role::RoleSignalTable 判定，产出带主进程锚点与 cgroup 成员补齐的
 * 角色事件。
 *
 * 文件内含三层，自下而上：
 *  - 纯数据层：SystemdUnitSnapshot / SystemdUnitDelta / SystemdSignal，
 *    与 sd-bus 无关的消息表示，可直接构造；
 *  - SystemdSignalTranslator：信号 → 观察量。纯逻辑、不持有总线，单元测试
 *    直接喂入录制序列；
 *  - SystemdRoleDiscoverer：总线接线与 run / stop 生命周期。
 *    头文件只用 sd-bus 类型的前置声明，不含 sd-bus 头。
 *
 * SystemdRoleDiscoverer 不继承 RoleDiscoverer 之外的任何类型。
 * @author red_shinku
 * @date 2026.9.12
 */

#ifndef HNG_ROLE_SYSTEMD_DISCOVERER_HPP_
#define HNG_ROLE_SYSTEMD_DISCOVERER_HPP_

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "agent/role_discovery/src/role_discoverer.hpp"
#include "agent/role_discovery/include/role_event.hpp"
#include "agent/role_discovery/include/role_event_sink.hpp"
#include "agent/role_discovery/src/role_observation.hpp"
#include "agent/role_discovery/src/role_signal_table.hpp"
#include "agent/event_data/include/process.hpp"

struct sd_bus;
struct sd_bus_message;
struct sd_bus_slot;

namespace hng {
namespace role {

/**
 * @brief unit 属性快照
 * @details 本发现器内部的属性缓存，与状态表的载荷缓存不是一回事。
 * PropertiesChanged 的 changed 字典只含变化的字段，故首次见到某 unit 时必须
 * 先取一次完整快照（GetAll）才能得到 Id 与 ControlGroup。
 * 字段跨两个 D-Bus 接口：Id / LoadState / ActiveState / SubState 属
 * org.freedesktop.systemd1.Unit，ServiceType / MainPID / ControlGroup 属
 * org.freedesktop.systemd1.Service。
 */
struct SystemdUnitSnapshot {
    std::string id;             ///< unit 原名（Unit.Id）
    std::string load_state;     ///< Unit.LoadState
    std::string active_state;   ///< Unit.ActiveState
    std::string sub_state;      ///< Unit.SubState
    std::string service_type;   ///< Service.Type（oneshot 等）
    uint32_t main_pid = 0;      ///< Service.MainPID，无主进程时为 0
    std::string control_group;  ///< Service.ControlGroup，无 cgroup 时为空串
    /// Unit.ActiveEnterTimestampMonotonic，未进入过 active 时为 0
    /// @details 只在 unit 重新进入 active 时前进，原地交接主进程不离开 active、
    /// 该值不变；仍处在 active 的 reload 也不变。取 Monotonic 版本以免受 NTP 回拨
    /// 影响。用途见 evaluate 的重启判据。
    uint64_t active_enter_monotonic = 0;
};

/**
 * @brief PropertiesChanged 中本模块跟踪的字段增量
 * @details 全部为 optional：changed 字典只含本次变化的字段，未出现的字段
 * 表示本次未变，而不是变成空值。
 */
struct SystemdUnitDelta {
    std::optional<std::string> id;                   ///< Unit.Id
    std::optional<std::string> load_state;           ///< Unit.LoadState
    std::optional<std::string> active_state;         ///< Unit.ActiveState
    std::optional<std::string> sub_state;            ///< Unit.SubState
    std::optional<std::string> service_type;         ///< Service.Type
    std::optional<std::string> control_group;        ///< Service.ControlGroup
    std::optional<uint32_t> main_pid;                ///< Service.MainPID
    std::optional<uint64_t> active_enter_monotonic;  ///< 见 SystemdUnitSnapshot
};

/// 信号种类
enum class SystemdSignalKind {
    UNIT_PROPERTIES,    ///< Properties.PropertiesChanged，unit 属性变化
    UNIT_NEW,           ///< Manager.UnitNew，unit 文件出现
    UNIT_REMOVED,       ///< Manager.UnitRemoved，unit 文件消失
    JOB_REMOVED,        ///< Manager.JobRemoved，启动/停止作业结束
    NAME_OWNER_CHANGED  ///< DBus.NameOwnerChanged，systemd 自身出现或消失
};

/**
 * @brief 解码后的信号
 * @details 已脱离 sd-bus 消息类型，可脱离总线构造。
 */
struct SystemdSignal {
    SystemdSignalKind kind = SystemdSignalKind::UNIT_PROPERTIES;
    /// 该消息在 systemd 那条连接上的序号，单调递增
    /// @details 用于判断一条增量是否早于“已采纳的某次读数”。0 表示未知
    /// （单测自己构造的消息），此时不做时序判断。见 SystemdSignalTranslator
    /// 的时序水位。
    uint64_t cookie        = 0;
    std::string object_path;  ///< unit 对象路径
    std::string unit_id;      ///< unit 名
    SystemdUnitDelta delta;   ///< UNIT_PROPERTIES：变化的字段
    std::string job_result;   ///< JOB_REMOVED：作业结果（done / failed 等）
    std::string new_owner;    ///< NAME_OWNER_CHANGED：新 owner，空串表示已消失
};

/**
 * @brief unit 过滤策略
 * @details 后缀、白名单、忽略列表三条依次判定；白名单非空时只有列出的 unit
 * 通过，且白名单优先于忽略列表——忽略列表是内建默认，白名单是显式指定。
 */
struct SystemdUnitFilter {
    /// 纳入的 unit 后缀，默认仅 service。scope 无 MainPID，无主进程锚点
    std::vector<std::string> unit_suffixes{"service"};
    /// 忽略的 unit 名前缀
    std::vector<std::string> ignore_prefixes{"systemd-", "user@"};
    /// 忽略的 unit 名全称
    std::vector<std::string> ignore_units{"dbus.service"};
    /// 白名单，空表示不启用
    std::vector<std::string> whitelist;

    /// unit 名是否纳入发现
    bool matches(const std::string& unit_id) const;
};

/**
 * @brief 发现器外部 IO 的注入点
 * @details 留空时由 SystemdSignalTranslator 填入真实实现（读 /proc 与
 * cgroupfs）。单元测试注入替身，以便断言精确锚点且不依赖真实进程。
 */
struct SystemdProbe {
    /// 读进程，空则读 /proc/<pid>/stat 字段 22
    /// @return 空表示**未知**，不表示“进程不存在”：/proc 视图不是宿主的、
    /// hidepid、命名空间差异与进程确已消失给出的是同一个结果，按 errno 分不开。
    /// “不存在”一律由源侧事实给出（MainPID 归零、declared_exit、枚举缺席）。
    std::function<std::optional<hng::Process>(uint32_t pid)> read_process;

    /// 枚举 cgroup 内全部进程，空则用 RoleCgroupReader::read
    std::function<std::vector<hng::Process>(const std::string& cgroup_path)>
        read_members;
};

/**
 * @brief 一次 unit 属性取数的结论
 * @details 三态。“取不到”不能压成“不存在”——把一次调用失败当成角色退出，
 * 已存活条目会被删、载荷缓存随之销毁，产出一对不可撤回的幻影退出/加入。
 */
struct SystemdFetchResult {
    enum class Kind {
        FOUND,    ///< 取到完整快照
        ABSENT,   ///< 对象确实不存在，源侧已给出“不存在”
        UNKNOWN,  ///< 调用失败或结果不全，源侧无结论
    };

    Kind kind = Kind::UNKNOWN;
    SystemdUnitSnapshot snapshot;  ///< kind 为 FOUND 时有效
    /// 最后一次应答的序号，即本次采纳的状态有多新；kind 非 FOUND 时为 0
    uint64_t cookie = 0;
};

/**
 * @brief 一次评估的结论
 * @details 三态。OBSERVED 可能携带不止一条观察量——锚点变化若判为重启，会展开成
 * 离开 + 进入两条（§4.1）。UNKNOWN 时调用方**不得推进属性快照缓存**，否则去重会
 * 挡住后续重评估，下游锚点永久停在旧值上（README §5.3 的 P1 第二半）。
 */
struct SystemdEvaluation {
    enum class Kind {
        OBSERVED,   ///< 产出观察量
        UNKNOWN,    ///< 主进程读不到，源侧无结论
        UNCHANGED,  ///< 被跟踪字段无变化，重复观察或重放
    };

    Kind kind = Kind::UNCHANGED;
    std::vector<RoleObservation> observations;  ///< OBSERVED 时按序有效
};

/**
 * @brief 一批信号翻译出的结果
 */
struct SystemdTranslation {
    std::vector<RoleObservation> observations;   ///< 喂给状态表的观察量
    std::vector<std::string> pending_snapshots;  ///< 待补完整快照的 unit 对象路径
};

/**
 * @brief 信号 → 观察量的翻译器
 * @details 维护 unit 属性快照缓存，按存活性判据把每次属性变化转成进入或离开
 * 观察量。只有被跟踪的字段真的变化、或首次得到某 unit 的快照时才产出观察量，
 * 重复与重放的输入不产出。
 *
 * 判据为“主进程已确定”而非“角色已就绪”：存在性由两层合成——进程层（MainPID
 * 非零且 /proc 可读）与状态层（源未宣告退出）。状态层只取 deactivating / failed：
 * MainPID 属 Service 接口、ActiveState 属 Unit 接口，两者没有共同时刻，拼接出的
 * MainPID != 0 ∧ inactive 是系统里不存在的组合，不予采纳。ActiveState / SubState
 * 作为属性携带，不阻塞发布。
 *
 * 非线程安全，由持有它的发现器线程独占访问。
 */
class SystemdSignalTranslator {
   public:
    /// @param filter unit 过滤策略
    /// @param probe IO 注入点，留空字段用真实实现
    explicit SystemdSignalTranslator(SystemdUnitFilter filter = {},
                                     SystemdProbe probe       = {});

    /// 丢弃时序水位
    /// @details 重连后 systemd 可能另起一条连接、其序号从头开始，留着旧水位
    /// 会把新消息全判成陈旧。丢弃最差只是失去这一层保护。
    void forget_ordering();

    /// 开启快照段
    /// @details 段内到达的流内观察（`on_signal`）不再直接返回，改为缓冲，等
    /// `end_segment()` 放行。枚举观察（`on_snapshot`）不受影响，照常返回。
    /// 理由见 `end_segment()`。
    void begin_segment();

    /// 结束快照段并取回缓冲的流内观察
    /// @details 段内流内观察必须排在枚举观察之后提交：`sd_bus_call_method` 等应答
    /// 期间会分派 match 回调，故枚举途中就能收到流内消息，若就地提交，同一实例键
    /// 上最后一笔会是**陈旧**的那笔——段内停掉的角色被快照里停止前的行读成加入，
    /// 产出永不修正的幽灵；反方向则永久丢失一个段内启动的角色。顺序由构造保证，
    /// 不能交给消息到达顺序。
    /// @return 缓冲的观察量，顺序即到达顺序
    std::vector<RoleObservation> end_segment();

    /// 喂入一条增量信号
    /// @return 本信号产出的观察量，以及首次见到该 unit 时请求补全的对象路径
    /// @note 段内产出的观察量进缓冲，不出现在返回值里，见 begin_segment
    SystemdTranslation on_signal(const SystemdSignal& signal);

    /// 喂入一次 GetAll 得到的完整快照
    /// @param object_path unit 对象路径
    /// @param snapshot 完整属性快照
    /// @param cookie 取数应答的序号；0 表示未知
    /// @return 该快照产出的观察量
    SystemdTranslation on_snapshot(const std::string& object_path,
                                   const SystemdUnitSnapshot& snapshot,
                                   uint64_t cookie = 0);

   private:
    /// 比较前后快照并判定跃迁
    /// @details 存在判据由两层合成：进程层（主进程可确定）与状态层（源未宣告
    /// 退出）。后者不可省——ExecStop 未走完时主进程仍在跑，/proc 仍可读，但
    /// 角色已不再对外可用，这一层只有源能给。
    /// 锚点变化再按 ActiveEnterTimestampMonotonic 是否前进分成两类：前进说明
    /// unit 重新进入过 active，是重启，展开为离开 + 进入；不变则是原地交接，
    /// 交给状态表产出主进程更换（§4.2）。
    /// @param announce 段内枚举：被跟踪字段无变化时也产出观察量，锚点补不齐时
    /// 产出未知观察量。状态表按代际对账，段内每个枚举到的条目都必须被 `submit`
    /// 命中一次才算本段已见，去重会让未变化的条目缺席、被结算成幽灵退出。
    SystemdEvaluation evaluate(const SystemdUnitSnapshot& before,
                               const SystemdUnitSnapshot& after, bool announce);

    /// 装配加入 / 主进程更换的完整载荷，含 cgroup 补齐
    RolePayload build_payload(const SystemdUnitSnapshot& snapshot,
                              const hng::Process& main) const;

    /// 按段内 / 段外把评估产出的观察量送出去
    void deliver(const SystemdEvaluation& evaluation, SystemdTranslation& out);

    /// 这次读到的 ActiveEnterTimestampMonotonic 是否可用
    /// @details 该值逐次前进、停止归零，故“比已见最大值小的非零值”只可能是
    /// 陈旧读数。拦下它是因为一个陈旧值会让随后真正的前进看起来像又进入了一次
    /// active，凭空产出一对退出/加入。可用时顺手抬高水位。
    /// @return 可用返回 true；陈旧返回 false，调用方保留原值
    bool accept_active_enter(const std::string& unit_id, uint64_t value);

    SystemdUnitFilter filter_;
    SystemdProbe probe_;

    std::unordered_map<std::string, SystemdUnitSnapshot>
        snapshots_;            ///< 对象路径 → 快照
    bool in_segment_ = false;  ///< 是否处于快照段内

    std::vector<RoleObservation> segment_buffer_;  ///< 段内流内观察的缓冲

    /// unit 名 → ActiveEnterTimestampMonotonic 的已见最大值
    std::unordered_map<std::string, uint64_t> active_enter_high_water_;

    /// 对象路径 → 已采纳状态的时序水位（那条消息的序号）
    /// @details 取数的应答与增量都是 systemd 发来的消息，各带单调序号，故
    /// “这条增量是否早于我们已经采纳的读数”是可判定的。不判定的后果：段内
    /// 枚举读到的状态可能比仍在途的流内消息新——枚举那条把一次重启报成
    /// 退出 + 加入，随后迟到的停止/启动消息把同一次重启又重放一遍，同一个
    /// 源事实产出两对事件。值上两条无法区分，只有序号能。
    std::unordered_map<std::string, uint64_t> watermark_;
};

/**
 * @brief 结算健康度
 * @details “不结算”这个后果只在 C++ 侧成立，故可观测点在这一侧。持续作废会
 * 静默退化成“只喂不结算”——没有这些量就看不出“再也没结算过”：单看次数会漏掉
 * “作废后立刻重试成功”，而危险的是后者。
 */
struct SystemdSettlementStats {
    uint64_t settlements = 0;  ///< 成功结算的段数
    uint64_t voids       = 0;  ///< 枚举未走完而作废的段数
    uint64_t anomalies =
        0;  ///< 枚举结构异常次数（应答容器类型不符、逐行读取失败）

    /// 取数时对象已不在的次数；成高频即说明 ListUnits
    /// 与取数之间的卸载窗口在被打中
    uint64_t units_gone      = 0;
    uint64_t unknown_fetches = 0;  ///< 逐项取数失败（未知）的次数
    std::int64_t since_last_settlement_ms =
        -1;  ///< 距上次成功结算的时长，从未结算为 -1
};

/**
 * @brief systemd 角色发现器
 * @details 生命周期：调用方在某个线程里调用 run()（阻塞），从任意线程调用
 * stop() 使其返回；本类不持有 std::thread，也不产生后台线程。析构前须已
 * run() 返回。
 *
 * 源不可用（宿主非 systemd init）时报告一次并转入带封顶的指数退避重试，
 * 期间不产出任何事件，run() 仍阻塞至 stop()。
 */
class SystemdRoleDiscoverer : public RoleDiscoverer {
   public:
    /**
     * @brief 构造配置
     */
    struct Config {
        SystemdUnitFilter filter;  ///< unit 过滤策略
        SystemdProbe probe;        ///< IO 注入点

        /// 周期快照间隔，0 表示不做
        /// @details 对账只在快照段结束时发生，故“没断连但信号被丢”产生的幽灵
        /// 存活期以到下一次 (重)连为止，可能是天级。周期快照给它设上界，代价是
        /// 每次 O(纳入发现的 unit 数) 次取数，故频率须有界。
        std::chrono::milliseconds snapshot_interval{600000};
    };

    /// @param sink 事件出口，须比本对象活得久
    /// @param config 构造配置
    SystemdRoleDiscoverer(RoleEventSink& sink, Config config);
    ~SystemdRoleDiscoverer() override;

    SystemdRoleDiscoverer(const SystemdRoleDiscoverer&)            = delete;
    SystemdRoleDiscoverer& operator=(const SystemdRoleDiscoverer&) = delete;

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
    SystemdSettlementStats settlement_stats() const;

   private:
    /// ① 先建流：连接 system bus、注册 match、Subscribe
    void attach_stream();
    /// ② 后快照：跑一次快照段，枚举现有 unit 并结算差额
    void prime_from_snapshot();
    /// ③ 循环：排空消息、补快照、poll，直到 stop()；断线在此重连
    void loop();

    /// 拆掉当前连接；未连接时无副作用
    /// @note 同时复位翻译层的时序水位：重连后 systemd 可能另起一条连接，
    /// 其序号从头开始，留着旧水位会把新消息全判成陈旧
    void detach_stream();
    /// 排空已到达消息
    /// @return 0 正常，-1 连接已断开
    int dispatch_pending();

    /// 枚举 ListUnits 中纳入发现的 unit，逐个取数并喂入状态表
    /// @param[out] complete 本次枚举是否走完：容器类型不符或逐行读取失败时为
    /// false，此时本次段作废、不结算
    /// @return 枚举到的行数（含被跳过的行）
    std::size_t enumerate_units(bool& complete);
    /// 取一个已知 unit 的属性并喂入状态表，按三态分流
    void harvest_unit(const std::string& object_path, const std::string& unit_id);

    /// 为待补快照的 unit 取一次完整属性并判定
    void resolve_pending_snapshots();
    /// 取一个 unit 的完整属性快照
    /// @return 三态：取到 / 对象确实不存在 / 调用失败或结果不全
    SystemdFetchResult fetch_snapshot(const std::string& object_path);

    /// 调用 Manager.Subscribe()，失败时报告
    bool subscribe();

    /// 把观察量喂入状态表，跃迁产出交给事件出口
    void submit(const SystemdTranslation& translation);
    /// 把一条观察量喂入状态表，跃迁产出交给事件出口
    void submit(const RoleObservation& observation);

    /// 单一出口：把一条跃迁产出交给事件出口
    /// @details 发现器内的产出（submit 与 end_snapshot 的结算）一律经此转发，
    /// publish 只被这一处调用，end_snapshot 的产出不另立通路
    void emit(const RoleEvent& event);

    /// 距下次周期快照的毫秒数，用于 poll 超时
    /// @return 未启用周期快照时为 -1（无限等待）
    int next_snapshot_timeout_ms() const;
    /// 下一次周期快照的到点时刻
    /// @return 未启用周期快照时为 -1
    std::int64_t snapshot_deadline_ns() const;
    /// 退避等待，可被 stop() 打断
    void backoff_wait(int& attempt);

    /// 处理一条已到达的 sd-bus 消息：解码、记日志、喂入翻译层
    void handle_message(struct sd_bus_message* message);

    RoleEventSink& sink_;  ///< 事件出口，构造时注入，不接管其生命周期
    Config config_;
    SystemdSignalTranslator translator_;
    RoleSignalTable table_;

    struct sd_bus* bus_ = nullptr;                ///< 当前连接，未连接时为空
    std::vector<struct sd_bus_slot*> slots_;      ///< 已注册的 match 规则
    std::vector<std::string> pending_snapshots_;  ///< 待补快照的 unit 对象路径
    bool resubscribe_requested_ = false;  ///< systemd 重新出现，待重订阅并重快照
    int wakeup_fd_              = -1;     ///< 唤醒 eventfd，供 stop() 打断 poll

    /// 下次周期快照的到点时刻，steady_clock 的纳秒计数；未启用时为 -1
    std::int64_t next_snapshot_ns_ = -1;

    /// stop() 置位，run() 与循环各处据此返回
    std::atomic<bool> stop_requested_{false};

    /// 结算健康度，由 settlement_stats() 从任意线程读取；各字段的含义与
    /// 用途见 SystemdSettlementStats
    std::atomic<uint64_t> settlements_{0};  ///< 成功结算的段数
    std::atomic<uint64_t> voids_{0};        ///< 枚举未走完而作废的段数
    std::atomic<uint64_t> anomalies_{0};    ///< 枚举结构异常次数

    /// 取数时对象已不在的次数；成高频即说明 ListUnits 与取数之间的卸载窗口
    /// 在被打中
    std::atomic<uint64_t> units_gone_{0};
    std::atomic<uint64_t> unknown_fetches_{0};  ///< 逐项取数失败的次数

    /// 上次成功结算的时刻，steady_clock 的纳秒计数；从未结算为 -1
    std::atomic<std::int64_t> last_settlement_ns_{-1};
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_SYSTEMD_DISCOVERER_HPP_

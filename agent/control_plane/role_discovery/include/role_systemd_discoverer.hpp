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
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "agent/control_plane/role_discovery/include/role_discoverer.hpp"
#include "agent/control_plane/role_discovery/include/role_observation.hpp"
#include "agent/control_plane/role_discovery/include/role_signal_table.hpp"
#include "agent/event_data/process.hpp"

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
};

/**
 * @brief PropertiesChanged 中本模块跟踪的字段增量
 * @details 全部为 optional：changed 字典只含本次变化的字段，未出现的字段
 * 表示本次未变，而不是变成空值。
 */
struct SystemdUnitDelta {
    std::optional<std::string> id;             ///< Unit.Id
    std::optional<std::string> load_state;     ///< Unit.LoadState
    std::optional<std::string> active_state;   ///< Unit.ActiveState
    std::optional<std::string> sub_state;      ///< Unit.SubState
    std::optional<std::string> service_type;   ///< Service.Type
    std::optional<std::string> control_group;  ///< Service.ControlGroup
    std::optional<uint32_t> main_pid;          ///< Service.MainPID
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
    std::function<std::optional<hng::Process>(uint32_t pid)> read_process;
    /// 枚举 cgroup 内全部进程，空则用 RoleCgroupReader::read
    std::function<std::vector<hng::Process>(const std::string& cgroup_path)>
        read_members;
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
 * 判据为「主进程已确定」而非「角色已就绪」：存活性只看 MainPID、是否进入拆除
 * 与探针可读性，ActiveState / SubState 作为属性携带，不阻塞发布。inactive 不算
 * 拆除——瞬态单元上 systemd 会先发 MainPID，再补一个值更旧的 ActiveState=
 * inactive，随后才回到 activating；把这帧读成「离开」会凭空产出一对
 * 加入/退出。
 *
 * 非线程安全，由持有它的发现器线程独占访问。
 */
class SystemdSignalTranslator {
   public:
    /// @param filter unit 过滤策略
    /// @param probe IO 注入点，留空字段用真实实现
    explicit SystemdSignalTranslator(SystemdUnitFilter filter = {},
                                     SystemdProbe probe       = {});

    /// 喂入一条增量信号
    /// @return 本信号产出的观察量，以及首次见到该 unit 时请求补全的对象路径
    SystemdTranslation on_signal(const SystemdSignal& signal);

    /// 喂入一次 GetAll 得到的完整快照
    /// @param object_path unit 对象路径
    /// @param snapshot 完整属性快照
    /// @return 该快照产出的观察量
    SystemdTranslation on_snapshot(const std::string& object_path,
                                   const SystemdUnitSnapshot& snapshot);

   private:
    /// 比较前后快照并判定跃迁，返回观察量
    /// @details 存在判据由两层合成：进程层（主进程可确定）与状态层（源未宣告
    /// 退出）。后者不可省——ExecStop 未走完时主进程仍在跑，/proc 仍可读，但
    /// 角色已不再对外可用，这一层只有源能给。
    std::optional<RoleObservation> evaluate(const SystemdUnitSnapshot& before,
                                            const SystemdUnitSnapshot& after);
    /// 装配加入 / 主进程更换的完整载荷，含 cgroup 补齐
    RolePayload build_payload(const SystemdUnitSnapshot& snapshot,
                              const hng::Process& main) const;

    SystemdUnitFilter filter_;
    SystemdProbe probe_;
    std::unordered_map<std::string, SystemdUnitSnapshot>
        snapshots_;  ///< 对象路径 → 快照
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
        /// 事件出口，留空则往 stderr 打一行摘要
        std::function<void(const RoleEvent&)> on_event;
        SystemdProbe probe;  ///< IO 注入点
    };

    explicit SystemdRoleDiscoverer(Config config = {});
    ~SystemdRoleDiscoverer() override;

    SystemdRoleDiscoverer(const SystemdRoleDiscoverer&)            = delete;
    SystemdRoleDiscoverer& operator=(const SystemdRoleDiscoverer&) = delete;

    /// 阻塞运行，直到 stop() 被调用
    /// @note 只能调用一次；返回后不再产出任何事件
    void run();

    /// 请求 run() 返回
    /// @note 幂等、可从任意线程调用；在 run() 之前调用时 run() 立即返回
    void stop();

    /// 过渡空实现：事件经 Config::on_event 交付，本接口的契约待阶段 05 定稿
    void publish() override;

   private:
    /// ① 先建流：连接 system bus、注册 match、Subscribe
    void attach_stream();
    /// ② 后快照：ListUnits 枚举现有 unit，经与按需补快照相同的通路进状态表
    void prime_from_snapshot();
    /// ③ 循环：排空消息、补快照、poll，直到 stop()；断线在此重连
    void loop();

    /// 拆掉当前连接；未连接时无副作用
    void detach_stream();
    /// 排空已到达消息
    /// @return 0 正常，-1 连接已断开
    int dispatch_pending();
    /// 为待补快照的 unit 取一次完整属性并判定
    void resolve_pending_snapshots();
    /// 取一个 unit 的完整属性快照
    /// @return 取不到（对象不存在、接口不匹配、调用失败）时为空
    std::optional<SystemdUnitSnapshot> fetch_snapshot(
        const std::string& object_path);
    /// 调用 Manager.Subscribe()，失败时报告
    bool subscribe();
    /// 把观察量喂入状态表，跃迁产出交给事件出口
    void submit(const SystemdTranslation& translation);
    /// 退避等待，可被 stop() 打断
    void backoff_wait(int& attempt);

    /// 处理一条已到达的 sd-bus 消息：解码、记日志、喂入翻译层
    void handle_message(struct sd_bus_message* message);

    Config config_;
    SystemdSignalTranslator translator_;
    RoleSignalTable table_;
    struct sd_bus* bus_ = nullptr;
    std::vector<struct sd_bus_slot*> slots_;
    std::vector<std::string> pending_snapshots_;
    bool resubscribe_requested_ = false;
    int wakeup_fd_              = -1;
    std::atomic<bool> stop_requested_{false};
};

}  // namespace role
}  // namespace hng

#endif  // HNG_ROLE_SYSTEMD_DISCOVERER_HPP_

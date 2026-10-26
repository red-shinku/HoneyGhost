/**
 * @file role_systemd_discoverer.cc
 * @brief systemd 角色发现器的翻译层与 sd-bus 接线实现
 * @author red_shinku
 * @date 2026.9.12
 */

#include "agent/role_discovery/src/role_systemd_discoverer.hpp"

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

#include <systemd/sd-bus.h>

#include "agent/role_discovery/src/role_cgroup_reader.hpp"

namespace hng {
namespace role {

namespace {

/// 重连退避的起始与上限，单位毫秒
constexpr int kBackoffBaseMs            = 200;
constexpr int kBackoffMaxMs             = 30000;

/// D-Bus 属性所在的两个接口
constexpr const char* kUnitInterface    = "org.freedesktop.systemd1.Unit";
constexpr const char* kServiceInterface = "org.freedesktop.systemd1.Service";

constexpr const char* kSystemdService   = "org.freedesktop.systemd1";
constexpr const char* kManagerPath      = "/org/freedesktop/systemd1";
constexpr const char* kManagerIface     = "org.freedesktop.systemd1.Manager";

/// unit 名后缀：最后一个 '.' 之后的部分，无 '.' 时为空
std::string unit_suffix(const std::string& unit_id)
{
    const std::size_t dot = unit_id.rfind('.');
    if (dot == std::string::npos) {
        return std::string();
    }
    return unit_id.substr(dot + 1);
}

/// 类型键：去掉 unit 后缀，再去掉 '@' 及其实例部分
std::string type_key_of(const std::string& unit_id)
{
    const std::size_t dot = unit_id.rfind('.');
    std::string base =
        (dot == std::string::npos) ? unit_id : unit_id.substr(0, dot);
    const std::size_t at = base.find('@');
    if (at != std::string::npos) {
        base.resize(at);
    }
    return base;
}

/// 源是否已宣告该 unit 退出
/// @note 只有 deactivating / failed，不含 inactive：判据只采纳系统里
/// 真实存在的组合。MainPID 属 Service 接口、ActiveState 属 Unit 接口，
/// 两条通道没有共同时刻，故 MainPID != 0 ∧ inactive 是拼接产物、系统
/// 里不存在；而 MainPID != 0 ∧ deactivating 真实存在（ExecStop 进行
/// 中），必须采纳。正常停止路径先经 deactivating，退出在该处即已发布，
/// 故不取 inactive 不改变停止路径的行为。
bool declared_exit(const std::string& active_state)
{
    return active_state == "deactivating" || active_state == "failed";
}

/// 把增量并入快照：未出现的字段表示本次未变
void merge(SystemdUnitSnapshot& snapshot, const SystemdUnitDelta& delta)
{
    if (delta.id) {
        snapshot.id = *delta.id;
    }
    if (delta.load_state) {
        snapshot.load_state = *delta.load_state;
    }
    if (delta.active_state) {
        snapshot.active_state = *delta.active_state;
    }
    if (delta.sub_state) {
        snapshot.sub_state = *delta.sub_state;
    }
    if (delta.service_type) {
        snapshot.service_type = *delta.service_type;
    }
    if (delta.control_group) {
        snapshot.control_group = *delta.control_group;
    }
    if (delta.main_pid) {
        snapshot.main_pid = *delta.main_pid;
    }
    if (delta.active_enter_monotonic) {
        snapshot.active_enter_monotonic = *delta.active_enter_monotonic;
    }
}

/// 被跟踪字段是否全等
bool same_tracked_fields(const SystemdUnitSnapshot& a,
                         const SystemdUnitSnapshot& b)
{
    return a.id == b.id && a.load_state == b.load_state &&
           a.active_state == b.active_state && a.sub_state == b.sub_state &&
           a.service_type == b.service_type && a.main_pid == b.main_pid &&
           a.control_group == b.control_group &&
           a.active_enter_monotonic == b.active_enter_monotonic;
}

/// unit 是否在两帧之间重新进入过 active
/// @details 只有重新进入 active 才让 ActiveEnterTimestampMonotonic 前进：原地交接
/// 主进程不离开 active，处在 active 的 reload 也不离开，两者该值都不变。
/// 两侧都非零是归零边界——停止后该值归零，不设这条边界会把 stop → start 读成
/// 一次跳变；要求严格大于而非不等——倒退只是旧读数，不是重新进入。
bool reentered_active(const SystemdUnitSnapshot& before,
                      const SystemdUnitSnapshot& after)
{
    return before.active_enter_monotonic != 0 &&
           after.active_enter_monotonic != 0 &&
           after.active_enter_monotonic > before.active_enter_monotonic;
}

/// 默认主进程探针：读 /proc/<pid>/stat 字段 22
std::optional<hng::Process> read_proc_process(uint32_t pid)
{
    std::ifstream stat(std::filesystem::path("/proc") / std::to_string(pid) /
                       "stat");
    if (!stat) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << stat.rdbuf();
    std::optional<uint64_t> start_time =
        RoleCgroupReader::parse_start_time(buffer.str());
    if (!start_time) {
        return std::nullopt;
    }
    return hng::Process{pid, *start_time};
}

void report(const char* what, int error_code)
{
    std::fprintf(stderr, "[role_systemd] %s：%s\n", what,
                 std::strerror(-error_code));
}

/// 从 a{sv} 中取出被跟踪的字段，其余跳过
/// @return 字典是否被完整读取
bool read_tracked_dict(sd_bus_message* message, SystemdUnitDelta& delta)
{
    int r = sd_bus_message_enter_container(message, 'a', "{sv}");
    if (r < 0) {
        return false;
    }
    while ((r = sd_bus_message_enter_container(message, 'e', "sv")) > 0) {
        const char* key = nullptr;
        if (sd_bus_message_read(message, "s", &key) < 0 || key == nullptr) {
            return false;
        }
        if (sd_bus_message_enter_container(message, 'v', nullptr) < 0) {
            return false;
        }
        // variant 自身的位置 peek 到的是 'v'，须进入后才拿得到载荷类型
        char type = 0;
        if (sd_bus_message_peek_type(message, &type, nullptr) < 0) {
            return false;
        }
        if (type == 's') {
            const char* value = nullptr;
            if (sd_bus_message_read(message, "s", &value) >= 0 &&
                value != nullptr) {
                if (std::strcmp(key, "Id") == 0) {
                    delta.id = value;
                }
                else if (std::strcmp(key, "LoadState") == 0) {
                    delta.load_state = value;
                }
                else if (std::strcmp(key, "ActiveState") == 0) {
                    delta.active_state = value;
                }
                else if (std::strcmp(key, "SubState") == 0) {
                    delta.sub_state = value;
                }
                else if (std::strcmp(key, "Type") == 0) {
                    delta.service_type = value;
                }
                else if (std::strcmp(key, "ControlGroup") == 0) {
                    delta.control_group = value;
                }
            }
        }
        else if (type == 'u') {
            uint32_t value = 0;
            if (sd_bus_message_read(message, "u", &value) >= 0 &&
                std::strcmp(key, "MainPID") == 0) {
                delta.main_pid = value;
            }
        }
        else if (type == 't') {
            uint64_t value = 0;
            if (sd_bus_message_read(message, "t", &value) >= 0 &&
                std::strcmp(key, "ActiveEnterTimestampMonotonic") == 0) {
                delta.active_enter_monotonic = value;
            }
        }
        else {
            sd_bus_message_skip(message, nullptr);
        }
        sd_bus_message_exit_container(message);  // variant
        sd_bus_message_exit_container(message);  // dict entry
    }
    sd_bus_message_exit_container(message);  // array
    return r == 0;
}

/// 错误是否表明「对象确实不存在」
/// @details 与「调用失败」必须分开：前者是源侧给出的事实，后者只能算未知。
/// 只认 UnknownObject——超时、权限、连接中断都不足以判断对象是否存在，而接口
/// 缺失另有含义，一并归入未知更安全。
bool is_absent_error(const sd_bus_error& error)
{
    return error.name != nullptr &&
           std::strcmp(error.name, SD_BUS_ERROR_UNKNOWN_OBJECT) == 0;
}

/// 取一个对象在指定接口上的全部属性，只留下被跟踪的字段
/// @param[out] absent 调用失败且错误表明对象确实不存在
/// @return 调用成功且字典被完整读取
bool get_all(sd_bus* bus, const std::string& object_path, const char* interface,
             SystemdUnitDelta& delta, bool& absent, uint64_t& cookie)
{
    sd_bus_error error    = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    const int r = sd_bus_call_method(bus, kSystemdService, object_path.c_str(),
                                     "org.freedesktop.DBus.Properties", "GetAll",
                                     &error, &reply, "s", interface);
    if (r < 0) {
        absent = is_absent_error(error);
        sd_bus_error_free(&error);
        return false;
    }
    sd_bus_error_free(&error);
    sd_bus_message_get_cookie(reply, &cookie);
    const bool ok = read_tracked_dict(reply, delta);
    sd_bus_message_unref(reply);
    return ok;
}

/// 单调时钟的纳秒读数，用于结算健康度与周期快照
std::int64_t now_ns()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

}  // namespace

// ============================================================
// SystemdUnitFilter
// ============================================================

bool SystemdUnitFilter::matches(const std::string& unit_id) const
{
    const std::string suffix = unit_suffix(unit_id);
    if (suffix.empty()) {
        return false;
    }
    if (std::find(unit_suffixes.begin(), unit_suffixes.end(), suffix) ==
        unit_suffixes.end()) {
        return false;
    }

    if (!whitelist.empty()) {  // 白名单是显式指定，优先于忽略列表
        return std::find(whitelist.begin(), whitelist.end(), unit_id) !=
               whitelist.end();
    }
    if (std::find(ignore_units.begin(), ignore_units.end(), unit_id) !=
        ignore_units.end()) {
        return false;
    }
    for (const std::string& prefix : ignore_prefixes) {
        if (unit_id.compare(0, prefix.size(), prefix) == 0) {
            return false;
        }
    }
    return true;
}

// ============================================================
// SystemdSignalTranslator
// ============================================================

SystemdSignalTranslator::SystemdSignalTranslator(SystemdUnitFilter filter,
                                                 SystemdProbe probe)
    : filter_(std::move(filter)), probe_(std::move(probe))
{
    if (!probe_.read_process) {
        probe_.read_process = read_proc_process;
    }
    if (!probe_.read_members) {
        probe_.read_members = [](const std::string& cgroup_path) {
            return RoleCgroupReader::read(cgroup_path);
        };
    }
}

bool SystemdSignalTranslator::accept_active_enter(const std::string& unit_id,
                                                  uint64_t value)
{
    if (value == 0) {
        return true;  // 停止时归零，是真实读数
    }
    const auto it = active_enter_high_water_.find(unit_id);
    if (it != active_enter_high_water_.end() && value <= it->second) {
        return false;  // 比已见最大值小：陈旧读数
    }
    active_enter_high_water_[unit_id] = value;
    return true;
}

void SystemdSignalTranslator::forget_ordering() { watermark_.clear(); }

void SystemdSignalTranslator::begin_segment()
{
    in_segment_ = true;
    segment_buffer_.clear();
}

std::vector<RoleObservation> SystemdSignalTranslator::end_segment()
{
    in_segment_ = false;
    return std::move(segment_buffer_);
}

/// 按段内 / 段外把评估产出的观察量送出去
/// @details 段内：流内观察进缓冲，等 end_segment 之后放行。段外：直接返回。
void SystemdSignalTranslator::deliver(const SystemdEvaluation& evaluation,
                                      SystemdTranslation& out)
{
    std::vector<RoleObservation>& sink =
        in_segment_ ? segment_buffer_ : out.observations;
    for (const RoleObservation& observation : evaluation.observations) {
        sink.push_back(observation);
    }
}

SystemdTranslation SystemdSignalTranslator::on_signal(const SystemdSignal& signal)
{
    SystemdTranslation result;

    switch (signal.kind) {
        case SystemdSignalKind::UNIT_PROPERTIES: {
            auto it = snapshots_.find(signal.object_path);
            if (it == snapshots_.end()) {
                // 首次见到该 unit：增量里没有 Id 与 ControlGroup，先补完整快照
                result.pending_snapshots.push_back(signal.object_path);
                break;
            }
            // 早于「已采纳读数」的增量在构造上就是旧的，采纳它只会把缓存拉回去：
            // 段内枚举可能读到比仍在途的流内消息更新的状态，迟到的那些消息会把
            // 同一次重启重放一遍。值上两者同形，只有序号能分
            const auto mark = watermark_.find(signal.object_path);
            if (signal.cookie != 0 && mark != watermark_.end() &&
                signal.cookie <= mark->second) {
                break;
            }
            if (!filter_.matches(it->second.id)) {
                break;
            }
            // 增量并入评估用副本，结论非未知才提交：未知时连缓存一起不推进，
            // 否则后续观察会被去重挡住、下游锚点永久停在旧值上
            SystemdUnitSnapshot candidate = it->second;
            SystemdUnitDelta delta        = signal.delta;
            if (delta.active_enter_monotonic &&
                !accept_active_enter(candidate.id,
                                     *delta.active_enter_monotonic)) {
                delta.active_enter_monotonic.reset();  // 陈旧读数不采纳，保留原值
            }
            merge(candidate, delta);
            const SystemdEvaluation evaluation =
                evaluate(it->second, candidate, /*announce=*/false);
            if (evaluation.kind != SystemdEvaluation::Kind::UNKNOWN) {
                it->second = candidate;
                if (signal.cookie != 0) {
                    watermark_[signal.object_path] = signal.cookie;
                }
            }
            deliver(evaluation, result);
            break;
        }
        case SystemdSignalKind::UNIT_NEW:
            // 不补快照：向尚未载入的 unit 对象发 GetAll 会使 systemd 就地载入
            // 该对象，载入即 UnitNew、随即卸载即 UnitRemoved，反复成环。从未
            // 启动的 unit 无主进程，本就不产出事件；已启动的 unit 由其属性变化
            // 按「首次见到」补快照，不依赖这里。
            break;
        case SystemdSignalKind::UNIT_REMOVED: {
            // 只丢弃属性快照，不参与存活判定
            snapshots_.erase(signal.object_path);
            watermark_.erase(signal.object_path);
            break;
        }
        case SystemdSignalKind::JOB_REMOVED:
        case SystemdSignalKind::NAME_OWNER_CHANGED:
            // 作业结果与 systemd 自身的存亡都只记日志：据此重取 unit 属性会把
            // 已卸载的对象重新载入，读回尚未更新的 MainPID，凭空产出一对加入/
            // 退出。重订阅与重新快照由发现器负责。
            break;
    }

    return result;
}

SystemdTranslation SystemdSignalTranslator::on_snapshot(
    const std::string& object_path, const SystemdUnitSnapshot& snapshot,
    uint64_t cookie)
{
    SystemdTranslation result;
    if (snapshot.id.empty()) {
        return result;  // 拿不到 Id 就无法构造实例键
    }
    if (cookie != 0) {
        watermark_[object_path] = cookie;  // 本次采纳的状态有多新
    }

    SystemdUnitSnapshot& stored      = snapshots_[object_path];
    const SystemdUnitSnapshot before = stored;
    if (!filter_.matches(snapshot.id)) {
        stored = snapshot;
        return result;
    }

    SystemdUnitSnapshot fetched = snapshot;
    if (!accept_active_enter(fetched.id, fetched.active_enter_monotonic)) {
        fetched.active_enter_monotonic = before.active_enter_monotonic;
    }

    // 段内枚举要 announce：状态表按代际对账，未变化的条目也须被 submit 命中一次
    SystemdEvaluation evaluation = evaluate(before, fetched, in_segment_);
    if (evaluation.kind != SystemdEvaluation::Kind::UNKNOWN) {
        stored = fetched;  // 未知不推进缓存，让下一次观察重新评估
    }
    // 枚举观察一律直接返回，段内也不缓冲：它要先于段内流内观察提交
    for (const RoleObservation& observation : evaluation.observations) {
        result.observations.push_back(observation);
    }
    return result;
}

SystemdEvaluation SystemdSignalTranslator::evaluate(
    const SystemdUnitSnapshot& before, const SystemdUnitSnapshot& after,
    bool announce)
{
    SystemdEvaluation result;
    if (!announce && same_tracked_fields(before, after)) {
        return result;  // 重复观察或重放的快照：不产出
    }

    // 存在判据由两层合成，缺一不可：
    //   进程层——主进程可确定（MainPID 非零且 /proc 可读）；
    //   状态层——源未宣告退出。ExecStop 未走完时主进程仍在跑、/proc 仍可读，
    //           但角色已不再对外可用，这一层只有源能给。
    if (declared_exit(after.active_state) || after.main_pid == 0) {
        // 源侧事实给出「不存在」：主进程已归零，或源已宣告退出
        result.kind = SystemdEvaluation::Kind::OBSERVED;
        result.observations.push_back(observe_leave(after.id));
        return result;
    }

    const std::optional<hng::Process> main = probe_.read_process(after.main_pid);
    if (!main.has_value()) {
        // 读不到一律是「未知」，不是「不存在」——据此产出退出会删掉存活条目、
        // 销毁载荷缓存，且下一次属性变化才把角色加回来
        result.kind = SystemdEvaluation::Kind::UNKNOWN;
        if (announce) {
            // 段内枚举到的条目锚点补不齐：仍须刷当代际，否则会被结算成幽灵退出
            result.observations.push_back(observe_unknown(after.id));
        }
        return result;
    }

    result.kind               = SystemdEvaluation::Kind::OBSERVED;
    // 只有锚点确实变了才轮到「交接还是重启」这个问题：锚点没变时既不是交接也
    // 不是重启，交给状态表按同一进程去重即可
    const bool anchor_changed = before.main_pid != after.main_pid;
    if (anchor_changed && reentered_active(before, after)) {
        // unit 重新进入过 active：这是重启，展开为退出 + 加入，不合并（§4.1）。
        // 判据用时间戳而不是「有没有观察到离开 active」，才能覆盖重连盲窗内
        // 发生的重启——那种情形下中间过程从未被观察到
        result.observations.push_back(observe_leave(after.id));
    }
    result.observations.push_back(observe_enter(build_payload(after, *main)));
    return result;
}

RolePayload SystemdSignalTranslator::build_payload(
    const SystemdUnitSnapshot& snapshot, const hng::Process& main) const
{
    RolePayload payload;
    payload.identity.instance_key               = snapshot.id;
    payload.identity.type_key                   = type_key_of(snapshot.id);
    payload.identity.source                     = RoleSource::SYSTEMD;

    payload.identity.attributes["active_state"] = snapshot.active_state;
    payload.identity.attributes["sub_state"]    = snapshot.sub_state;
    if (!snapshot.service_type.empty()) {
        payload.identity.attributes["service_type"] = snapshot.service_type;
    }

    payload.main_process = main;
    // systemd 的 ControlGroup 相对 cgroup 挂载点，载荷里给出可直接打开的绝对路径
    payload.cgroup_path  = RoleCgroupReader::absolute(snapshot.control_group);
    if (!payload.cgroup_path.empty()) {
        payload.member_processes = probe_.read_members(payload.cgroup_path);
    }
    return payload;
}

// ============================================================
// SystemdRoleDiscoverer
// ============================================================

SystemdRoleDiscoverer::SystemdRoleDiscoverer(RoleEventSink& sink, Config config)
    : sink_(sink),
      config_(std::move(config)),
      translator_(config_.filter, config_.probe)
{
    wakeup_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

SystemdRoleDiscoverer::~SystemdRoleDiscoverer()
{
    detach_stream();
    if (wakeup_fd_ >= 0) {
        ::close(wakeup_fd_);
    }
}

void SystemdRoleDiscoverer::run()
{
    if (stop_requested_.load()) {
        return;
    }
    attach_stream();        // ① 先建流
    prime_from_snapshot();  // ② 后快照
    // 首个快照结论：首次失败即不可用，后续重连不改写
    report_source_barrier(bus_ != nullptr);
    loop();  // ③ 循环，直到 stop()
    detach_stream();
}

void SystemdRoleDiscoverer::report_source_barrier(bool available)
{
    if (config_.barrier == nullptr || barrier_reported_) {
        return;
    }
    barrier_reported_ = true;
    config_.barrier->ready(RoleSource::SYSTEMD, available);
}

void SystemdRoleDiscoverer::stop()
{
    stop_requested_.store(true);
    if (wakeup_fd_ >= 0) {
        const uint64_t token  = 1;
        const ssize_t written = ::write(wakeup_fd_, &token, sizeof(token));
        (void)written;
    }
}

void SystemdRoleDiscoverer::publish(const RoleEvent& event)
{
    sink_.on_role_event(event);
}

void SystemdRoleDiscoverer::emit(const RoleEvent& event) { publish(event); }

void SystemdRoleDiscoverer::attach_stream()
{
    detach_stream();

    struct sd_bus* bus = nullptr;
    int r              = sd_bus_open_system(&bus);
    if (r < 0) {
        report("连接 system bus 失败", r);
        return;
    }
    bus_                             = bus;

    static const char* kMatchRules[] = {
        "type='signal',sender='org.freedesktop.systemd1',"
        "path_namespace='/org/freedesktop/systemd1/unit',"
        "interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged'",
        "type='signal',sender='org.freedesktop.systemd1',path='/org/freedesktop/"
        "systemd1',interface='org.freedesktop.systemd1.Manager',"
        "member='UnitNew'",
        "type='signal',sender='org.freedesktop.systemd1',path='/org/freedesktop/"
        "systemd1',interface='org.freedesktop.systemd1.Manager',"
        "member='UnitRemoved'",
        "type='signal',sender='org.freedesktop.systemd1',path='/org/freedesktop/"
        "systemd1',interface='org.freedesktop.systemd1.Manager',"
        "member='JobRemoved'",
        "type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/"
        "DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',"
        "arg0='org.freedesktop.systemd1'",
    };
    for (const char* rule : kMatchRules) {
        sd_bus_slot* slot = nullptr;
        // 用无捕获 lambda 适配 sd-bus 的回调签名，使头文件不必暴露 sd_bus_error
        r                 = sd_bus_add_match(
            bus_, &slot, rule,
            [](sd_bus_message* message, void* userdata, sd_bus_error*) -> int {
                static_cast<SystemdRoleDiscoverer*>(userdata)->handle_message(
                    message);
                return 1;
            },
            this);
        if (r < 0) {
            report("注册 match 规则失败", r);
            detach_stream();
            return;
        }
        slots_.push_back(slot);
    }

    subscribe();  // 不调用，systemd 不向本连接发送 unit 级信号
}

void SystemdRoleDiscoverer::detach_stream()
{
    for (sd_bus_slot* slot : slots_) {
        sd_bus_slot_unref(slot);
    }
    slots_.clear();
    if (bus_ != nullptr) {
        sd_bus_unref(bus_);
        bus_ = nullptr;
    }
    pending_snapshots_.clear();
    // 重连后 systemd 可能另起一条连接、序号从头开始；留着旧水位会把新消息
    // 全判成陈旧。丢掉水位最差也只是失去这一层保护，而重连后本就要重新快照
    translator_.forget_ordering();
}

bool SystemdRoleDiscoverer::subscribe()
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    const int r =
        sd_bus_call_method(bus_, kSystemdService, kManagerPath, kManagerIface,
                           "Subscribe", &error, nullptr, "");
    if (r < 0) {
        report("调用 Manager.Subscribe 失败（宿主可能不是 systemd init）", r);
        sd_bus_error_free(&error);
        return false;
    }
    sd_bus_error_free(&error);
    return true;
}

void SystemdRoleDiscoverer::prime_from_snapshot()
{
    next_snapshot_ns_ = snapshot_deadline_ns();  // 每次尝试都重新排期

    if (bus_ == nullptr) {
        return;
    }

    // 快照段：段内命中的条目刷当代际，段末未再出现的存活项按退出结算。
    // systemd 无子范围，范围留空即表的整个域
    table_.begin_snapshot();
    translator_.begin_segment();

    bool complete          = false;
    const std::size_t rows = enumerate_units(complete);

    if (!complete) {
        // 枚举没走完就不是权威状态，据它结算会误杀仍存活但没枚举到的角色。
        // 退回「只喂不结算」，下一次完整段自会修正；持续作废须可见
        ++voids_;
        std::fprintf(stderr,
                     "[role_systemd] 枚举未走完（%zu 行），本次段作废、不结算\n",
                     rows);
    }
    else {
        for (const RoleEvent& event : table_.end_snapshot()) {
            emit(event);
        }
        ++settlements_;
        last_settlement_ns_.store(now_ns());
    }

    // 缓冲的流内观察一律放行，顺序即到达顺序。作废只是不结算，不丢观察量
    for (const RoleObservation& observation : translator_.end_segment()) {
        submit(observation);
    }
}

std::size_t SystemdRoleDiscoverer::enumerate_units(bool& complete)
{
    complete = false;
    if (bus_ == nullptr) {
        return 0;
    }

    sd_bus_error error    = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    int r = sd_bus_call_method(bus_, kSystemdService, kManagerPath, kManagerIface,
                               "ListUnits", &error, &reply, "");
    if (r < 0) {
        report("调用 Manager.ListUnits 失败", r);
        sd_bus_error_free(&error);
        return 0;
    }
    sd_bus_error_free(&error);

    // 应答的容器类型不符：一个 unit 都没枚举到，不能读成「枚举结果为空」
    r = sd_bus_message_enter_container(reply, 'a', "(ssssssouso)");
    if (r < 0) {
        ++anomalies_;
        std::fprintf(stderr,
                     "[role_systemd] ListUnits 应答格式不符，本次段作废\n");
        sd_bus_message_unref(reply);
        return 0;
    }

    std::size_t rows = 0;
    while ((r = sd_bus_message_enter_container(reply, 'r', "ssssssouso")) > 0) {
        const char *name = nullptr, *description = nullptr, *load_state = nullptr,
                   *active_state = nullptr, *sub_state = nullptr,
                   *following = nullptr, *object_path = nullptr,
                   *job_type = nullptr, *job_path = nullptr;
        uint32_t job_id = 0;
        if (sd_bus_message_read(reply, "ssssssouso", &name, &description,
                                &load_state, &active_state, &sub_state,
                                &following, &object_path, &job_id, &job_type,
                                &job_path) < 0) {
            // 逐行读取失败：剩余 unit 全部落下，收尾照常会让人以为枚举完整
            ++anomalies_;
            std::fprintf(stderr,
                         "[role_systemd] ListUnits 逐行读取中断于第 %zu 行，"
                         "本次段作废\n",
                         rows);
            sd_bus_message_unref(reply);
            return rows;
        }
        sd_bus_message_exit_container(reply);
        ++rows;

        if (name == nullptr || object_path == nullptr ||
            !config_.filter.matches(name)) {
            continue;
        }
        harvest_unit(object_path, name);
    }
    sd_bus_message_exit_container(reply);
    sd_bus_message_unref(reply);

    complete = true;
    return rows;
}

void SystemdRoleDiscoverer::harvest_unit(const std::string& object_path,
                                         const std::string& unit_id)
{
    const SystemdFetchResult fetched = fetch_snapshot(object_path);
    switch (fetched.kind) {
        case SystemdFetchResult::Kind::FOUND:
            submit(translator_.on_snapshot(object_path, fetched.snapshot,
                                           fetched.cookie));
            break;
        case SystemdFetchResult::Kind::ABSENT:
            // 对象确实不存在：源侧事实，产出退出。成高频即说明 ListUnits 与
            // 取数之间的卸载窗口在被打中
            ++units_gone_;
            submit(observe_leave(unit_id));
            break;
        case SystemdFetchResult::Kind::UNKNOWN:
            // 取数失败不能压成「不存在」：喂一条未知观察量，它不产出跃迁，
            // 但计为本段已见，免于被对账清掉
            ++unknown_fetches_;
            submit(observe_unknown(unit_id));
            break;
    }
}

SystemdFetchResult SystemdRoleDiscoverer::fetch_snapshot(
    const std::string& object_path)
{
    SystemdFetchResult result;

    // Unit 接口给 Id / LoadState / ActiveState / SubState /
    // ActiveEnterTimestamp， Service 接口给 Type / MainPID /
    // ControlGroup，两者分开取
    SystemdUnitDelta unit_delta;
    bool absent     = false;
    uint64_t cookie = 0;
    if (!get_all(bus_, object_path, kUnitInterface, unit_delta, absent, cookie)) {
        result.kind = absent ? SystemdFetchResult::Kind::ABSENT
                             : SystemdFetchResult::Kind::UNKNOWN;
        return result;
    }
    // 水位取「本次读数最早的那一发应答」：早于它的消息对整次读数都是旧的。
    // 不取较晚那一发——两次应答之间到达的增量可能携带更新的 Unit 侧字段
    // （重启恰好落在这两次调用之间时，Unit 应答给旧化身、Service 应答给新化身），
    // 丢掉它就再也修不回来，重启会被折叠成主进程更换
    result.cookie = cookie;
    merge(result.snapshot, unit_delta);
    if (result.snapshot.id.empty()) {
        // 拿不到 Id 就构造不出实例键，源侧对这次观察无结论
        result.kind = SystemdFetchResult::Kind::UNKNOWN;
        return result;
    }
    // 非 .service 单元无主进程锚点（.scope 亦然），只回 Unit 接口的部分，
    // 由翻译层按过滤器挡下并缓存，避免其每次属性变化都重取一次
    if (unit_suffix(result.snapshot.id) != "service") {
        result.kind = SystemdFetchResult::Kind::FOUND;
        return result;
    }

    SystemdUnitDelta service_delta;
    absent = false;
    if (!get_all(bus_, object_path, kServiceInterface, service_delta, absent,
                 cookie)) {
        // 取不全就不判定：主进程锚点在 Service 接口上，缺了它无法区分「没有主
        // 进程」与「没取到」，据半份快照结算会把存活角色误报为退出
        result.kind = SystemdFetchResult::Kind::UNKNOWN;
        return result;
    }
    merge(result.snapshot, service_delta);
    result.kind = SystemdFetchResult::Kind::FOUND;
    return result;
}

int SystemdRoleDiscoverer::dispatch_pending()
{
    int processed = 0;
    for (;;) {
        const int r = sd_bus_process(bus_, nullptr);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            return processed;
        }
        ++processed;
    }
}

void SystemdRoleDiscoverer::resolve_pending_snapshots()
{
    if (pending_snapshots_.empty() || bus_ == nullptr) {
        return;
    }
    std::vector<std::string> paths;
    paths.swap(pending_snapshots_);
    for (const std::string& path : paths) {
        if (stop_requested_.load()) {
            return;
        }
        // 段外取不到就放弃，等该 unit 的下一次属性变化再来：这里是首次见到
        // 某个对象路径，拿不到 Id 就构造不出实例键，源侧对这次观察无结论
        const SystemdFetchResult fetched = fetch_snapshot(path);
        if (fetched.kind != SystemdFetchResult::Kind::FOUND) {
            ++unknown_fetches_;
            continue;
        }
        submit(translator_.on_snapshot(path, fetched.snapshot, fetched.cookie));
    }
}

void SystemdRoleDiscoverer::submit(const SystemdTranslation& translation)
{
    for (const std::string& path : translation.pending_snapshots) {
        if (std::find(pending_snapshots_.begin(), pending_snapshots_.end(),
                      path) == pending_snapshots_.end()) {
            pending_snapshots_.push_back(path);
        }
    }
    for (const RoleObservation& observation : translation.observations) {
        submit(observation);
    }
}

void SystemdRoleDiscoverer::submit(const RoleObservation& observation)
{
    if (std::optional<RoleEvent> event = table_.submit(observation)) {
        emit(*event);
    }
}

int SystemdRoleDiscoverer::next_snapshot_timeout_ms() const
{
    if (next_snapshot_ns_ < 0) {
        return -1;  // 未启用周期快照：无限等待
    }
    const std::int64_t remaining = next_snapshot_ns_ - now_ns();
    if (remaining <= 0) {
        return 0;
    }
    return static_cast<int>(remaining / 1000000);
}

std::int64_t SystemdRoleDiscoverer::snapshot_deadline_ns() const
{
    if (config_.snapshot_interval.count() <= 0) {
        return -1;
    }
    return now_ns() + std::chrono::duration_cast<std::chrono::nanoseconds>(
                          config_.snapshot_interval)
                          .count();
}

SystemdSettlementStats SystemdRoleDiscoverer::settlement_stats() const
{
    SystemdSettlementStats stats;
    stats.settlements       = settlements_.load();
    stats.voids             = voids_.load();
    stats.anomalies         = anomalies_.load();
    stats.units_gone        = units_gone_.load();
    stats.unknown_fetches   = unknown_fetches_.load();

    const std::int64_t last = last_settlement_ns_.load();
    if (last >= 0) {
        stats.since_last_settlement_ms = (now_ns() - last) / 1000000;  // 毫秒
    }
    return stats;
}

void SystemdRoleDiscoverer::backoff_wait(int& attempt)
{
    const int shift = std::min(attempt, 16);
    const int delay = std::min(kBackoffBaseMs << shift, kBackoffMaxMs);
    ++attempt;

    struct pollfd wakeup;
    wakeup.fd      = wakeup_fd_;
    wakeup.events  = POLLIN;
    wakeup.revents = 0;
    if (::poll(&wakeup, 1, delay) > 0 && wakeup.revents != 0) {
        uint64_t token    = 0;
        const ssize_t got = ::read(wakeup_fd_, &token, sizeof(token));
        (void)got;  // 收到停止通知，下一轮循环即返回
    }
}

void SystemdRoleDiscoverer::loop()
{
    int attempt = 0;
    while (!stop_requested_.load()) {
        if (bus_ == nullptr) {  // 尚未连上或刚断开：退避后重连并重新快照
            backoff_wait(attempt);
            if (stop_requested_.load()) {
                break;
            }
            attach_stream();
            if (bus_ == nullptr) {
                continue;
            }
            attempt = 0;
            prime_from_snapshot();
            continue;
        }

        const int drained = dispatch_pending();
        if (drained < 0) {
            detach_stream();
            continue;
        }

        if (resubscribe_requested_) {  // systemd 自身重新出现
            resubscribe_requested_ = false;
            if (!subscribe()) {
                detach_stream();
                continue;
            }
            prime_from_snapshot();
        }

        resolve_pending_snapshots();
        if (drained > 0) {
            continue;  // 本轮有消息，可能又置了待补快照，再排空一次
        }

        // 周期快照：给「没断连但信号被丢」产生的幽灵设上界。与重连路径共用
        // 同一次结算，故只对本轮 ListUnits 返回、且活动的行取数
        if (next_snapshot_ns_ >= 0 && now_ns() >= next_snapshot_ns_) {
            prime_from_snapshot();
            continue;
        }

        struct pollfd fds[2];
        fds[0].fd       = sd_bus_get_fd(bus_);
        fds[0].events   = static_cast<short>(sd_bus_get_events(bus_));
        fds[0].revents  = 0;
        fds[1].fd       = wakeup_fd_;
        fds[1].events   = POLLIN;
        fds[1].revents  = 0;

        const int ready = ::poll(fds, 2, next_snapshot_timeout_ms());
        if (ready < 0 && errno != EINTR) {
            detach_stream();
        }
        if (fds[1].revents != 0) {
            uint64_t token    = 0;
            const ssize_t got = ::read(wakeup_fd_, &token, sizeof(token));
            (void)got;
        }
    }
}

namespace {

/// 解码一条消息；不属于监测范围时返回 false
bool decode_message(sd_bus_message* message, SystemdSignal& signal)
{
    const char* member = sd_bus_message_get_member(message);
    const char* path   = sd_bus_message_get_path(message);
    if (member == nullptr || path == nullptr) {
        return false;
    }

    if (std::strcmp(member, "PropertiesChanged") == 0) {
        const char* interface = nullptr;
        if (sd_bus_message_read(message, "s", &interface) < 0 ||
            interface == nullptr) {
            return false;
        }
        // 只跟踪 Unit 与 Service 两个接口上的属性
        if (std::strcmp(interface, kUnitInterface) != 0 &&
            std::strcmp(interface, kServiceInterface) != 0) {
            return false;
        }
        signal.kind        = SystemdSignalKind::UNIT_PROPERTIES;
        signal.object_path = path;
        sd_bus_message_get_cookie(message, &signal.cookie);
        return read_tracked_dict(message, signal.delta);
    }

    if (std::strcmp(member, "UnitNew") == 0 ||
        std::strcmp(member, "UnitRemoved") == 0) {
        const char* unit_id   = nullptr;
        const char* unit_path = nullptr;
        if (sd_bus_message_read(message, "so", &unit_id, &unit_path) < 0 ||
            unit_id == nullptr || unit_path == nullptr) {
            return false;
        }
        signal.kind        = (std::strcmp(member, "UnitNew") == 0)
                                 ? SystemdSignalKind::UNIT_NEW
                                 : SystemdSignalKind::UNIT_REMOVED;
        signal.unit_id     = unit_id;
        signal.object_path = unit_path;
        return true;
    }

    if (std::strcmp(member, "JobRemoved") == 0) {
        uint32_t job_id      = 0;
        const char* job_path = nullptr;
        const char* unit_id  = nullptr;
        const char* result   = nullptr;
        if (sd_bus_message_read(message, "uoss", &job_id, &job_path, &unit_id,
                                &result) < 0 ||
            unit_id == nullptr || result == nullptr) {
            return false;
        }
        signal.kind       = SystemdSignalKind::JOB_REMOVED;
        signal.unit_id    = unit_id;
        signal.job_result = result;
        return true;
    }

    if (std::strcmp(member, "NameOwnerChanged") == 0) {
        const char *name = nullptr, *old_owner = nullptr, *new_owner = nullptr;
        if (sd_bus_message_read(message, "sss", &name, &old_owner, &new_owner) <
                0 ||
            name == nullptr || new_owner == nullptr) {
            return false;
        }
        if (std::strcmp(name, kSystemdService) != 0) {
            return false;
        }
        signal.kind      = SystemdSignalKind::NAME_OWNER_CHANGED;
        signal.new_owner = new_owner;
        return true;
    }

    return false;
}

}  // namespace

void SystemdRoleDiscoverer::handle_message(sd_bus_message* message)
{
    SystemdSignal signal;
    if (!decode_message(message, signal)) {
        return;
    }

    if (signal.kind == SystemdSignalKind::NAME_OWNER_CHANGED) {
        if (signal.new_owner.empty()) {
            std::fprintf(stderr, "[role_systemd] systemd 从总线上消失\n");
        }
        else {
            std::fprintf(stderr, "[role_systemd] systemd 重新出现，重新订阅\n");
            resubscribe_requested_ = true;  // 重订阅与重新快照在循环体里做
        }
        return;
    }

    if (signal.kind == SystemdSignalKind::JOB_REMOVED) {
        std::fprintf(stderr, "[role_systemd] 作业结束 %s result=%s\n",
                     signal.unit_id.c_str(), signal.job_result.c_str());
    }
    if (signal.delta.sub_state && *signal.delta.sub_state == "auto-restart") {
        std::fprintf(stderr, "[role_systemd] %s 进入自动重启\n",
                     signal.object_path.c_str());
    }

    submit(translator_.on_signal(signal));
}

}  // namespace role
}  // namespace hng

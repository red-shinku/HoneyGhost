/**
 * @file role_systemd_discoverer.cc
 * @brief systemd 角色发现器的翻译层与 sd-bus 接线实现
 * @author red_shinku
 * @date 2026.9.12
 */

#include "./include/role_systemd_discoverer.hpp"

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

#include "agent/control_plane/role_discovery/include/role_cgroup_reader.hpp"

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
/// @note 只有 deactivating / failed。inactive 不算宣告退出：瞬态单元上 systemd
/// 会先发 MainPID，再补一个值更旧的 ActiveState=inactive，随后才回 activating，
/// 把这帧读成退出会凭空产出一对加入/退出；正常停止路径上 active 先经
/// deactivating，退出在该处即已发布，故不取 inactive 不改变停止路径的行为。
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
}

/// 被跟踪字段是否全等
bool same_tracked_fields(const SystemdUnitSnapshot& a,
                         const SystemdUnitSnapshot& b)
{
    return a.id == b.id && a.load_state == b.load_state &&
           a.active_state == b.active_state && a.sub_state == b.sub_state &&
           a.service_type == b.service_type && a.main_pid == b.main_pid &&
           a.control_group == b.control_group;
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

const char* action_name(RoleAction action)
{
    switch (action) {
        case RoleAction::JOIN:
            return "JOIN";
        case RoleAction::LEAVE:
            return "LEAVE";
        case RoleAction::MAIN_PROCESS_CHANGE:
            return "MAIN_PROCESS_CHANGE";
    }
    return "?";
}

/// 默认事件出口：往 stderr 打一行摘要
void print_event(const RoleEvent& event)
{
    std::fprintf(
        stderr,
        "[role_systemd] %-19s %-32s pid=%-7u start=%-12llu 成员=%zu "
        "cgroup=%s\n",
        action_name(event.action), event.payload.identity.instance_key.c_str(),
        event.payload.main_process.pid,
        static_cast<unsigned long long>(
            event.payload.main_process.pid_start_time),
        event.payload.member_processes.size(), event.payload.cgroup_path.c_str());
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
        else {
            sd_bus_message_skip(message, nullptr);
        }
        sd_bus_message_exit_container(message);  // variant
        sd_bus_message_exit_container(message);  // dict entry
    }
    sd_bus_message_exit_container(message);  // array
    return r == 0;
}

/// 取一个对象在指定接口上的全部属性，只留下被跟踪的字段
bool get_all(sd_bus* bus, const std::string& object_path, const char* interface,
             SystemdUnitDelta& delta)
{
    sd_bus_error error    = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    const int r = sd_bus_call_method(bus, kSystemdService, object_path.c_str(),
                                     "org.freedesktop.DBus.Properties", "GetAll",
                                     &error, &reply, "s", interface);
    if (r < 0) {
        sd_bus_error_free(&error);
        return false;
    }
    sd_bus_error_free(&error);
    const bool ok = read_tracked_dict(reply, delta);
    sd_bus_message_unref(reply);
    return ok;
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
            const SystemdUnitSnapshot before = it->second;
            merge(it->second, signal.delta);
            if (!filter_.matches(it->second.id)) {
                break;
            }
            if (std::optional<RoleObservation> observation =
                    evaluate(before, it->second)) {
                result.observations.push_back(std::move(*observation));
            }
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
            auto it = snapshots_.find(signal.object_path);
            if (it != snapshots_.end()) {
                snapshots_.erase(it);
            }
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
    const std::string& object_path, const SystemdUnitSnapshot& snapshot)
{
    SystemdTranslation result;
    if (snapshot.id.empty()) {
        return result;  // 拿不到 Id 就无法构造实例键
    }

    SystemdUnitSnapshot& stored      = snapshots_[object_path];
    const SystemdUnitSnapshot before = stored;
    stored                           = snapshot;

    if (!filter_.matches(snapshot.id)) {
        return result;
    }
    if (std::optional<RoleObservation> observation = evaluate(before, stored)) {
        result.observations.push_back(std::move(*observation));
    }
    return result;
}

std::optional<RoleObservation> SystemdSignalTranslator::evaluate(
    const SystemdUnitSnapshot& before, const SystemdUnitSnapshot& after)
{
    if (same_tracked_fields(before, after)) {
        return std::nullopt;  // 重复观察或重放的快照：不产出
    }

    // 存在判据由两层合成，缺一不可：
    //   进程层——主进程可确定（MainPID 非零且 /proc 可读）；
    //   状态层——源未宣告退出。ExecStop 未走完时主进程仍在跑、/proc 仍可读，
    //           但角色已不再对外可用，这一层只有源能给。
    std::optional<hng::Process> main;
    if (!declared_exit(after.active_state) && after.main_pid != 0) {
        main = probe_.read_process(after.main_pid);
    }
    if (main.has_value()) {
        return observe_enter(build_payload(after, *main));
    }
    return observe_leave(after.id);
}

RolePayload SystemdSignalTranslator::build_payload(
    const SystemdUnitSnapshot& snapshot, const hng::Process& main) const
{
    RolePayload payload;
    payload.identity.instance_key               = snapshot.id;
    payload.identity.type_key                   = type_key_of(snapshot.id);

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

SystemdRoleDiscoverer::SystemdRoleDiscoverer(Config config)
    : config_(std::move(config)), translator_(config_.filter, config_.probe)
{
    if (!config_.on_event) {
        config_.on_event = print_event;
    }
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
    loop();                 // ③ 循环，直到 stop()
    detach_stream();
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

void SystemdRoleDiscoverer::publish()
{
    // 事件当前经 Config::on_event 交付，本接口待阶段 05 定稿
}

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
    if (bus_ == nullptr) {
        return;
    }

    sd_bus_error error    = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    int r = sd_bus_call_method(bus_, kSystemdService, kManagerPath, kManagerIface,
                               "ListUnits", &error, &reply, "");
    if (r < 0) {
        report("调用 Manager.ListUnits 失败", r);
        sd_bus_error_free(&error);
        return;
    }
    sd_bus_error_free(&error);

    r = sd_bus_message_enter_container(reply, 'a', "(ssssssouso)");
    if (r < 0) {
        sd_bus_message_unref(reply);
        return;
    }
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
            break;
        }
        sd_bus_message_exit_container(reply);

        if (name != nullptr && object_path != nullptr &&
            config_.filter.matches(name)) {
            if (std::optional<SystemdUnitSnapshot> snapshot =
                    fetch_snapshot(object_path)) {
                submit(translator_.on_snapshot(object_path, *snapshot));
            }
        }
    }
    sd_bus_message_exit_container(reply);
    sd_bus_message_unref(reply);
}

std::optional<SystemdUnitSnapshot> SystemdRoleDiscoverer::fetch_snapshot(
    const std::string& object_path)
{
    // Unit 接口给 Id / LoadState / ActiveState / SubState，
    // Service 接口给 Type / MainPID / ControlGroup，两者分开取
    SystemdUnitDelta unit_delta;
    if (!get_all(bus_, object_path, kUnitInterface, unit_delta)) {
        return std::nullopt;
    }
    SystemdUnitSnapshot snapshot;
    merge(snapshot, unit_delta);
    if (snapshot.id.empty()) {
        return std::nullopt;
    }
    // 非 .service 单元无主进程锚点（.scope 亦然），只回 Unit 接口的部分，
    // 由翻译层按过滤器挡下并缓存，避免其每次属性变化都重取一次
    if (unit_suffix(snapshot.id) != "service") {
        return snapshot;
    }

    SystemdUnitDelta service_delta;
    if (!get_all(bus_, object_path, kServiceInterface, service_delta)) {
        return std::nullopt;  // 取不全就不判定，避免把存活角色误报为退出
    }
    merge(snapshot, service_delta);
    return snapshot;
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
        std::optional<SystemdUnitSnapshot> snapshot = fetch_snapshot(path);
        if (!snapshot) {
            continue;  // 取不到就放弃，等该 unit 的下一次属性变化再来
        }
        submit(translator_.on_snapshot(path, *snapshot));
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
        if (std::optional<RoleEvent> event = table_.submit(observation)) {
            config_.on_event(*event);
        }
    }
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

        struct pollfd fds[2];
        fds[0].fd       = sd_bus_get_fd(bus_);
        fds[0].events   = static_cast<short>(sd_bus_get_events(bus_));
        fds[0].revents  = 0;
        fds[1].fd       = wakeup_fd_;
        fds[1].events   = POLLIN;
        fds[1].revents  = 0;

        const int ready = ::poll(fds, 2, -1);
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
        uint64_t cookie = 0;
        sd_bus_message_get_cookie(message, &cookie);
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

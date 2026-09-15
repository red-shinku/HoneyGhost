/**
 * @file role_containerd_discoverer.cc
 * @brief containerd 角色发现器的翻译层与 socket 接线实现
 * @author red_shinku
 * @date 2026.9.13
 */

#include "./include/role_containerd_discoverer.hpp"

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

#include "agent/control_plane/role_discovery/include/role_cgroup_reader.hpp"
#include "role_containerd_bridge.pb.h"

namespace hng {
namespace role {

namespace {

/// 单帧上限，与翻译进程侧一致
constexpr uint32_t kMaxFrameBytes = 4u << 20;

/// 读一帧内字节的等待上限：本地 socket 上帧很小，久等不来即视为连接已坏
constexpr int kReadTimeoutSec     = 5;

/// 取镜像引用的最后一段，去掉 registry、tag 与 digest
std::string image_basename(const std::string& image)
{
    std::string name = image;
    if (const std::size_t digest = name.find('@'); digest != std::string::npos) {
        name.resize(digest);
    }
    // 只有冒号出现在最后一段时才当 tag：registry 的端口号前面有 '/'
    const std::size_t colon = name.rfind(':');
    if (colon != std::string::npos && name.find('/') < colon) {
        name.resize(colon);
    }
    if (const std::size_t slash = name.rfind('/'); slash != std::string::npos) {
        name = name.substr(slash + 1);
    }
    return name;
}

/// 类型键：k8s 容器取 io.kubernetes.container.name，其余退化到镜像引用的最后一段
/// @note 非 k8s 容器的映射规则是待定项，此处只做退化，不做配置
std::string type_key_of(const ContainerAttributes& attributes)
{
    if (!attributes.container_name.empty()) {
        return attributes.container_name;
    }
    std::string base = image_basename(attributes.image);
    if (!base.empty()) {
        return base;
    }
    return attributes.container_id;  // 退无可退时给出实例键，不留空类型键
}

/// 非空才写入属性，避免字典里堆一串空值
void set_attribute(std::map<std::string, std::string>& attributes,
                   const char* key, const std::string& value)
{
    if (!value.empty()) {
        attributes[key] = value;
    }
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

/// 默认 cgroup 路径探针：读 /proc/<pid>/cgroup 再拼上挂载点
std::string read_proc_cgroup_path(uint32_t pid)
{
    std::optional<std::string> path = RoleCgroupReader::read_process_cgroup(pid);
    if (!path) {
        return std::string();
    }
    return RoleCgroupReader::absolute(*path);
}

std::int64_t now_ns()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void report(const char* what)
{
    std::fprintf(stderr, "[role_containerd] %s：%s\n", what,
                 std::strerror(errno));
}

}  // namespace

// ============================================================
// 协议解码
// ============================================================

bool decode_frame(const hng::role_bridge::Frame& frame,
                  ContainerdMessage& message)
{
    switch (frame.body_case()) {
        case hng::role_bridge::Frame::kSnapshotBegin: {
            const hng::role_bridge::SnapshotBegin& begin = frame.snapshot_begin();
            message.kind            = ContainerdMessage::Kind::SNAPSHOT_BEGIN;
            message.source          = begin.source();
            message.backend_version = begin.backend_version();
            message.namespaces.assign(begin.namespaces().begin(),
                                      begin.namespaces().end());
            return true;
        }
        case hng::role_bridge::Frame::kObservation: {
            const hng::role_bridge::Observation& observation =
                frame.observation();
            switch (observation.kind()) {
                case hng::role_bridge::Observation::UPSERT:
                    message.observation.remove = false;
                    break;
                case hng::role_bridge::Observation::REMOVE:
                    message.observation.remove = true;
                    break;
                default:
                    return false;  // 未指定加入还是退出：无法判定，整帧丢弃
            }
            message.kind               = ContainerdMessage::Kind::OBSERVATION;

            ContainerdObservation& out = message.observation;
            out.in_snapshot            = observation.in_snapshot();
            out.pid                    = observation.pid();
            out.timestamp_ns           = observation.timestamp_ns();

            ContainerAttributes& attributes = out.attributes;
            attributes.container_id         = observation.container_id();
            // namespace 是 C++ 关键字，生成物给的访问器带下划线
            attributes.container_namespace  = observation.namespace_();
            attributes.pod_uid              = observation.pod_uid();
            attributes.pod_name             = observation.pod_name();
            attributes.pod_namespace        = observation.pod_namespace();
            attributes.container_name       = observation.container_name();
            attributes.image                = observation.image();
            attributes.labels.clear();
            for (const auto& label : observation.labels()) {
                attributes.labels.emplace(label.first, label.second);
            }
            return true;
        }
        case hng::role_bridge::Frame::kSnapshotEnd:
            message.kind           = ContainerdMessage::Kind::SNAPSHOT_END;
            message.declared_count = frame.snapshot_end().count();
            return true;
        default:
            return false;  // 空帧：不属于本协议
    }
}

// ============================================================
// ContainerFilter
// ============================================================

bool ContainerFilter::matches(const ContainerAttributes& attributes) const
{
    if (!namespace_whitelist.empty() &&
        std::find(namespace_whitelist.begin(), namespace_whitelist.end(),
                  attributes.container_namespace) == namespace_whitelist.end()) {
        return false;
    }
    // agent 自身的容器（含翻译进程自身）属于 agent 所在的 Pod
    if (!attributes.pod_uid.empty() &&
        std::find(exclude_pod_uids.begin(), exclude_pod_uids.end(),
                  attributes.pod_uid) != exclude_pod_uids.end()) {
        return false;
    }
    return true;
}

// ============================================================
// ContainerdBridgeTranslator
// ============================================================

ContainerdBridgeTranslator::ContainerdBridgeTranslator(ContainerFilter filter,
                                                       ContainerProbe probe)
    : filter_(std::move(filter)), probe_(std::move(probe))
{
    if (!probe_.read_process) {
        probe_.read_process = read_proc_process;
    }
    if (!probe_.read_cgroup_path) {
        probe_.read_cgroup_path = read_proc_cgroup_path;
    }
    if (!probe_.read_members) {
        probe_.read_members = [](const std::string& cgroup_path) {
            return RoleCgroupReader::read(cgroup_path);
        };
    }
}

ContainerTranslation ContainerdBridgeTranslator::on_message(
    const ContainerdMessage& message)
{
    ContainerTranslation out;

    switch (message.kind) {
        case ContainerdMessage::Kind::SNAPSHOT_BEGIN:
            in_snapshot_      = true;
            segment_scope_    = message.namespaces;
            segment_received_ = 0;
            for (auto& entry : pending_) {
                entry.second.seen = false;
            }
            {
                ContainerCommand command;
                command.kind  = ContainerCommand::Kind::BEGIN_SNAPSHOT;
                command.scope = message.namespaces;
                out.commands.push_back(std::move(command));
            }
            break;

        case ContainerdMessage::Kind::OBSERVATION: {
            const ContainerdObservation& observation = message.observation;
            // 段内只应有枚举项，段外只应有流内项；反过来即帧序违约
            if (observation.in_snapshot != in_snapshot_) {
                out.violations.push_back(observation.attributes.container_id +
                                         (observation.in_snapshot
                                              ? "：段外出现枚举项"
                                              : "：段内出现流内项"));
            }
            if (observation.in_snapshot) {
                ++segment_received_;
            }

            if (observation.remove) {
                pending_.erase(observation.attributes.container_id);
                ContainerCommand command;
                command.kind = ContainerCommand::Kind::SUBMIT;
                command.observation =
                    observe_leave(observation.attributes.container_id);
                out.commands.push_back(std::move(command));
                break;
            }

            // 被过滤掉的容器既不喂观察量，也不计入「本段已见」：它的条目本就不
            // 存在，而计入会让过滤策略一改就留下一批幽灵
            if (!filter_.matches(observation.attributes)) {
                break;
            }
            if (std::optional<RoleObservation> enter =
                    build_enter(observation.attributes, observation.pid)) {
                pending_.erase(observation.attributes.container_id);
                ContainerCommand command;
                command.kind        = ContainerCommand::Kind::SUBMIT;
                command.observation = std::move(*enter);
                out.commands.push_back(std::move(command));
                break;
            }
            defer_anchor(observation.attributes, observation.pid, out);
            break;
        }

        case ContainerdMessage::Kind::SNAPSHOT_END: {
            const bool complete = segment_received_ == message.declared_count;
            if (!complete) {
                out.violations.push_back("段内条目数与源侧声明不符：实收 " +
                                         std::to_string(segment_received_) +
                                         " 声明 " +
                                         std::to_string(message.declared_count));
            }
            else {
                // 本段没再见到的待补锚点项：容器已不在运行，撤下
                for (auto it = pending_.begin(); it != pending_.end();) {
                    const bool in_scope =
                        std::find(segment_scope_.begin(), segment_scope_.end(),
                                  it->second.attributes.container_namespace) !=
                        segment_scope_.end();
                    if (in_scope && !it->second.seen) {
                        it = pending_.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            }

            ContainerCommand command;
            command.kind           = ContainerCommand::Kind::END_SNAPSHOT;
            command.settle         = complete;
            command.declared_count = message.declared_count;
            command.received_count = segment_received_;
            out.commands.push_back(std::move(command));

            reset_segment();
            break;
        }
    }

    return out;
}

ContainerTranslation ContainerdBridgeTranslator::retry_pending()
{
    ContainerTranslation out;
    if (in_snapshot_) {
        // 段内不放行：流内观察插在枚举项之间会破坏段内顺序，而新补齐的项若不在
        // 本段枚举里，紧接着的对账就会把它清掉，产出一对无谓的加入/退出
        return out;
    }
    for (auto it = pending_.begin(); it != pending_.end();) {
        std::optional<RoleObservation> enter =
            build_enter(it->second.attributes, it->second.pid);
        if (!enter) {
            ++it;
            continue;
        }
        ContainerCommand command;
        command.kind        = ContainerCommand::Kind::SUBMIT;
        command.observation = std::move(*enter);
        out.commands.push_back(std::move(command));
        it = pending_.erase(it);
    }
    return out;
}

void ContainerdBridgeTranslator::reset_segment()
{
    in_snapshot_ = false;
    segment_scope_.clear();
    segment_received_ = 0;
}

std::optional<RoleObservation> ContainerdBridgeTranslator::build_enter(
    const ContainerAttributes& attributes, uint32_t pid) const
{
    std::optional<hng::Process> main = probe_.read_process(pid);
    if (!main) {
        return std::nullopt;  // 读不到即未知，不得读成不存在
    }

    RolePayload payload;
    payload.identity.instance_key             = attributes.container_id;
    payload.identity.type_key                 = type_key_of(attributes);
    payload.identity.attributes               = attributes.labels;

    std::map<std::string, std::string>& extra = payload.identity.attributes;
    set_attribute(extra, "namespace", attributes.container_namespace);
    set_attribute(extra, "container_name", attributes.container_name);
    set_attribute(extra, "pod_uid", attributes.pod_uid);
    set_attribute(extra, "pod_name", attributes.pod_name);
    set_attribute(extra, "pod_namespace", attributes.pod_namespace);
    set_attribute(extra, "image", attributes.image);

    payload.main_process = *main;
    payload.cgroup_path  = probe_.read_cgroup_path(pid);
    if (!payload.cgroup_path.empty()) {
        payload.member_processes = probe_.read_members(payload.cgroup_path);
    }
    return observe_enter(std::move(payload), attributes.container_namespace);
}

void ContainerdBridgeTranslator::defer_anchor(
    const ContainerAttributes& attributes, uint32_t pid,
    ContainerTranslation& out)
{
    PendingAnchor& entry = pending_[attributes.container_id];
    entry.attributes     = attributes;
    entry.pid            = pid;
    entry.seen           = in_snapshot_;

    // 段内的未知项必须计为「本段已见」，否则它的条目会被本段对账清除，而它
    // 其实还活着，只是这一刻取不到锚点。段外无处可依，只入队等下一轮。
    if (in_snapshot_) {
        ContainerCommand command;
        command.kind        = ContainerCommand::Kind::SUBMIT;
        command.observation = observe_unknown(attributes.container_id);
        out.commands.push_back(std::move(command));
    }
}

// ============================================================
// ContainerdRoleDiscoverer
// ============================================================

ContainerdRoleDiscoverer::ContainerdRoleDiscoverer(RoleEventSink& sink,
                                                   Config config)
    : sink_(sink),
      config_(std::move(config)),
      translator_(config_.filter, config_.probe)
{
    wakeup_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

ContainerdRoleDiscoverer::~ContainerdRoleDiscoverer()
{
    detach();
    if (wakeup_fd_ >= 0) {
        ::close(wakeup_fd_);
    }
}

void ContainerdRoleDiscoverer::run()
{
    if (stop_requested_.load()) {
        return;
    }
    loop();  // 连接即建源，断开即回到连接
}

void ContainerdRoleDiscoverer::stop()
{
    stop_requested_.store(true);
    if (wakeup_fd_ >= 0) {
        const uint64_t token  = 1;
        const ssize_t written = ::write(wakeup_fd_, &token, sizeof(token));
        (void)written;
    }
}

void ContainerdRoleDiscoverer::publish(const RoleEvent& event)
{
    sink_.on_role_event(event);
}

void ContainerdRoleDiscoverer::emit(const RoleEvent& event) { publish(event); }

SettlementStats ContainerdRoleDiscoverer::settlement_stats() const
{
    SettlementStats stats;
    stats.settlements       = settlements_.load();
    stats.voids             = voids_.load();
    stats.anomalies         = anomalies_.load();
    stats.pending_anchors   = translator_.pending_anchors();

    const std::int64_t last = last_settlement_ns_.load();
    if (last >= 0) {
        stats.since_last_settlement_ms = (now_ns() - last) / 1000000;  // 单位毫秒
    }
    return stats;
}

bool ContainerdRoleDiscoverer::connect()
{
    if (config_.socket_path.size() >= sizeof(sockaddr_un::sun_path)) {
        std::fprintf(stderr, "[role_containerd] socket 路径过长：%s\n",
                     config_.socket_path.c_str());
        return false;
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        report("创建 socket 失败");
        return false;
    }

    struct sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, config_.socket_path.c_str(),
                 sizeof(address.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&address),
                  sizeof(address)) < 0) {
        report("连接翻译进程失败（socket 未就绪）");
        ::close(fd);
        return false;
    }
    struct timeval timeout{};
    timeout.tv_sec = kReadTimeoutSec;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    fd_             = fd;
    session_opened_ = false;
    translator_.reset_segment();  // 上一会话可能在段中间断掉
    return true;
}

void ContainerdRoleDiscoverer::detach()
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    session_opened_ = false;
    segment_open_   = false;
}

void ContainerdRoleDiscoverer::backoff_wait(int& attempt)
{
    const std::int64_t shift = std::min(attempt, 16);
    const std::int64_t delay =
        std::min(static_cast<std::int64_t>(config_.backoff_base.count()) << shift,
                 static_cast<std::int64_t>(config_.backoff_max.count()));
    ++attempt;

    struct pollfd wakeup;
    wakeup.fd      = wakeup_fd_;
    wakeup.events  = POLLIN;
    wakeup.revents = 0;
    if (::poll(&wakeup, 1, static_cast<int>(delay)) > 0 && wakeup.revents != 0) {
        uint64_t token    = 0;
        const ssize_t got = ::read(wakeup_fd_, &token, sizeof(token));
        (void)got;  // 收到停止通知，下一轮循环即返回
    }
}

bool ContainerdRoleDiscoverer::read_exact(void* buffer, std::size_t length)
{
    std::size_t offset = 0;
    while (offset < length) {
        const ssize_t got =
            ::read(fd_, static_cast<char*>(buffer) + offset, length - offset);
        if (got > 0) {
            offset += static_cast<std::size_t>(got);
            continue;
        }
        if (got < 0 && errno == EINTR) {
            continue;
        }
        return false;  // 断开或读超时：帧已经不完整，连接不可用
    }
    return true;
}

bool ContainerdRoleDiscoverer::read_and_handle()
{
    unsigned char header[4] = {};
    if (!read_exact(header, sizeof(header))) {
        return false;
    }
    const uint32_t size = (static_cast<uint32_t>(header[0]) << 24) |
                          (static_cast<uint32_t>(header[1]) << 16) |
                          (static_cast<uint32_t>(header[2]) << 8) |
                          static_cast<uint32_t>(header[3]);
    if (size == 0 || size > kMaxFrameBytes) {
        std::fprintf(stderr, "[role_containerd] 帧长度非法：%u\n", size);
        return false;
    }

    std::string payload(size, '\0');
    if (!read_exact(payload.data(), payload.size())) {
        return false;
    }

    hng::role_bridge::Frame frame;
    if (!frame.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
        std::fprintf(stderr, "[role_containerd] 帧解析失败，连接不可信\n");
        return false;
    }

    ContainerdMessage message;
    if (!decode_frame(frame, message)) {
        // 不属于本协议的帧只记日志跳过：一条坏消息不得中断整条流
        std::fprintf(stderr, "[role_containerd] 忽略无法识别的帧\n");
        return true;
    }

    handle(message);
    return true;
}

void ContainerdRoleDiscoverer::handle(const ContainerdMessage& message)
{
    if (message.kind == ContainerdMessage::Kind::SNAPSHOT_BEGIN) {
        std::fprintf(stderr,
                     "[role_containerd] 快照段开场 来源=%s 后端=%s 范围=%zu 个\n",
                     message.source.c_str(), message.backend_version.c_str(),
                     message.namespaces.size());
    }
    execute(translator_.on_message(message));
}

void ContainerdRoleDiscoverer::execute(const ContainerTranslation& translation)
{
    pending_anchors_.store(translator_.pending_anchors());
    for (const std::string& violation : translation.violations) {
        ++anomalies_;
        std::fprintf(stderr, "[role_containerd] 协议违约：%s\n",
                     violation.c_str());
    }

    for (const ContainerCommand& command : translation.commands) {
        switch (command.kind) {
            case ContainerCommand::Kind::BEGIN_SNAPSHOT: {
                // 已有未结算的段又来开场：源侧作废了上一段。持续作废意味着
                // 对账其实没在跑，须可见
                if (segment_open_) {
                    ++voids_;
                    std::fprintf(stderr,
                                 "[role_containerd] "
                                 "上一段未结算即被作废，连续作废 %llu 次\n",
                                 static_cast<unsigned long long>(voids_.load()));
                }
                segment_open_   = true;
                session_opened_ = true;
                table_.begin_snapshot(command.scope);
                break;
            }
            case ContainerCommand::Kind::SUBMIT: {
                if (!session_opened_) {
                    ++anomalies_;
                    std::fprintf(
                        stderr,
                        "[role_containerd] 协议违约：会话未以快照段开场\n");
                    session_opened_ = true;  // 只报一次，不刷屏
                }
                if (std::optional<RoleEvent> event =
                        table_.submit(command.observation)) {
                    emit(*event);
                }
                break;
            }
            case ContainerCommand::Kind::END_SNAPSHOT: {
                const bool was_open = segment_open_;
                segment_open_       = false;

                if (!was_open) {
                    // 没有开场的收场：不该发生，且绝不能当成一次成功结算——那会
                    // 把「距上次成功结算的时长」这个唯一的健康度信号刷新掉
                    ++anomalies_;
                    std::fprintf(
                        stderr,
                        "[role_containerd] 协议违约：收场没有对应的开场\n");
                    break;
                }
                if (!command.settle) {
                    // 不完整的枚举不是权威状态，据它结算会误杀仍存活但没枚举
                    // 到的角色。退回「只喂不结算」，下次完整段自会修正
                    std::fprintf(
                        stderr, "[role_containerd] 段不可结算：实收 %u 声明 %u\n",
                        command.received_count, command.declared_count);
                    break;
                }
                for (const RoleEvent& event : table_.end_snapshot()) {
                    emit(event);
                }
                ++settlements_;
                last_settlement_ns_.store(now_ns());
                break;
            }
        }
    }
}

void ContainerdRoleDiscoverer::loop()
{
    int attempt = 0;
    while (!stop_requested_.load()) {
        if (fd_ < 0) {
            if (!connect()) {
                backoff_wait(attempt);
                continue;
            }
            attempt = 0;
            continue;
        }

        struct pollfd fds[2];
        fds[0].fd       = fd_;
        fds[0].events   = POLLIN;
        fds[0].revents  = 0;
        fds[1].fd       = wakeup_fd_;
        fds[1].events   = POLLIN;
        fds[1].revents  = 0;

        const int ready = ::poll(
            fds, 2, static_cast<int>(config_.anchor_retry_interval.count()));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            detach();
            continue;
        }

        if (fds[1].revents != 0) {
            uint64_t token    = 0;
            const ssize_t got = ::read(wakeup_fd_, &token, sizeof(token));
            (void)got;
        }
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            detach();
            continue;
        }
        if (fds[0].revents & POLLIN) {
            if (!read_and_handle()) {
                detach();
            }
            continue;
        }

        // 没有消息：重试待补锚点。只在空转时做，事件密集时不逐帧重试
        execute(translator_.retry_pending());
    }
}

}  // namespace role
}  // namespace hng

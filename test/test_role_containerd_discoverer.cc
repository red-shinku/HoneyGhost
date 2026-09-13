/**
 * @file test_role_containerd_discoverer.cc
 * @brief containerd 角色发现器的单元测试：协议解码、翻译层与 socket 接线
 * @details
 * 覆盖 agent/control_plane/role_discovery 的 role_containerd_discoverer：
 *  - 解码：真实生成物构造的帧 → 本地消息表示，空帧被拒；
 *  - 翻译层：快照段与流内观察产出的动作序列、类型键、属性、cgroup 补齐与过滤；
 *  - 待补锚点队列：段内失败计为已见并产出未知观察量、重试补齐、段末未被
 *    再见到的项被撤下；
 *  - 帧序违约：段内外标记不符、段内条目数与声明不符（后者不结算）；
 *  - 接线：假翻译进程经真实 Unix socket 送帧，断言产出的事件；断开后重连并
 *    以空快照对账，断言退出事件。
 *
 * @author red_shinku
 * @date 2026.9.13
 */

#include "agent/control_plane/role_discovery/include/role_containerd_discoverer.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "agent/control_plane/role_discovery/include/role_cgroup_reader.hpp"
#include "role_containerd_bridge.pb.h"

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

using hng::Process;
using hng::role::ContainerAttributes;
using hng::role::ContainerCommand;
using hng::role::ContainerdBridgeTranslator;
using hng::role::ContainerdMessage;
using hng::role::ContainerdObservation;
using hng::role::ContainerdRoleDiscoverer;
using hng::role::ContainerFilter;
using hng::role::ContainerProbe;
using hng::role::ContainerTranslation;
using hng::role::decode_frame;
using hng::role::ObservationKind;
using hng::role::RoleAction;
using hng::role::RoleEvent;
using hng::role::SettlementStats;

// ============================================================
// 帧构造：用真实生成物构造，测试样本与线上流同形
// ============================================================

hng::role_bridge::Frame make_begin(const std::vector<std::string>& namespaces)
{
    hng::role_bridge::Frame frame;
    hng::role_bridge::SnapshotBegin* begin = frame.mutable_snapshot_begin();
    begin->set_source("test-bridge");
    begin->set_backend_version("2.2.4");
    for (const std::string& name : namespaces) {
        begin->add_namespaces(name);
    }
    return frame;
}

hng::role_bridge::Frame make_upsert(const ContainerAttributes& attributes,
                                    uint32_t pid, bool in_snapshot)
{
    hng::role_bridge::Frame frame;
    hng::role_bridge::Observation* observation = frame.mutable_observation();
    observation->set_kind(hng::role_bridge::Observation::UPSERT);
    observation->set_in_snapshot(in_snapshot);
    observation->set_container_id(attributes.container_id);
    observation->set_pid(pid);
    observation->set_namespace_(attributes.container_namespace);
    observation->set_pod_uid(attributes.pod_uid);
    observation->set_pod_name(attributes.pod_name);
    observation->set_pod_namespace(attributes.pod_namespace);
    observation->set_container_name(attributes.container_name);
    observation->set_image(attributes.image);
    for (const auto& label : attributes.labels) {
        (*observation->mutable_labels())[label.first] = label.second;
    }
    return frame;
}

hng::role_bridge::Frame make_remove(const std::string& container_id)
{
    hng::role_bridge::Frame frame;
    hng::role_bridge::Observation* observation = frame.mutable_observation();
    observation->set_kind(hng::role_bridge::Observation::REMOVE);
    observation->set_container_id(container_id);
    return frame;
}

hng::role_bridge::Frame make_end(uint32_t count)
{
    hng::role_bridge::Frame frame;
    frame.mutable_snapshot_end()->set_count(count);
    return frame;
}

/// 解码一帧，失败即测试失败
ContainerdMessage decode_or_die(const hng::role_bridge::Frame& frame)
{
    ContainerdMessage message;
    if (!decode_frame(frame, message)) {
        ++g_fail;
        std::fprintf(stderr, "[FAIL] 帧应可解码\n");
    }
    return message;
}

/// 构造一条流内加入消息（翻译层测试用，不经 socket）
ContainerdMessage live_upsert(const ContainerAttributes& attributes, uint32_t pid)
{
    return decode_or_die(make_upsert(attributes, pid, false));
}

/// 一份 k8s 容器的属性：CRI 标签齐备
ContainerAttributes k8s_attributes(const std::string& id,
                                   const std::string& container_name)
{
    ContainerAttributes attributes;
    attributes.container_id        = id;
    attributes.container_namespace = "k8s.io";
    attributes.pod_uid             = "pod-uid-1";
    attributes.pod_name            = "nginx-7d9c";
    attributes.pod_namespace       = "prod";
    attributes.container_name      = container_name;
    attributes.image               = "registry.k8s.io/nginx:1.27";
    attributes.labels["io.kubernetes.container.name"] = container_name;
    attributes.labels["custom"]                       = "kept";
    return attributes;
}

// ============================================================
// 注入的 IO 替身
// ============================================================

/// 固定进程表与 cgroup 表的探针，锚点与成员都不依赖真实进程
struct FakeProbe {
    std::map<uint32_t, Process> processes;
    std::map<uint32_t, std::string> cgroups;
    std::map<std::string, std::vector<Process>> members;

    ContainerProbe probe()
    {
        ContainerProbe injected;
        injected.read_process = [this](uint32_t pid) -> std::optional<Process> {
            auto it = processes.find(pid);
            if (it == processes.end()) {
                return std::nullopt;
            }
            return it->second;
        };
        injected.read_cgroup_path = [this](uint32_t pid) {
            auto it = cgroups.find(pid);
            return it == cgroups.end() ? std::string() : it->second;
        };
        injected.read_members = [this](const std::string& path) {
            auto it = members.find(path);
            return it == members.end() ? std::vector<Process>{} : it->second;
        };
        return injected;
    }
};

// ============================================================
// 解码
// ============================================================

void run_decode()
{
    const ContainerdMessage begin = decode_or_die(make_begin({"k8s.io", "moby"}));
    CHECK(begin.kind == ContainerdMessage::Kind::SNAPSHOT_BEGIN, "应为段开场");
    CHECK(begin.source == "test-bridge" && begin.backend_version == "2.2.4",
          "后端标注应透传");
    CHECK(begin.namespaces.size() == 2 && begin.namespaces[1] == "moby",
          "段范围应透传");

    ContainerAttributes attributes = k8s_attributes("a1", "nginx");
    const ContainerdMessage upsert =
        decode_or_die(make_upsert(attributes, 4242, true));
    CHECK(upsert.kind == ContainerdMessage::Kind::OBSERVATION, "应为观察");
    CHECK(!upsert.observation.remove && upsert.observation.in_snapshot,
          "应为段内加入观察");
    CHECK(upsert.observation.pid == 4242, "锚点应透传");
    CHECK(upsert.observation.attributes.pod_name == "nginx-7d9c" &&
              upsert.observation.attributes.container_namespace == "k8s.io",
          "聚类字段与 namespace 应透传");
    CHECK(upsert.observation.attributes.labels.count("custom") == 1,
          "标签应原样透传");

    const ContainerdMessage remove = decode_or_die(make_remove("a1"));
    CHECK(remove.observation.remove, "应为退出观察");
    CHECK(remove.observation.attributes.container_id == "a1", "退出应带实例键");

    const ContainerdMessage end = decode_or_die(make_end(3));
    CHECK(end.kind == ContainerdMessage::Kind::SNAPSHOT_END &&
              end.declared_count == 3,
          "段收场应带条目数");

    // 空帧不属于本协议
    hng::role_bridge::Frame empty;
    ContainerdMessage ignored;
    CHECK(!decode_frame(empty, ignored), "空帧应被拒");

    // 未指定加入还是退出的观察无法判定，整帧丢弃
    hng::role_bridge::Frame unspecified;
    unspecified.mutable_observation()->set_container_id("a1");
    CHECK(!decode_frame(unspecified, ignored), "未指定类型的观察应被拒");
}

// ============================================================
// 翻译层：快照段、类型键、属性与 cgroup 补齐
// ============================================================

void run_translate_segment()
{
    FakeProbe fake;
    fake.processes[4242] = Process{4242, 999};
    fake.processes[7]    = Process{7, 111};
    fake.cgroups[4242]   = "/sys/fs/cgroup/kubepods/pod-uid-1/abc";
    fake.members["/sys/fs/cgroup/kubepods/pod-uid-1/abc"] = {Process{4242, 999},
                                                             Process{4243, 1}};

    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    const ContainerTranslation begin =
        translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    CHECK(begin.commands.size() == 1 &&
              begin.commands[0].kind == ContainerCommand::Kind::BEGIN_SNAPSHOT,
          "段开场应产出一个开段动作");
    CHECK(begin.commands[0].scope.size() == 1 &&
              begin.commands[0].scope[0] == "k8s.io",
          "开段应带本段范围");

    const ContainerTranslation upsert = translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a1", "nginx"), 4242, true)));
    CHECK(upsert.commands.size() == 1, "段内加入应产出一个动作");
    const hng::role::RoleObservation& observation =
        upsert.commands[0].observation;
    CHECK(observation.kind == ObservationKind::PRESENT, "应为进入观察");
    CHECK(observation.scope == "k8s.io", "观察量应带源内子范围");
    CHECK(observation.payload.identity.instance_key == "a1", "实例键应为容器 ID");
    CHECK(observation.payload.identity.type_key == "nginx",
          "k8s 容器类型键应取容器名");
    CHECK(observation.payload.main_process.pid == 4242 &&
              observation.payload.main_process.pid_start_time == 999,
          "锚点应由探针补齐");
    CHECK(observation.payload.cgroup_path ==
              "/sys/fs/cgroup/kubepods/pod-uid-1/abc",
          "cgroup 路径应补齐");
    CHECK(observation.payload.member_processes.size() == 2, "成员应补齐");
    const std::map<std::string, std::string>& attributes =
        observation.payload.identity.attributes;
    CHECK(attributes.at("pod_name") == "nginx-7d9c" &&
              attributes.at("image") == "registry.k8s.io/nginx:1.27",
          "协议字段应落进属性字典");
    CHECK(attributes.at("custom") == "kept", "标签应原样进属性字典");

    const ContainerTranslation end =
        translator.on_message(decode_or_die(make_end(1)));
    CHECK(end.commands.size() == 1 &&
              end.commands[0].kind == ContainerCommand::Kind::END_SNAPSHOT,
          "段收场应产出一个结算动作");
    CHECK(end.commands[0].settle && end.commands[0].received_count == 1,
          "条目数相符时应结算");

    // 流内加入：不标 in_snapshot，其余与段内一致
    const ContainerTranslation live = translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a2", "nginx"), 7, false)));
    CHECK(live.commands.size() == 1 &&
              live.commands[0].observation.kind == ObservationKind::PRESENT,
          "流内加入应产出进入观察");

    // 退出只带实例键，不回查也不补齐
    const ContainerTranslation gone =
        translator.on_message(decode_or_die(make_remove("a1")));
    CHECK(gone.commands.size() == 1 &&
              gone.commands[0].observation.kind == ObservationKind::ABSENT,
          "退出应产出离开观察");
    CHECK(gone.commands[0].observation.payload.identity.instance_key == "a1",
          "离开观察应带实例键");
}

/// 非 k8s 容器：类型键退化到镜像引用的最后一段
void run_type_key_degradation()
{
    FakeProbe fake;
    fake.processes[9] = Process{9, 1};
    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    ContainerAttributes attributes;
    attributes.container_id        = "d1";
    attributes.container_namespace = "moby";
    attributes.image               = "docker.io:5000/library/nginx:1.27";

    const ContainerTranslation out =
        translator.on_message(decode_or_die(make_upsert(attributes, 9, false)));
    CHECK(out.commands.size() == 1, "应产出进入观察");
    CHECK(out.commands[0].observation.payload.identity.type_key == "nginx",
          "类型键应退化到镜像最后一段（去掉 registry 与 tag）");

    // 镜像引用为空时退无可退，用实例键兜底
    attributes.image = "";
    const ContainerTranslation fallback =
        translator.on_message(decode_or_die(make_upsert(attributes, 9, false)));
    CHECK(fallback.commands.size() == 1 &&
              fallback.commands[0].observation.payload.identity.type_key == "d1",
          "无镜像时应用实例键兜底");
}

// ============================================================
// 翻译层：过滤
// ============================================================

void run_filter()
{
    FakeProbe fake;
    fake.processes[1] = Process{1, 1};

    ContainerFilter filter;
    filter.namespace_whitelist = {"k8s.io"};
    filter.exclude_pod_uids    = {"pod-uid-1"};
    ContainerdBridgeTranslator translator(filter, fake.probe());

    // namespace 不在白名单内
    ContainerAttributes other = k8s_attributes("b1", "nginx");
    other.container_namespace = "moby";
    CHECK(translator.on_message(live_upsert(other, 1)).commands.empty(),
          "白名单外的 namespace 不应产出动作");

    // agent 自身的 Pod
    ContainerAttributes self = k8s_attributes("c1", "agent");
    self.pod_uid             = "pod-uid-1";
    CHECK(translator.on_message(live_upsert(self, 1)).commands.empty(),
          "被排除的 Pod 不应产出动作");

    // 通过过滤的容器照常产出
    ContainerAttributes kept = k8s_attributes("d1", "nginx");
    kept.pod_uid             = "another-pod";
    CHECK(translator.on_message(live_upsert(kept, 1)).commands.size() == 1,
          "白名单内的容器应产出动作");
}

// ============================================================
// 翻译层：待补锚点队列
// ============================================================

void run_pending_anchors()
{
    FakeProbe fake;  // 进程表为空：锚点一律取不到
    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    const ContainerTranslation missing = translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a1", "nginx"), 4242, true)));

    // 段内取不到锚点：不得读成不存在，也不得静默丢弃——产出未知观察量，
    // 让该条目免于被本段对账清除
    CHECK(missing.commands.size() == 1 &&
              missing.commands[0].observation.kind == ObservationKind::UNKNOWN,
          "段内锚点取不到应产出未知观察量");
    CHECK(translator.pending_anchors() == 1, "取不到锚点应入队");
    CHECK(translator.on_message(decode_or_die(make_end(1))).commands.size() == 1,
          "段应照常收场（未知项计为本段已见）");
    CHECK(translator.pending_anchors() == 1, "本段又见到了它，队列应保留");

    // 补上了：下一轮重试产出进入观察量
    fake.processes[4242]               = Process{4242, 999};
    const ContainerTranslation retried = translator.retry_pending();
    CHECK(retried.commands.size() == 1 &&
              retried.commands[0].observation.kind == ObservationKind::PRESENT,
          "重试补齐后应产出进入观察量");
    CHECK(translator.pending_anchors() == 0, "补齐后应出队");

    // 段外取不到锚点：无处可依，只入队不产出观察量
    const ContainerTranslation live = translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a2", "nginx"), 555, false)));
    CHECK(live.commands.empty(), "段外取不到锚点不应产出观察量");
    CHECK(translator.pending_anchors() == 1, "段外取不到锚点应入队");

    // 容器退出：待补项随之撤下
    translator.on_message(decode_or_die(make_remove("a2")));
    CHECK(translator.pending_anchors() == 0, "退出应撤下待补项");
}

/// 段内不放行待补项：插在枚举项之间会破坏段内顺序，而本段的对账又会把它清掉
void run_pending_blocked_in_segment()
{
    FakeProbe fake;
    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a1", "nginx"), 4242, true)));
    CHECK(translator.pending_anchors() == 1, "锚点取不到应入队");

    fake.processes[4242] = Process{4242, 999};  // 锚点已可取
    CHECK(translator.retry_pending().commands.empty(), "段内不得放行待补项");
    CHECK(translator.pending_anchors() == 1, "段内不放行，项应留在队列里");

    translator.on_message(decode_or_die(make_end(1)));
    const ContainerTranslation retried = translator.retry_pending();
    CHECK(retried.commands.size() == 1 &&
              retried.commands[0].observation.kind == ObservationKind::PRESENT,
          "段外应放行补齐的项");
}

/// 下一个快照段没再见到的待补项：容器已不在运行，撤下
void run_pending_eviction()
{
    FakeProbe fake;
    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a1", "nginx"), 4242, true)));
    translator.on_message(decode_or_die(make_end(1)));
    CHECK(translator.pending_anchors() == 1, "锚点取不到应入队");

    // 下一个快照段覆盖同一范围，但没有它
    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    translator.on_message(decode_or_die(make_end(0)));
    CHECK(translator.pending_anchors() == 0, "本段未再见到的待补项应被撤下");

    // 范围不含它时不得撤下：本段没为那个 namespace 说话
    translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a2", "nginx"), 5, false)));
    CHECK(translator.pending_anchors() == 1, "段外入队");
    translator.on_message(decode_or_die(make_begin({"moby"})));
    translator.on_message(decode_or_die(make_end(0)));
    CHECK(translator.pending_anchors() == 1, "范围外的待补项不应被撤下");
}

// ============================================================
// 翻译层：帧序违约
// ============================================================

void run_violations()
{
    FakeProbe fake;
    fake.processes[1] = Process{1, 1};
    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    // 段外出现枚举项
    ContainerTranslation out = translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a1", "nginx"), 1, true)));
    CHECK(out.violations.size() == 1, "段外出现枚举项应记为违约");

    // 段内出现流内项：这正是段内缓冲失效的形态
    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    out = translator.on_message(live_upsert(k8s_attributes("a1", "nginx"), 1));
    CHECK(out.violations.size() == 1, "段内出现流内项应记为违约");
    CHECK(translator.on_message(decode_or_die(make_end(0))).commands.size() == 1,
          "段应照常收场");
}

/// 段内条目数与源侧声明不符：不完整的枚举不是权威状态，不可据它结算
void run_count_mismatch()
{
    FakeProbe fake;  // 无进程：锚点取不到，条目进待补队列
    ContainerdBridgeTranslator translator(ContainerFilter{}, fake.probe());

    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    translator.on_message(
        decode_or_die(make_upsert(k8s_attributes("a1", "nginx"), 4242, true)));
    translator.on_message(decode_or_die(make_end(1)));
    CHECK(translator.pending_anchors() == 1, "锚点取不到应入队");

    // 下一段：声明 3 条却只收到 0 条
    translator.on_message(decode_or_die(make_begin({"k8s.io"})));
    const ContainerTranslation out =
        translator.on_message(decode_or_die(make_end(3)));
    CHECK(out.commands.size() == 1 && !out.commands[0].settle,
          "条目数不符时不应结算");
    CHECK(out.violations.size() == 1, "条目数不符应记为违约");
    CHECK(out.commands[0].received_count == 0 &&
              out.commands[0].declared_count == 3,
          "应报出实收与声明");
    // 不可信的段不得动待补队列：它没为这些条目说过话
    CHECK(translator.pending_anchors() == 1, "不结算的段不得撤下待补项");
}

// ============================================================
// 接线：假翻译进程经真实 Unix socket 送帧
// ============================================================

/// 临时目录，析构时递归删除
class TempDir {
   public:
    TempDir()
    {
        std::string tmpl =
            (std::filesystem::temp_directory_path() / "hng_role_bridge_XXXXXX")
                .string();
        std::vector<char> buffer(tmpl.begin(), tmpl.end());
        buffer.push_back('\0');
        if (const char* made = ::mkdtemp(buffer.data())) {
            path_ = made;
        }
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    TempDir(const TempDir&)            = delete;
    TempDir& operator=(const TempDir&) = delete;
    const std::filesystem::path& path() const { return path_; }

   private:
    std::filesystem::path path_;
};

/// 扮演翻译进程：监听 socket，等发现器连上后按需送帧
class FakeBridge {
   public:
    explicit FakeBridge(const std::filesystem::path& socket_path)
    {
        listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listen_fd_ < 0) {
            return;
        }
        struct sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, socket_path.c_str(),
                     sizeof(address.sun_path) - 1);
        if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&address),
                   sizeof(address)) < 0 ||
            ::listen(listen_fd_, 4) < 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
    }
    ~FakeBridge()
    {
        close_connection();
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
        }
    }

    /// 等发现器连上；超时返回 false
    bool accept_one(int timeout_ms = 3000)
    {
        if (listen_fd_ < 0) {
            return false;
        }
        struct pollfd fd;
        fd.fd      = listen_fd_;
        fd.events  = POLLIN;
        fd.revents = 0;
        if (::poll(&fd, 1, timeout_ms) <= 0) {
            return false;
        }
        connection_fd_ = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (connection_fd_ >= 0) {
            struct timeval timeout{};
            timeout.tv_sec = 2;
            ::setsockopt(connection_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         sizeof(timeout));
        }
        return connection_fd_ >= 0;
    }

    /// 断开当前连接，等着发现器重连
    void close_connection()
    {
        if (connection_fd_ >= 0) {
            ::close(connection_fd_);
            connection_fd_ = -1;
        }
    }

    bool send(const hng::role_bridge::Frame& frame)
    {
        if (connection_fd_ < 0) {
            return false;
        }
        std::string payload;
        if (!frame.SerializeToString(&payload)) {
            return false;
        }
        const uint32_t size           = static_cast<uint32_t>(payload.size());
        const unsigned char header[4] = {
            static_cast<unsigned char>((size >> 24) & 0xff),
            static_cast<unsigned char>((size >> 16) & 0xff),
            static_cast<unsigned char>((size >> 8) & 0xff),
            static_cast<unsigned char>(size & 0xff)};
        if (write_all(header, sizeof(header)) &&
            write_all(payload.data(), payload.size())) {
            return true;
        }
        return false;
    }

   private:
    bool write_all(const void* buffer, std::size_t length)
    {
        std::size_t offset = 0;
        while (offset < length) {
            const ssize_t written =
                ::write(connection_fd_, static_cast<const char*>(buffer) + offset,
                        length - offset);
            if (written > 0) {
                offset += static_cast<std::size_t>(written);
                continue;
            }
            if (written < 0 && errno == EINTR) {
                continue;
            }
            return false;
        }
        return true;
    }

    int listen_fd_     = -1;
    int connection_fd_ = -1;
};

/// 收集事件的出口
class EventSink {
   public:
    void operator()(const RoleEvent& event)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event.action);
        keys_.push_back(event.payload.identity.instance_key);
        pids_.push_back(event.payload.main_process.pid);
    }

    /// 等到至少 n 个事件；超时返回此刻已收集到的
    std::size_t wait_for(std::size_t n, int timeout_ms = 3000)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (events_.size() >= n) {
                    return events_.size();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        std::lock_guard<std::mutex> lock(mutex_);
        return events_.size();
    }

    std::vector<RoleAction> actions()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }
    std::vector<std::string> keys()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return keys_;
    }
    std::vector<uint32_t> pids()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return pids_;
    }

   private:
    std::mutex mutex_;
    std::vector<RoleAction> events_;
    std::vector<std::string> keys_;
    std::vector<uint32_t> pids_;
};

/// 端到端：真实 socket 上的快照段、流内事件、断连重连与对账
void run_wiring()
{
    TempDir tmp;
    const std::string socket_path = (tmp.path() / "bridge.sock").string();
    FakeBridge bridge(socket_path);

    FakeProbe fake;
    fake.processes[4242] = Process{4242, 999};
    fake.processes[7]    = Process{7, 111};

    EventSink sink;
    ContainerdRoleDiscoverer::Config config;
    config.socket_path           = socket_path;
    config.probe                 = fake.probe();
    config.on_event              = std::ref(sink);
    config.anchor_retry_interval = std::chrono::milliseconds(20);
    config.backoff_base          = std::chrono::milliseconds(10);
    config.backoff_max           = std::chrono::milliseconds(50);

    ContainerdRoleDiscoverer discoverer(config);
    std::thread runner([&discoverer] { discoverer.run(); });

    // ① 一次完整快照段：a 加入
    CHECK(bridge.accept_one(), "发现器应连上");
    bridge.send(make_begin({"k8s.io"}));
    bridge.send(make_upsert(k8s_attributes("a1", "nginx"), 4242, true));
    bridge.send(make_end(1));
    CHECK(sink.wait_for(1) == 1, "快照段应产出加入事件");
    CHECK(sink.actions()[0] == RoleAction::JOIN, "应为加入");
    CHECK(sink.keys()[0] == "a1" && sink.pids()[0] == 4242,
          "应为 a1 且锚点 4242");

    // ② 流内事件：同一容器重复观察不产出，另一个容器加入产出
    bridge.send(make_upsert(k8s_attributes("a1", "nginx"), 4242, false));
    bridge.send(make_upsert(k8s_attributes("a2", "nginx"), 7, false));
    CHECK(sink.wait_for(2) == 2, "流内加入应产出事件");
    CHECK(sink.keys()[1] == "a2", "第二个事件应为 a2");

    // ③ 断开重连：新会话以空快照对账，a1 与 a2 各产出一个退出
    bridge.close_connection();
    CHECK(bridge.accept_one(), "发现器应重连");
    bridge.send(make_begin({"k8s.io"}));
    bridge.send(make_end(0));
    CHECK(sink.wait_for(4) == 4, "重连后的空快照应对账出两个退出");
    const std::vector<RoleAction> actions = sink.actions();
    CHECK(actions[2] == RoleAction::LEAVE && actions[3] == RoleAction::LEAVE,
          "对账应产出退出，且按实例键升序");
    CHECK(sink.keys()[2] == "a1" && sink.keys()[3] == "a2", "退出顺序应确定");

    // ④ 未结算的段不产出退出：新会话只开段不收场，表内的存活项保持
    bridge.send(make_upsert(k8s_attributes("a3", "nginx"), 7, false));
    CHECK(sink.wait_for(5) == 5, "a3 加入应产出事件");
    bridge.send(make_begin({"k8s.io"}));
    bridge.send(make_upsert(k8s_attributes("a3", "nginx"), 7, true));
    // 不发 SnapshotEnd，直接断连
    bridge.close_connection();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(sink.wait_for(5) == 5, "未走完的段不得产出退出");

    const SettlementStats stats = discoverer.settlement_stats();
    CHECK(stats.settlements >= 2, "应记下成功结算的段数");

    // ⑤ 没有开场的收场：记为违约，且不得刷新「距上次成功结算的时长」
    CHECK(bridge.accept_one(), "发现器应重连");
    bridge.send(make_end(0));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const SettlementStats after = discoverer.settlement_stats();
    CHECK(after.settlements == stats.settlements, "无开场的收场不得记为结算");
    CHECK(after.anomalies > stats.anomalies, "无开场的收场应记为违约");

    discoverer.stop();
    runner.join();
}

/// 翻译进程未起：退避重试期间不产出事件，stop() 仍能打断
void run_backoff()
{
    TempDir tmp;
    ContainerdRoleDiscoverer::Config config;
    config.socket_path  = (tmp.path() / "absent.sock").string();
    config.backoff_base = std::chrono::milliseconds(10);
    config.backoff_max  = std::chrono::milliseconds(20);

    EventSink sink;
    config.on_event = std::ref(sink);

    ContainerdRoleDiscoverer discoverer(config);
    std::thread runner([&discoverer] { discoverer.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    discoverer.stop();
    runner.join();

    CHECK(sink.actions().empty(), "源不可用期间不应产出事件");
    CHECK(discoverer.settlement_stats().settlements == 0, "不应有结算");
}

}  // namespace

int main()
{
    run_decode();
    run_translate_segment();
    run_type_key_degradation();
    run_filter();
    run_pending_anchors();
    run_pending_blocked_in_segment();
    run_pending_eviction();
    run_violations();
    run_count_mismatch();
    run_wiring();
    run_backoff();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (containerd discoverer)\n");
    return 0;
}

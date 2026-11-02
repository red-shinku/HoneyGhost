/**
 * @file
 * @brief 配置边界、标签策略、成员刷新、重试及消费线程的单元测试。
 * @author inless427
 */
#include "agent/role_filter/src/role_filter.hpp"
#include "agent/role_filter/src/role_filter_state.hpp"
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace {
using namespace hng;
int checks = 0;
void require(bool condition, const char* message)
{
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
template <class Action>
void rejects(Action action, const char* fragment)
{
    try {
        action();
    }
    catch (const std::exception& error) {
        require(std::string(error.what()).find(fragment) != std::string::npos,
                "错误消息应保留定位信息");
        return;
    }
    require(false, "应拒绝非法输入");
}
RoleFilterPolicy policy(const std::string& input)
{
    std::istringstream stream(input);
    return RoleFilterPolicy(parse_role_filter_config(stream, "test.conf"));
}

class Lookup final : public RoleLookupService {
   public:
    mutable std::mutex mutex;
    std::unordered_map<uint32_t, Role> role_map;
    std::unordered_map<uint32_t, std::vector<Process>> processes;
    std::unordered_map<uint32_t, Process> anchors;
    std::unordered_map<Process, uint32_t> owners;
    bool fail         = false;
    mutable int reads = 0;
    void set(Role role, std::vector<Process> members)
    {
        std::lock_guard lock(mutex);
        role_map[role.roleID]  = role;
        processes[role.roleID] = std::move(members);
    }
    std::optional<uint32_t> lookup(Process process) const override
    {
        std::lock_guard lock(mutex);
        auto it = owners.find(process);
        return it == owners.end() ? std::nullopt
                                  : std::optional<uint32_t>(it->second);
    }
    std::optional<Role> role(uint32_t id) const override
    {
        std::lock_guard lock(mutex);
        auto it = role_map.find(id);
        return it == role_map.end() ? std::nullopt
                                    : std::optional<Role>(it->second);
    }
    std::optional<hng::role::RoleIdentity> identity(uint32_t) const override
    {
        return {};
    }
    std::vector<Role> roles() const override
    {
        std::lock_guard lock(mutex);
        std::vector<Role> result;
        result.reserve(role_map.size());
        for (const auto& [id, role] : role_map) result.push_back(role);
        return result;
    }
    std::vector<Role> supervised_roles() const override { return {}; }
    std::optional<Process> main_process(uint32_t id) const override
    {
        std::lock_guard lock(mutex);
        auto it = anchors.find(id);
        return it == anchors.end() ? std::nullopt
                                   : std::optional<Process>(it->second);
    }
    RoleManagerStats stats() const override { return {}; }
    std::vector<Process> members(uint32_t id) const override
    {
        std::lock_guard lock(mutex);
        ++reads;
        if (fail) throw std::runtime_error("枚举暂时失败");
        auto it = processes.find(id);
        return it == processes.end() ? std::vector<Process>{} : it->second;
    }
};
class Supervision final : public ::RoleSupervisionService {
   public:
    void set_supervised(uint32_t roleID, bool supervised) override
    {
        std::lock_guard lock(mutex);
        states[roleID] = supervised;
    }
    bool is_supervised(uint32_t roleID) const
    {
        std::lock_guard lock(mutex);
        auto it = states.find(roleID);
        return it != states.end() && it->second;
    }

   private:
    mutable std::mutex mutex;
    std::unordered_map<uint32_t, bool> states;
};
class Map final : public ProcessFilterMap {
   public:
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::unordered_set<Process> values;
    int allow_calls = 0, erase_calls = 0, fail_allow = 0, fail_erase = 0;
    bool partial = false;
    std::error_code allow(Process process) noexcept override
    {
        std::lock_guard lock(mutex);
        ++allow_calls;
        if (fail_allow) {
            --fail_allow;
            if (partial) values.insert(process);
            return std::make_error_code(std::errc::no_buffer_space);
        }
        values.insert(process);
        cv.notify_all();
        return {};
    }
    std::error_code erase(Process process) noexcept override
    {
        std::lock_guard lock(mutex);
        ++erase_calls;
        if (fail_erase) {
            --fail_erase;
            return std::make_error_code(std::errc::io_error);
        }
        values.erase(process);
        return {};
    }
    bool contains(Process process) const
    {
        std::lock_guard lock(mutex);
        return values.count(process);
    }
    bool wait(Process process)
    {
        std::unique_lock lock(mutex);
        return cv.wait_for(lock, std::chrono::seconds(2),
                           [&] { return values.count(process); });
    }
};
struct Fixture {
    Lookup lookup;
    Map* map;
    Supervision supervision;
    std::unique_ptr<RoleFilter> filter;
    Fixture()
    {
        auto backend = std::make_unique<Map>();
        map          = backend.get();
        RoleFilterOptions options;
        options.refresh_interval = std::chrono::milliseconds(10);
        options.liveness         = [](Process) { return ProcessLiveness::ALIVE; };
        filter                   = std::make_unique<RoleFilter>(
            lookup, policy("[whitelist]\nexact: nginx.service\n"),
            std::move(backend), options);
        filter->set_supervision_service(&supervision);
    }
    void joined(Role role, std::vector<Process> members)
    {
        lookup.set(role, std::move(members));
        filter->on_role_joined(role);
        filter->drain();
    }
};

void configuration()
{
    require(!RoleFilterPolicy().should_collect("nginx.service"), "默认拒绝");
    auto rules = policy(
        "# 注释\r\n[whitelist]\r\nexact: nginx.service\r\nregex: "
        "registry/app:v1\\..*\n"
        "exact: image#tag:v2\n[blacklist]\nexact: registry/app:v1.debug\n");
    require(rules.should_collect("nginx.service"), "unit 精确匹配");
    require(!rules.should_collect("NGINX.service"), "精确匹配区分大小写");
    require(!rules.should_collect("prefix/nginx.service"),
            "精确匹配不能匹配子串");
    require(rules.should_collect("registry/app:v1.2"), "镜像引用正则匹配");
    require(!rules.should_collect("prefix/registry/app:v1.2"),
            "正则匹配整个标签");
    require(!rules.should_collect("registry/app:v1.debug"), "黑名单优先");
    require(rules.should_collect("image#tag:v2"), "保留冒号和井号");
    require(!rules.should_collect(""), "空标签拒绝");
    require(!policy("[blacklist]\nregex: .*\n").should_collect("x"),
            "只有黑名单仍默认拒绝");
    for (const auto& input :
         {"exact: x\n", "[unknown]\n", "[whitelist]\n[whitelist]\n",
          "[blacklist]\n[blacklist]\n", "[whitelist]\nunknown: x\n",
          "[whitelist]\nexact:\n", "[whitelist]\nregex: [\n"})
        rejects([&] { policy(input); }, "test.conf:");
    rejects([&] { policy("[whitelist]\nexact: " + std::string(4097, 'a')); },
            "4096");
    rejects([&] { policy(std::string(8193, 'a')); }, "8192");
    rejects([&] { policy(std::string(1024 * 1024 + 1, '\n')); }, "1 MiB");
    std::string many = "[whitelist]\n";
    for (int i = 0; i < 4097; ++i) many += "exact: x\n";
    rejects([&] { policy(many); }, "规则数");
    rejects([&] { policy(std::string("[whitelist]\nexact: a\0b", 22)); }, "NUL");
    rejects([&] { policy("[whitelist]\nregex: [\n"); }, "test.conf:2:");
    rejects(
        [&] {
            RoleFilterPolicy invalid(
                RoleFilterConfig{{{static_cast<LabelMatch>(100), "x"}}, {}});
        },
        "类型");
    rejects([&] { load_role_filter_config("/nonexistent-hng-role-filter.conf"); },
            "无法打开");
    auto loaded = load_role_filter_config("config/role_filter.conf");
    require(RoleFilterPolicy(loaded).should_collect("nginx.service"),
            "文件入口加载样例");
    std::istringstream broken("[whitelist]");
    broken.setstate(std::ios::badbit);
    rejects([&] { parse_role_filter_config(broken, "broken"); }, "读取失败");
}

void maintenance()
{
    const Process first{101, 200}, child{102, 201};
    Fixture fixture;
    fixture.joined({1, "nginx.service"}, {first, first, {0, 0}});
    require(fixture.map->contains(first), "加入后允许进程");
    require(fixture.map->allow_calls == 1, "重复成员去重");
    require(fixture.supervision.is_supervised(1), "关注角色应登记监管");
    fixture.filter->on_role_joined({1, "nginx.service"});
    fixture.filter->drain();
    require(fixture.map->allow_calls == 1, "重复通知幂等");
    fixture.joined({2, "ignored.service"}, {child});
    require(fixture.filter->stats().roles == 2, "未关注的角色也保留记录");
    require(!fixture.map->contains(child), "未关注角色不入 map");
    require(!fixture.supervision.is_supervised(2), "未关注角色不登记监管");
    fixture.lookup.set({1, "nginx.service"}, {});
    fixture.filter->drain();
    require(fixture.map->contains(first), "空枚举不能误判进程离开");
    require(fixture.filter->stats().empty_members > 0, "空枚举可观测");
    fixture.lookup.set({1, "nginx.service"}, {child});
    fixture.filter->drain();
    require(fixture.map->contains(first) && fixture.map->contains(child),
            "部分枚举保留旧成员并补齐 fork");
    fixture.lookup.fail = true;
    fixture.filter->drain();
    fixture.lookup.fail = false;
    require(fixture.map->contains(first), "枚举异常不杀死消费逻辑");
    require(fixture.filter->stats().lookup_errors > 0, "查询异常可观测");
    fixture.lookup.role_map[1].roleLabel = "ignored.service";
    fixture.filter->on_role_main_process_changed({1, "ignored.service"});
    fixture.filter->drain();
    require(!fixture.map->contains(first) && !fixture.map->contains(child),
            "标签变化撤销成员");
    require(!fixture.supervision.is_supervised(1), "标签变化撤销监管");
    fixture.lookup.set({1, "nginx.service"}, {first});
    fixture.filter->request_refresh();
    fixture.filter->drain();
    require(fixture.map->contains(first), "显式刷新使用权威标签");
    require(fixture.supervision.is_supervised(1), "恢复关注后重新登记监管");
    rejects(
        [&] {
            auto invalid = policy("[whitelist]\nregex: [\n");
            fixture.filter->replace_policy(invalid);
        },
        "非法正则");
    require(fixture.map->contains(first), "配置构造失败不影响旧策略");
    fixture.map->fail_erase = 1;
    fixture.filter->replace_policy(RoleFilterPolicy());
    fixture.filter->drain();
    require(fixture.map->contains(first), "删除失败保留待重试项");
    require(!fixture.supervision.is_supervised(1), "策略清空应撤销监管");
    fixture.filter->drain();
    require(!fixture.map->contains(first), "删除失败后重试");
    fixture.filter->replace_policy(policy("[whitelist]\nexact: nginx.service\n"));
    fixture.filter->drain();
    require(fixture.map->contains(first), "策略替换可重新允许");
    require(fixture.supervision.is_supervised(1), "策略恢复应重新登记监管");
    fixture.lookup.owners[first] = 2;
    fixture.filter->drain();
    require(!fixture.map->contains(first), "权威归属变化撤销旧角色许可");
    fixture.lookup.owners.erase(first);
    fixture.filter->drain();
    fixture.filter->on_role_left({1, "nginx.service"});
    fixture.filter->drain();
    require(!fixture.map->contains(first), "退出按缓存撤销许可");
    require(!fixture.supervision.is_supervised(1), "角色退出应撤销监管");
    require(fixture.lookup.role_map.count(1), "维护器不删除 RoleManager 的角色");
    Fixture partial;
    partial.map->fail_allow = 1;
    partial.map->partial    = true;
    partial.joined({1, "nginx.service"}, {first});
    require(partial.map->contains(first) &&
                partial.filter->stats().applied_processes == 0,
            "部分写入错误保持不确定状态");
    partial.filter->replace_policy(RoleFilterPolicy());
    partial.filter->drain();
    require(!partial.map->contains(first), "策略变更不能遗漏部分成功的写入");
    Fixture retry;
    retry.map->fail_allow = 1;
    retry.joined({1, "nginx.service"}, {first});
    retry.filter->drain();
    require(retry.map->contains(first) && retry.filter->stats().map_errors == 1,
            "写入错误重试");
    require(retry.filter->stats().last_map_error != 0, "保留最近 map 错误");
    retry.lookup.role_map.clear();
    retry.filter->drain();
    require(!retry.map->contains(first) && retry.filter->stats().roles == 0,
            "排队后角色已退出");
    require(!retry.supervision.is_supervised(1), "角色从权威源消失应撤销监管");
    retry.filter->stop();
    retry.filter->request_refresh();
    require(retry.filter->stats().queue_rejected == 1, "停止后拒绝新任务");
    rejects(
        [&] { RoleFilter invalid(retry.lookup, RoleFilterPolicy(), nullptr); },
        "不可为空");
    RoleFilterOptions bad;
    bad.refresh_interval = std::chrono::milliseconds(0);
    rejects(
        [&] {
            RoleFilter invalid(retry.lookup, RoleFilterPolicy(),
                               std::make_unique<Map>(), bad);
        },
        "必须为正");
}

void initial_roles()
{
    const Process first{501, 1500}, ignored{502, 1501}, anchor{503, 1502};
    {
        Fixture fixture;
        fixture.lookup.set({1, "nginx.service"}, {first});
        fixture.lookup.set({2, "ignored.service"}, {ignored});
        require(fixture.filter->state() == ComponentState::CONSTRUCTED,
                "构造后状态应为 CONSTRUCTED");
        require(!fixture.filter->ready(), "未 seed 不应就绪");
        fixture.filter->run();
        require(fixture.filter->state() == ComponentState::CONSTRUCTED,
                "未 seed 的 run 立即返回且不改状态");
        fixture.filter->stop();
        require(fixture.filter->state() == ComponentState::STOPPED,
                "未运行时 stop 直接置 STOPPED");
    }
    {
        Fixture fixture;
        fixture.lookup.set({1, "nginx.service"}, {first});
        fixture.lookup.set({2, "ignored.service"}, {ignored});
        fixture.filter->seed_initial_roles();
        require(fixture.filter->state() == ComponentState::READY,
                "seed 后状态应为 READY");
        require(fixture.filter->ready(), "seed 后应就绪");
        require(fixture.map->contains(first), "seed 只写入策略命中的成员");
        require(!fixture.map->contains(ignored), "seed 不写入未命中策略的角色");
        require(fixture.filter->stats().roles == 2, "seed 应记录当前角色全集");
        const int allows = fixture.map->allow_calls;
        fixture.filter->seed_initial_roles();
        require(fixture.map->allow_calls == allows, "重复 seed 为空操作");
        require(fixture.filter->state() == ComponentState::READY,
                "重复 seed 不改变状态");
    }
    {
        Fixture fixture;
        fixture.lookup.set({3, "nginx.service"}, {});
        fixture.lookup.anchors[3] = anchor;
        fixture.filter->seed_initial_roles();
        require(fixture.map->contains(anchor), "members() 为空时仍应写入锚点");
        require(fixture.filter->stats().empty_members > 0, "空成员枚举应可观测");
    }
    {
        const Process dead{504, 1503};
        Lookup lookup;
        lookup.set({4, "nginx.service"}, {first, dead});
        auto backend = std::make_unique<Map>();
        Map* map     = backend.get();
        RoleFilterOptions options;
        options.liveness = [&](Process process) {
            return process == dead ? ProcessLiveness::DEAD
                                   : ProcessLiveness::ALIVE;
        };
        RoleFilter filter(lookup, policy("[whitelist]\nexact: nginx.service\n"),
                          std::move(backend), options);
        filter.seed_initial_roles();
        require(map->contains(first) && !map->contains(dead),
                "seed 应经存活核对移除死成员");
    }
    {
        Lookup lookup;
        lookup.set({5, "nginx.service"}, {first});
        auto backend    = std::make_unique<Map>();
        Map* map        = backend.get();
        map->fail_allow = 1;
        RoleFilterOptions options;
        options.liveness = [](Process) { return ProcessLiveness::ALIVE; };
        RoleFilter filter(lookup, policy("[whitelist]\nexact: nginx.service\n"),
                          std::move(backend), options);
        filter.seed_initial_roles();
        require(filter.state() == ComponentState::READY,
                "map 写入失败不阻止 READY");
        require(filter.stats().map_errors == 1 &&
                    filter.stats().applied_processes == 0,
                "map 写入失败应保留不确定状态");
        require(!map->contains(first), "失败时未写入 map");
        filter.request_refresh();
        filter.drain();
        require(map->contains(first), "清掉失败后刷新应补写");
        require(filter.state() == ComponentState::READY, "补写后状态不变");
    }
}

void periodic()
{
    Fixture fixture;
    const Process first{201, 1000}, child{202, 1001};
    fixture.lookup.set({1, "nginx.service"}, {first});
    fixture.filter->on_role_joined({1, "nginx.service"});
    fixture.filter->seed_initial_roles();
    struct Runner {
        RoleFilter& filter;
        std::thread thread;
        explicit Runner(RoleFilter& value)
            : filter(value), thread([&value] { value.run(); })
        {
        }
        ~Runner()
        {
            filter.stop();
            thread.join();
        }
    } runner(*fixture.filter);
    require(fixture.map->wait(first), "消费线程处理初始任务");
    fixture.lookup.set({1, "nginx.service"}, {first, child});
    require(fixture.map->wait(child), "无新角色通知也定时补齐成员");
}

void member_notifications()
{
    const Process first{301, 1300}, child{302, 1301}, orphan{303, 1302};
    Fixture fixture;
    fixture.joined({1, "nginx.service"}, {first});
    require(fixture.map->contains(first), "加入后允许成员");
    require(fixture.map->allow_calls == 1, "加入只写一次");

    // 权威枚举仍只返回旧成员：新增项只能来自通知载荷
    fixture.filter->on_role_members_changed({1, "nginx.service"}, {child});
    fixture.filter->drain();
    require(fixture.map->contains(child), "成员通知应即时允许新增进程");

    fixture.filter->on_role_members_changed({99, "nginx.service"}, {orphan});
    fixture.filter->drain();
    require(!fixture.map->contains(orphan), "未跟踪角色的成员通知应忽略");

    fixture.joined({2, "ignored.service"}, {});
    fixture.filter->on_role_members_changed({2, "ignored.service"}, {orphan});
    fixture.filter->drain();
    require(!fixture.map->contains(orphan), "未关注角色的成员通知应忽略");

    fixture.filter->on_role_members_changed({1, "nginx.service"}, {{0, 0}});
    fixture.filter->drain();
    require(fixture.map->allow_calls == 2, "空身份不应写入 map");
}

void member_prompt()
{
    const Process first{401, 1400}, child{402, 1401};
    Lookup lookup;
    lookup.set({1, "nginx.service"}, {first});
    auto backend = std::make_unique<Map>();
    Map* map     = backend.get();
    RoleFilterOptions options;
    options.refresh_interval = std::chrono::hours(1);
    options.liveness         = [](Process) { return ProcessLiveness::ALIVE; };
    RoleFilter filter(lookup, policy("[whitelist]\nexact: nginx.service\n"),
                      std::move(backend), options);
    filter.seed_initial_roles();
    struct Runner {
        RoleFilter& filter;
        std::thread thread;
        explicit Runner(RoleFilter& value)
            : filter(value), thread([&value] { value.run(); })
        {
        }
        ~Runner()
        {
            filter.stop();
            thread.join();
        }
    } runner(filter);
    filter.on_role_joined({1, "nginx.service"});
    require(map->wait(first), "消费线程应处理加入");
    // 周期刷新远未到点：名单更新只能由成员通知触发
    filter.on_role_members_changed({1, "nginx.service"}, {child});
    require(map->wait(child), "成员通知应即时更新名单，不必等周期刷新");
}

void liveness()
{
    const auto parent =
        std::filesystem::current_path() / "build-agent/role-filter";
    std::filesystem::create_directories(parent);
    std::string pattern = (parent / "proc-XXXXXX").string();
    char* directory     = mkdtemp(pattern.data());
    if (!directory) throw std::runtime_error("创建测试目录失败");
    const std::filesystem::path root(directory);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup()
        {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    } cleanup{root};
    std::filesystem::create_directory(root / "123");
    auto write = [&](const std::string& content) {
        std::ofstream file(root / "123/stat");
        file << content;
    };
    std::string stat = "123 (name ) with spaces) S";
    for (int field = 4; field < 22; ++field) stat += " 0";
    write(stat + " 42\n");
    require(
        detail::proc_liveness({123, 42}, root.string()) == ProcessLiveness::ALIVE,
        "procfs 支持 comm 中的括号和空格");
    require(
        detail::proc_liveness({123, 43}, root.string()) == ProcessLiveness::DEAD,
        "检测 PID 复用");
    require(
        detail::proc_liveness({124, 42}, root.string()) == ProcessLiveness::DEAD,
        "检测进程退出");
    write("malformed");
    require(detail::proc_liveness({123, 42}, root.string()) ==
                ProcessLiveness::UNKNOWN,
            "损坏 stat 保守返回未知");
    write(stat + " invalid\n");
    require(detail::proc_liveness({123, 42}, root.string()) ==
                ProcessLiveness::UNKNOWN,
            "启动时间非法返回未知");
    write(std::string(16385, 'x'));
    require(detail::proc_liveness({123, 42}, root.string()) ==
                ProcessLiveness::UNKNOWN,
            "procfs 读取有界");
    Lookup lookup;
    auto map              = std::make_unique<Map>();
    auto* view            = map.get();
    ProcessLiveness state = ProcessLiveness::ALIVE;
    RoleFilterOptions options;
    options.liveness = [&](Process) { return state; };
    RoleFilter filter(lookup, policy("[whitelist]\nexact: nginx.service\n"),
                      std::move(map), options);
    lookup.set({1, "nginx.service"}, {{123, 42}});
    filter.on_role_joined({1, "nginx.service"});
    filter.drain();
    state = ProcessLiveness::UNKNOWN;
    filter.drain();
    require(view->contains({123, 42}), "未知状态保留许可");
    state = ProcessLiveness::DEAD;
    filter.drain();
    require(!view->contains({123, 42}), "明确退出撤销许可");
}
}  // namespace
int main()
{
    try {
        configuration();
        maintenance();
        initial_roles();
        periodic();
        member_notifications();
        member_prompt();
        liveness();
        std::printf("PASS: role_filter, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}

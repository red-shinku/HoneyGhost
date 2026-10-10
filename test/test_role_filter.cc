#include "agent/role_filter/include/role_filter.hpp"
#include "agent/role_filter/src/role_filter_state.hpp"

#include <atomic>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unistd.h>

namespace {
int checks = 0;
#define CHECK(condition) do { ++checks; if (!(condition)) throw std::runtime_error( \
    std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": " #condition); } while (0)

template<class F> void throws(F&& f)
{
    bool caught = false;
    try { f(); } catch (const std::exception&) { caught = true; }
    CHECK(caught);
}

using namespace hng;
using hng::detail::ProcessSet;
const Process p1{100, 1000}, p2{101, 1001}, reused{100, 2000};

RoleFilterPolicy policy(const std::string& text)
{
    std::istringstream input(text);
    return RoleFilterPolicy(parse_role_filter_config(input, "test.conf"));
}

class Lookup final : public RoleLookupService {
   public:
    std::map<uint32_t, Role> roles;
    std::map<uint32_t, std::vector<Process>> processes;
    std::unordered_map<Process, uint32_t> owners;
    mutable std::atomic<int> reads{0};
    bool fail_members = false;
    std::optional<uint32_t> lookup(Process p) const override
    {
        auto it = owners.find(p);
        return it == owners.end() ? std::nullopt : std::optional<uint32_t>(it->second);
    }
    std::optional<Role> role(uint32_t id) const override
    {
        auto it = roles.find(id);
        return it == roles.end() ? std::nullopt : std::optional<Role>(it->second);
    }
    std::optional<hng::role::RoleIdentity> identity(uint32_t) const override { return std::nullopt; }
    std::vector<Process> members(uint32_t id) const override
    {
        ++reads;
        if (fail_members) throw std::runtime_error("枚举失败");
        auto it = processes.find(id);
        return it == processes.end() ? std::vector<Process>{} : it->second;
    }
};

class Map final : public ProcessFilterMap {
   public:
    mutable std::mutex mutex;
    ProcessSet values;
    int allows = 0, erases = 0;
    int allow_failures = 0, erase_failures = 0;
    bool partial_failure = false;
    std::error_code allow(Process p) noexcept override
    {
        std::lock_guard lock(mutex);
        ++allows;
        if (allow_failures > 0) {
            --allow_failures;
            if (partial_failure) values.insert(p);
            return {ENOSPC, std::generic_category()};
        }
        values.insert(p);
        return {};
    }
    std::error_code erase(Process p) noexcept override
    {
        std::lock_guard lock(mutex);
        ++erases;
        if (erase_failures > 0) { --erase_failures; return {EIO, std::generic_category()}; }
        values.erase(p);
        return {};
    }
    bool contains(Process p) const { std::lock_guard lock(mutex); return values.count(p); }
    std::size_t size() const { std::lock_guard lock(mutex); return values.size(); }
};

struct Fixture {
    Lookup lookup;
    Map* map;
    ProcessSet dead;
    std::unique_ptr<RoleFilter> filter;
    Fixture()
    {
        auto owned = std::make_unique<Map>(); map = owned.get();
        RoleFilterOptions options;
        options.liveness = [this](Process p) {
            return dead.count(p) ? ProcessLiveness::DEAD : ProcessLiveness::UNKNOWN;
        };
        filter = std::make_unique<RoleFilter>(lookup,
            policy("[whitelist]\nregex: .*\\.service\n[blacklist]\nexact: debug.service\n"),
            std::move(owned), options);
    }
    void join(uint32_t id, const std::string& label, std::vector<Process> processes)
    {
        lookup.roles[id] = {id, label}; lookup.processes[id] = std::move(processes);
        filter->on_role_joined(lookup.roles[id]);
    }
};

void config_tests()
{
    CHECK(!policy("").should_collect("sshd.service"));
    CHECK(!RoleFilterPolicy().should_collect(""));
    auto p = policy("# comment\r\n[blacklist]\r\nexact: nginx.service\n[whitelist]\n"
        "exact: nginx.service\nregex: honeypot-[a-z]+\\.service\nexact: host:5000/org/image:v1#tag\n");
    CHECK(!p.should_collect("nginx.service"));
    CHECK(p.should_collect("honeypot-web.service"));
    CHECK(!p.should_collect("prefix/honeypot-web.service"));
    CHECK(!p.should_collect("honeypot-web.service.extra"));
    CHECK(!p.should_collect("Honeypot-web.service"));
    CHECK(p.should_collect("host:5000/org/image:v1#tag"));
    CHECK(!p.should_collect("unlisted.service"));
    for (auto text : {"exact: foo", "[unknown]", "[whitelist]\n[whitelist]",
                      "[whitelist]\nexact:", "[whitelist]\nregex: [",
                      "[whitelist]\nglob: *", "[whitelist]\nexact= foo"}) {
        throws([&] { (void)policy(text); });
    }
    throws([] { (void)policy(std::string("[whitelist]\nexact: a\0b", 23)); });
    throws([] { (void)policy("[whitelist]\nexact: " + std::string(4097, 'a')); });
    throws([] { (void)policy(std::string(8193, 'a')); });
    throws([] { (void)load_role_filter_config("/nonexistent/hng-role-filter.conf"); });
    std::istringstream invalid("ignored"); invalid.setstate(std::ios::badbit);
    throws([&] { (void)parse_role_filter_config(invalid); });
    try { (void)policy("[whitelist]\nregex: ["); }
    catch (const std::runtime_error& e) { CHECK(std::string(e.what()).find("test.conf:2:") != std::string::npos); }
    CHECK(RoleFilterPolicy(load_role_filter_config("config/role_filter.conf")).should_collect("sshd.service"));
    std::string excessive = "[whitelist]\n";
    for (int i = 0; i < 4097; ++i) excessive += "exact: foo\n";
    throws([&] { (void)policy(excessive); });
}

void membership_tests()
{
    Fixture f;
    f.join(1, "sshd.service", {p1, p1, {0, 0}, {99, 0}});
    CHECK(f.lookup.reads == 0); CHECK(f.map->size() == 0);
    f.filter->drain();
    CHECK(f.map->size() == 1); CHECK(f.map->contains(p1)); CHECK(f.map->allows == 1);
    f.filter->on_role_joined(f.lookup.roles[1]); f.filter->drain();
    CHECK(f.map->allows == 1);
    f.lookup.processes[1] = {p1, p2}; f.filter->drain();
    CHECK(f.map->contains(p2));
    f.lookup.processes[1] = {}; f.filter->drain();
    CHECK(f.map->size() == 2); CHECK(f.filter->stats().empty_members > 0);
    f.dead.insert(p1); f.lookup.processes[1] = {reused}; f.filter->drain();
    CHECK(!f.map->contains(p1)); CHECK(f.map->contains(reused)); CHECK(f.map->contains(p2));
    f.lookup.roles[1].roleLabel = "debug.service";
    f.filter->on_role_main_process_changed(f.lookup.roles[1]); f.filter->drain();
    CHECK(f.map->size() == 0); CHECK(f.filter->stats().roles == 1);
    f.lookup.roles[1].roleLabel = "sshd.service";
    f.filter->on_role_main_process_changed(f.lookup.roles[1]); f.filter->drain();
    CHECK(f.map->contains(reused));
    f.lookup.roles.erase(1); const int reads = f.lookup.reads;
    f.filter->on_role_left({1, "sshd.service"}); f.filter->drain();
    CHECK(f.map->size() == 0); CHECK(f.lookup.reads == reads);
    f.filter->on_role_left({1, "sshd.service"}); f.filter->drain();
    CHECK(f.map->size() == 0); CHECK(f.filter->stats().roles == 0);
}

void ownership_tests()
{
    Fixture f;
    f.join(1, "sshd.service", {p1}); f.join(2, "nginx.service", {p1});
    f.filter->drain(); CHECK(f.map->size() == 1);
    f.lookup.roles.erase(1); f.filter->on_role_left({1, "sshd.service"});
    f.filter->drain(); CHECK(f.map->contains(p1));
    f.join(3, "debug.service", {p1}); f.lookup.owners[p1] = 3;
    f.filter->drain(); CHECK(!f.map->contains(p1));
    CHECK(f.filter->stats().roles == 2); // 不因不关注角色而移除记录
    f.lookup.owners[p1] = 2; f.filter->drain(); CHECK(f.map->contains(p1));
    f.lookup.roles.erase(2); f.filter->drain(); CHECK(!f.map->contains(p1));
}

void retry_tests()
{
    Fixture f;
    f.map->allow_failures = 1;
    f.join(1, "sshd.service", {p1}); f.filter->drain();
    CHECK(!f.map->contains(p1)); CHECK(f.filter->stats().map_errors == 1);
    CHECK(f.filter->stats().last_map_error == ENOSPC);
    f.filter->drain(); CHECK(f.map->contains(p1));
    f.lookup.fail_members = true; f.filter->drain();
    CHECK(f.map->contains(p1)); CHECK(f.filter->stats().lookup_errors == 1);
    f.lookup.fail_members = false;
    f.map->erase_failures = 1; f.lookup.roles.erase(1);
    f.filter->on_role_left({1, "sshd.service"}); f.filter->drain();
    CHECK(f.map->contains(p1));
    f.filter->drain(); CHECK(!f.map->contains(p1));

    Fixture partial;
    partial.map->partial_failure = true; partial.map->allow_failures = 1;
    partial.join(1, "sshd.service", {p1}); partial.filter->drain();
    CHECK(partial.map->contains(p1)); CHECK(partial.filter->stats().applied_processes == 0);
    partial.filter->replace_policy(RoleFilterPolicy()); partial.filter->drain();
    CHECK(!partial.map->contains(p1)); // 部分写成功但未计 applied 的项仍被撤销
}

void reload_and_stop_tests()
{
    Fixture f; f.join(1, "sshd.service", {p1}); f.filter->drain();
    throws([&] { f.filter->replace_policy(policy("[whitelist]\nregex: [")); });
    f.filter->drain(); CHECK(f.map->contains(p1));
    f.filter->replace_policy(RoleFilterPolicy()); f.filter->drain(); CHECK(f.map->size() == 0);
    f.filter->replace_policy(policy("[whitelist]\nexact: sshd.service"));
    f.filter->stop(); f.filter->stop(); f.filter->run(); CHECK(f.map->contains(p1));
    f.filter->request_refresh(); CHECK(f.filter->stats().queue_rejected == 1);
    throws([&] { RoleFilter bad(f.lookup, RoleFilterPolicy(), {}); });
    auto m = std::make_unique<Map>(); RoleFilterOptions options; options.refresh_interval = std::chrono::milliseconds(0);
    throws([&] { RoleFilter bad(f.lookup, RoleFilterPolicy(), std::move(m), options); });
    throws([] { (void)make_bpf_process_filter_map({}); });
    throws([] { (void)make_bpf_process_filter_map({-1}); });
}

void worker_tests()
{
    Lookup lookup;
    lookup.roles[1] = {1, "sshd.service"}; lookup.processes[1] = {p1};
    auto m = std::make_unique<Map>(); auto* map = m.get();
    RoleFilterOptions opts;
    opts.refresh_interval = std::chrono::milliseconds(10);
    opts.liveness = [](Process) { return ProcessLiveness::ALIVE; };
    RoleFilter filter(lookup, policy("[whitelist]\nexact: sshd.service"), std::move(m), opts);
    std::thread worker([&] { filter.run(); });
    struct Join { RoleFilter& f; std::thread& t; ~Join() { f.stop(); t.join(); } } join{filter, worker};
    std::vector<std::thread> producers;
    for (int i = 0; i < 4; ++i) producers.emplace_back([&] {
        for (int j = 0; j < 100; ++j) filter.on_role_joined({1, "sshd.service"});
    });
    for (auto& thread : producers) thread.join();
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!map->contains(p1) && std::chrono::steady_clock::now() < until) std::this_thread::yield();
    CHECK(map->contains(p1));
    const int before = lookup.reads;
    while (lookup.reads <= before && std::chrono::steady_clock::now() < until) std::this_thread::yield();
    CHECK(lookup.reads > before); // 无角色通知时也会定时刷新
}

void liveness_tests()
{
    const std::string root = "build-agent/role-filter/proc-fixture";
    std::filesystem::create_directories(root + "/123");
    struct Cleanup { std::string root; ~Cleanup() { std::filesystem::remove_all(root); } } cleanup{root};
    auto write = [&](const std::string& start) {
        std::ofstream out(root + "/123/stat");
        out << "123 (name with ) space\nand newline) S";
        for (int n = 4; n <= 21; ++n) out << " 0";
        out << ' ' << start << " 0 0\n";
    };
    write("456");
    CHECK(hng::detail::proc_liveness({123, 456}, root) == ProcessLiveness::ALIVE);
    CHECK(hng::detail::proc_liveness({123, 457}, root) == ProcessLiveness::DEAD);
    CHECK(hng::detail::proc_liveness({124, 456}, root) == ProcessLiveness::DEAD);
    write("18446744073709551616");
    CHECK(hng::detail::proc_liveness({123, 456}, root) == ProcessLiveness::UNKNOWN);
    write("-1");
    CHECK(hng::detail::proc_liveness({123, 456}, root) == ProcessLiveness::UNKNOWN);
    write("456bad");
    CHECK(hng::detail::proc_liveness({123, 456}, root) == ProcessLiveness::UNKNOWN);
    { std::ofstream out(root + "/123/stat"); out << "malformed"; }
    CHECK(hng::detail::proc_liveness({123, 456}, root) == ProcessLiveness::UNKNOWN);
}
}  // namespace

int main()
{
    try {
        config_tests(); membership_tests(); ownership_tests(); retry_tests();
        reload_and_stop_tests(); worker_tests(); liveness_tests();
        std::printf("PASS: role_filter, %d checks\n", checks);
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "FAIL: %s\n", e.what()); return 1; }
}

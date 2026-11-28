/**
 * @file test_bpf_program_group.cc
 * @brief BpfProgramGroup 的顺序、fail-fast、回滚、幂等卸载与统计快照。
 * @note 使用假加载器，无 libbpf / 无特权。
 */

#include "agent/bpf_loader/include/bpf_program_group.hpp"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

int checks = 0;
#define REQUIRE(expression)                                                   \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expression))                                                    \
            throw std::runtime_error(std::string(#expression) + " at line " + \
                                     std::to_string(__LINE__));               \
    } while (false)

class FakeLoader final : public hng::BpfProgramLoader {
   public:
    FakeLoader(std::string name, std::vector<std::string>& log)
        : name_(std::move(name)), log_(log)
    {
    }

    bool prepare() override
    {
        log_.push_back("prepare:" + name_);
        prepared_ = prepare_result;
        return prepare_result;
    }

    bool attach() override
    {
        log_.push_back("attach:" + name_);
        attached_ = attach_result;
        return attach_result;
    }

    void detach() noexcept override
    {
        log_.push_back("detach:" + name_);
        attached_ = false;
    }

    hng::BpfProgramState state() const noexcept override
    {
        if (attached_) {
            return hng::BpfProgramState::ATTACHED;
        }
        return prepared_ ? hng::BpfProgramState::PREPARED
                         : hng::BpfProgramState::UNPREPARED;
    }

    hng::BpfProgramStats stats() const noexcept override { return stats_; }

    bool prepare_result = true;
    bool attach_result  = true;
    hng::BpfProgramStats stats_;

   private:
    std::string name_;
    std::vector<std::string>& log_;
    bool prepared_ = false;
    bool attached_ = false;
};

void verify_prepare_order_and_fail_fast()
{
    std::vector<std::string> log;
    FakeLoader first("first", log);
    FakeLoader second("second", log);
    FakeLoader third("third", log);
    second.prepare_result = false;

    hng::BpfProgramGroup group;
    group.add(first);
    group.add(second);
    group.add(third);

    REQUIRE(!group.prepare_all());
    const std::vector<std::string> expected = {"prepare:first", "prepare:second"};
    REQUIRE(log == expected);
    REQUIRE(third.state() == hng::BpfProgramState::UNPREPARED);
}

void verify_attach_order()
{
    std::vector<std::string> log;
    FakeLoader first("first", log);
    FakeLoader second("second", log);

    hng::BpfProgramGroup group;
    group.add(first);
    group.add(second);
    REQUIRE(group.prepare_all());
    log.clear();

    REQUIRE(group.attach_all());
    const std::vector<std::string> expected = {"attach:first", "attach:second"};
    REQUIRE(log == expected);
    REQUIRE(first.state() == hng::BpfProgramState::ATTACHED);
    REQUIRE(second.state() == hng::BpfProgramState::ATTACHED);
}

void verify_attach_rollback()
{
    std::vector<std::string> log;
    FakeLoader first("first", log);
    FakeLoader second("second", log);
    FakeLoader third("third", log);
    second.attach_result = false;

    hng::BpfProgramGroup group;
    group.add(first);
    group.add(second);
    group.add(third);
    REQUIRE(group.prepare_all());
    log.clear();

    REQUIRE(!group.attach_all());
    const std::vector<std::string> expected = {"attach:first", "attach:second",
                                               "detach:first", "detach:second",
                                               "detach:third"};
    REQUIRE(log == expected);
}

void verify_detach_idempotent()
{
    std::vector<std::string> log;
    FakeLoader first("first", log);
    FakeLoader second("second", log);

    hng::BpfProgramGroup group;
    group.add(first);
    group.add(second);

    group.detach_all();
    group.detach_all();
    const std::vector<std::string> expected = {"detach:first", "detach:second",
                                               "detach:first", "detach:second"};
    REQUIRE(log == expected);
}

void verify_stats_order()
{
    std::vector<std::string> log;
    FakeLoader first("first", log);
    FakeLoader second("second", log);
    first.stats_.total_programs     = 3;
    first.stats_.skipped_probes     = 1;
    second.stats_.total_programs    = 7;
    second.stats_.attached_programs = 2;
    second.stats_.attach_failed     = 4;

    hng::BpfProgramGroup group;
    group.add(first);
    group.add(second);

    const std::vector<hng::BpfProgramStats> stats = group.stats();
    REQUIRE(stats.size() == 2);
    REQUIRE(stats[0].total_programs == 3);
    REQUIRE(stats[0].skipped_probes == 1);
    REQUIRE(stats[0].attached_programs == 0);
    REQUIRE(stats[1].total_programs == 7);
    REQUIRE(stats[1].attached_programs == 2);
    REQUIRE(stats[1].attach_failed == 4);
}

}  // namespace

int main()
{
    try {
        verify_prepare_order_and_fail_fast();
        verify_attach_order();
        verify_attach_rollback();
        verify_detach_idempotent();
        verify_stats_order();
        std::printf("PASS: bpf program group, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}

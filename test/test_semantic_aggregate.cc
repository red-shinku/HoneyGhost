/**
 * @file test_semantic_aggregate.cc
 * @brief 语义聚合的双线消费、预算轮转与停机排空，无 IO / 无特权。
 */
#include "agent/semantic/src/semantic.hpp"
#include "agent/util/include/event_channel.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>

namespace {

int checks = 0;
#define REQUIRE(expression)                                                   \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expression))                                                    \
            throw std::runtime_error(std::string(#expression) + " at line " + \
                                     std::to_string(__LINE__));               \
    } while (false)

template <class Pred>
bool wait_until(Pred done, int timeout_ms = 2000)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return done();
}

file_access_data make_file_raw(uint32_t pid)
{
    file_access_data raw{};
    raw.head.pid = pid;
    std::memset(raw.comm, 'c', sizeof(raw.comm));
    std::memset(raw.filename, 'f', sizeof(raw.filename));
    std::memcpy(raw.filename, "/tmp/a", 6);
    raw.flags          = 0x1234;
    raw.is_innamespace = 1;
    return raw;
}

syscall_event make_syscall_raw(uint32_t pid, int32_t exit_code)
{
    syscall_event raw{};
    raw.hdr.head.pid            = pid;
    raw.hdr.type                = PROCESS_EVENT;
    raw.hdr.name                = SYSCALL_EVENT_EXIT_GROUP;
    raw.process_event.exit_code = exit_code;
    return raw;
}

void run_two_lines()
{
    hng::EventChannel<file_access_data> raw_file(256);
    hng::EventChannel<syscall_event> raw_syscall(256);
    hng::EventChannel<hng::file_semantic_data> out_file(512);
    hng::EventChannel<hng::syscall_semantic_data> out_syscall(512);

    Semantic semantic(&raw_file.reader(), &raw_syscall.reader(),
                      &out_file.writer(), &out_syscall.writer());
    REQUIRE(semantic.state() == hng::ComponentState::READY);

    std::thread thread([&semantic] { semantic.run(); });

    REQUIRE(raw_file.writer().push(make_file_raw(123)));
    REQUIRE(wait_until([&out_file] { return !out_file.empty(); }));
    hng::file_semantic_data file_out;
    REQUIRE(out_file.reader().try_pop(file_out));
    REQUIRE(file_out.head.pid == 123);
    REQUIRE(file_out.head.type == hng::EventType::FILE_EVENT);
    REQUIRE(!file_out.data.semantic_filename().empty());

    REQUIRE(raw_syscall.writer().push(make_syscall_raw(456, 7)));
    REQUIRE(wait_until([&out_syscall] { return !out_syscall.empty(); }));
    hng::syscall_semantic_data syscall_out;
    REQUIRE(out_syscall.reader().try_pop(syscall_out));
    REQUIRE(syscall_out.head.pid == 456);
    REQUIRE(syscall_out.head.type == hng::EventType::SYSCALL_EVENT);
    const auto* process =
        std::get_if<hng::process_semantic_data>(&syscall_out.data);
    REQUIRE(process != nullptr);
    REQUIRE(process->exit_code() == 7);

    // 热点文件线超过预算时，syscall 线仍应在首轮获得处理。
    for (uint32_t i = 1; i <= 200; ++i) {
        REQUIRE(raw_file.writer().push(make_file_raw(1000 + i)));
    }
    REQUIRE(raw_syscall.writer().push(make_syscall_raw(789, 9)));
    REQUIRE(wait_until([&out_syscall] { return !out_syscall.empty(); }));
    hng::syscall_semantic_data hot_syscall;
    REQUIRE(out_syscall.reader().try_pop(hot_syscall));
    REQUIRE(hot_syscall.head.pid == 789);

    REQUIRE(wait_until([&out_file] { return out_file.size() == 200; }));
    for (uint32_t i = 0; i < 200; ++i) {
        hng::file_semantic_data event;
        REQUIRE(out_file.reader().try_pop(event));
    }

    semantic.stop();
    thread.join();
    REQUIRE(semantic.state() == hng::ComponentState::STOPPED);
    REQUIRE(raw_file.empty());
    REQUIRE(raw_syscall.empty());
}

void drain_on_stop()
{
    hng::EventChannel<file_access_data> raw_file(8);
    hng::EventChannel<syscall_event> raw_syscall(8);
    hng::EventChannel<hng::file_semantic_data> out_file(16);
    hng::EventChannel<hng::syscall_semantic_data> out_syscall(16);

    for (uint32_t i = 0; i < 4; ++i) {
        REQUIRE(raw_file.writer().push(make_file_raw(i)));
    }
    for (uint32_t i = 0; i < 4; ++i) {
        REQUIRE(raw_syscall.writer().push(make_syscall_raw(i, 0)));
    }

    Semantic semantic(&raw_file.reader(), &raw_syscall.reader(),
                      &out_file.writer(), &out_syscall.writer());
    semantic.stop();
    REQUIRE(semantic.state() == hng::ComponentState::STOPPED);
    semantic.run();  // 已停止：不消费
    REQUIRE(raw_file.size() == 4);
    REQUIRE(raw_syscall.size() == 4);

    Semantic running(&raw_file.reader(), &raw_syscall.reader(),
                     &out_file.writer(), &out_syscall.writer());
    std::thread thread([&running] { running.run(); });
    REQUIRE(wait_until([&raw_file] { return raw_file.empty(); }));
    running.stop();
    thread.join();
    REQUIRE(running.state() == hng::ComponentState::STOPPED);
    REQUIRE(raw_file.empty() && raw_syscall.empty());
}

void unwired_lines()
{
    Semantic semantic(nullptr, nullptr, nullptr, nullptr);
    std::thread thread([&semantic] { semantic.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    semantic.stop();
    thread.join();
    REQUIRE(semantic.state() == hng::ComponentState::STOPPED);
}

}  // namespace

int main()
{
    try {
        run_two_lines();
        drain_on_stop();
        unwired_lines();
        std::printf("PASS: semantic aggregate, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}

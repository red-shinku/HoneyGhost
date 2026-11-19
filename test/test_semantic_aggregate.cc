/**
 * @file test_semantic_aggregate.cc
 * @brief 语义聚合的单线消费、预算与停机排空，无 IO / 无特权。
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

syscall_event make_syscall_raw(uint32_t pid, int32_t exit_code)
{
    syscall_event raw{};
    raw.hdr.head.pid            = pid;
    raw.hdr.subtype             = PROCESS_EVENT;
    raw.hdr.name                = SYSCALL_EVENT_EXIT_GROUP;
    raw.process_event.exit_code = exit_code;
    return raw;
}

syscall_event make_file_raw(uint32_t pid, uint32_t path_flags)
{
    syscall_event raw{};
    raw.hdr.head.pid          = pid;
    raw.hdr.subtype           = FILE_EVENT;
    raw.hdr.name              = SYSCALL_EVENT_OPEN;
    raw.file_event.path_flags = path_flags;
    std::strncpy(raw.file_event.path, "rel/x", sizeof(raw.file_event.path) - 1);
    return raw;
}

void run_single_line()
{
    hng::EventChannel<syscall_event> raw_syscall(256);
    hng::EventChannel<hng::syscall_semantic_data> out_syscall(512);

    Semantic semantic(&raw_syscall.reader(), &out_syscall.writer());
    REQUIRE(semantic.state() == hng::ComponentState::READY);

    std::thread thread([&semantic] { semantic.run(); });

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

    // 超过单轮预算：队列中的事件仍应全部被消费。
    for (uint32_t i = 1; i <= 200; ++i) {
        REQUIRE(raw_syscall.writer().push(make_syscall_raw(1000 + i, 0)));
    }
    REQUIRE(wait_until([&out_syscall] { return out_syscall.size() == 200; }));
    for (uint32_t i = 0; i < 200; ++i) {
        hng::syscall_semantic_data event;
        REQUIRE(out_syscall.reader().try_pop(event));
    }

    semantic.stop();
    thread.join();
    REQUIRE(semantic.state() == hng::ComponentState::STOPPED);
    REQUIRE(raw_syscall.empty());

    const hng::SemanticStats stats = semantic.stats();
    REQUIRE(stats.processed_syscall == 201);
}

void drain_on_stop()
{
    hng::EventChannel<syscall_event> raw_syscall(8);
    hng::EventChannel<hng::syscall_semantic_data> out_syscall(16);

    for (uint32_t i = 0; i < 4; ++i) {
        REQUIRE(raw_syscall.writer().push(make_syscall_raw(i, 0)));
    }

    Semantic semantic(&raw_syscall.reader(), &out_syscall.writer());
    semantic.stop();
    REQUIRE(semantic.state() == hng::ComponentState::STOPPED);
    semantic.run();  // 已停止：不消费
    REQUIRE(raw_syscall.size() == 4);

    Semantic running(&raw_syscall.reader(), &out_syscall.writer());
    std::thread thread([&running] { running.run(); });
    REQUIRE(wait_until([&raw_syscall] { return raw_syscall.empty(); }));
    running.stop();
    thread.join();
    REQUIRE(running.state() == hng::ComponentState::STOPPED);
    REQUIRE(raw_syscall.empty());
}

/// @brief 未解析路径按事件计数，path_flags 一并透传到语义数据
void count_unresolved_path()
{
    hng::EventChannel<syscall_event> raw_syscall(16);
    hng::EventChannel<hng::syscall_semantic_data> out_syscall(16);

    Semantic semantic(&raw_syscall.reader(), &out_syscall.writer());
    std::thread thread([&semantic] { semantic.run(); });

    REQUIRE(raw_syscall.writer().push(make_file_raw(1, PATH_UNRESOLVED)));
    REQUIRE(raw_syscall.writer().push(make_file_raw(2, 0)));
    REQUIRE(raw_syscall.writer().push(make_file_raw(3, PATH_TRUNCATED)));
    REQUIRE(raw_syscall.writer().push(
        make_file_raw(4, PATH_UNRESOLVED | PATH_TRUNCATED)));
    REQUIRE(wait_until([&out_syscall] { return out_syscall.size() == 4; }));

    const uint32_t expect_flags[] = {PATH_UNRESOLVED, 0, PATH_TRUNCATED,
                                     PATH_UNRESOLVED | PATH_TRUNCATED};
    for (uint32_t expect : expect_flags) {
        hng::syscall_semantic_data event;
        REQUIRE(out_syscall.reader().try_pop(event));
        const auto* file =
            std::get_if<hng::file_syscall_semantic_data>(&event.data);
        REQUIRE(file != nullptr);
        REQUIRE(file->path_flags() == expect);
        REQUIRE(file->path() == "rel/x");
    }

    semantic.stop();
    thread.join();
    REQUIRE(semantic.state() == hng::ComponentState::STOPPED);

    const hng::SemanticStats stats = semantic.stats();
    REQUIRE(stats.processed_syscall == 4);
    REQUIRE(stats.path_unresolved == 2);
}

void unwired_line()
{
    Semantic semantic(nullptr, nullptr);
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
        run_single_line();
        count_unresolved_path();
        drain_on_stop();
        unwired_line();
        std::printf("PASS: semantic aggregate, %d checks\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}

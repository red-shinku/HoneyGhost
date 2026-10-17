/**
 * @file cli_stream_manager.cc
 * @brief CLIStreamManager 的实现
 * @author red-shinku
 * @date 2026.10.16
 */

#include "agent/cli_server/src/cli_stream_manager.hpp"

#include <utility>

#include <userver/utils/assert.hpp>

#include "agent/cli_server/src/cli_stream.hpp"

CLIStreamManager::StreamSlot::StreamSlot(StreamSlot&& other) noexcept
    : owner_(std::exchange(other.owner_, nullptr))
{
}

CLIStreamManager::StreamSlot& CLIStreamManager::StreamSlot::operator=(
    StreamSlot&& other) noexcept
{
    if (this != &other) {
        if (owner_ != nullptr) {
            owner_->release_slot();
        }
        owner_ = std::exchange(other.owner_, nullptr);
    }
    return *this;
}

CLIStreamManager::StreamSlot::~StreamSlot()
{
    if (owner_ != nullptr) {
        owner_->release_slot();
    }
}

CLIStreamManager::CLIStreamManager(std::size_t max_streams)
    : max_streams_(max_streams)
{
}

CLIStreamManager::~CLIStreamManager()
{
    UASSERT_MSG(streams_.empty(),
                "CLIStreamManager destroyed while streams were still attached");
}

std::optional<CLIStreamManager::StreamSlot> CLIStreamManager::acquire()
{
    std::size_t current = active_.load(std::memory_order_relaxed);
    while (current < max_streams_) {
        if (active_.compare_exchange_weak(current, current + 1,
                                          std::memory_order_acq_rel,
                                          std::memory_order_relaxed)) {
            return StreamSlot{*this};
        }
    }
    return std::nullopt;
}

void CLIStreamManager::attach(CLIStream* stream)
{
    const std::lock_guard lock(mu_);
    streams_.push_back(stream);
}

void CLIStreamManager::detach(CLIStream* stream)
{
    const std::lock_guard lock(mu_);
    const std::size_t removed = std::erase(streams_, stream);
    UASSERT_MSG(removed == 1, "detach of a stream that is not in the table");
}

void CLIStreamManager::shutdown()
{
    shutting_down_.store(true, std::memory_order_release);
    const std::lock_guard lock(mu_);
    for (CLIStream* stream : streams_) {
        stream->close();
    }
}

bool CLIStreamManager::shutting_down() const
{
    return shutting_down_.load(std::memory_order_acquire);
}

std::size_t CLIStreamManager::active_streams() const
{
    return active_.load(std::memory_order_relaxed);
}

void CLIStreamManager::release_slot()
{
    active_.fetch_sub(1, std::memory_order_acq_rel);
}

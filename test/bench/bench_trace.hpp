/**
 * @file bench_trace.hpp
 * @brief 压测语料文件的读写
 * @details
 * 语料把真实 ringbuf 记录按原样落盘，供不依赖 BPF 的压测复用。格式为同机
 * 使用、本机字节序：头部为 8 字节 magic "HNGTRACE"、uint32 版本号 1、
 * uint32 保留字段 0；随后逐条记录为 uint32 长度加该长度的负载，负载即
 * ringbuf 记录原文，长度取值 [1, 65535]；文件以 EOF 结束，没有尾记录。
 */

#ifndef HNG_TEST_BENCH_BENCH_TRACE_HPP_
#define HNG_TEST_BENCH_BENCH_TRACE_HPP_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace bench {

/// @brief 语料文件头 magic
inline constexpr char kTraceMagic[8] = {'H', 'N', 'G', 'T', 'R', 'A', 'C', 'E'};
/// @brief 语料格式版本
inline constexpr std::uint32_t kTraceVersion        = 1;
/// @brief 语料文件头字节数：magic 8 + 版本 4 + 保留 4
inline constexpr std::size_t kTraceHeaderSize       = 16;
/// @brief 单条记录负载的最大字节数
inline constexpr std::uint32_t kTraceMaxPayloadSize = 65535;

/**
 * @brief 语料写入器
 * @note 只应由一个线程使用；close() 之前的记录可能仍在 std::ofstream 的
 *       缓冲区里。
 */
class TraceWriter {
   public:
    /**
     * @brief 打开语料文件并写入文件头
     * @param[in] path 目标路径，已存在时截断
     * @param[out] error 失败原因
     * @return 成功时为 true
     * @note 失败后对象处于未打开状态，记录数与负载字节数归零。
     */
    bool open(const std::string& path, std::string& error);

    /**
     * @brief 追加一条记录
     * @param[in] data 负载起始地址
     * @param[in] size 负载字节数，必须在 [1, 65535]
     * @return 成功时为 true；失败后不再写入
     * @note 失败原因经 error() 读取；一旦失败，后续调用直接返回 false。
     */
    bool write(const void* data, std::size_t size);

    /// @brief 冲刷并关闭文件；未打开时无操作
    void close();

    /// @brief 已成功写入的记录数
    std::uint64_t records() const;

    /// @brief 已成功写入的负载字节数
    std::uint64_t payload_bytes() const;

    /// @brief 最近一次失败的原因；无失败时为空
    const std::string& error() const;

   private:
    std::ofstream stream_;
    std::string error_;
    std::uint64_t records_       = 0;
    std::uint64_t payload_bytes_ = 0;
};

/**
 * @brief 语料读取器
 * @note 只应由一个线程使用。
 */
class TraceReader {
   public:
    /**
     * @brief 打开语料文件并校验文件头
     * @param[in] path 目标路径
     * @param[out] error 失败原因
     * @return 成功时为 true
     * @note magic 或版本不匹配时关闭文件并返回 false。
     */
    bool open(const std::string& path, std::string& error);

    /**
     * @brief 读取下一条记录
     * @param[out] out 负载；失败或 EOF 时被清空
     * @param[out] error 失败原因
     * @return 读到记录时为 true；正常 EOF 返回 false 且 error 为空；记录长度
     *         或负载不完整时返回 false 并写 error
     */
    bool next(std::vector<char>& out, std::string& error);

    /// @brief 已成功读取的记录数
    std::uint64_t records() const;

    /// @brief 已成功读取的负载字节数
    std::uint64_t payload_bytes() const;

   private:
    std::ifstream stream_;
    std::uint64_t records_       = 0;
    std::uint64_t payload_bytes_ = 0;
};

inline bool TraceWriter::open(const std::string& path, std::string& error)
{
    close();
    stream_.clear();
    error_.clear();
    records_       = 0;
    payload_bytes_ = 0;

    stream_.open(path, std::ios::binary | std::ios::trunc);
    if (!stream_.is_open()) {
        error_ = "无法打开语料文件";
        error  = error_;
        return false;
    }

    unsigned char header[kTraceHeaderSize] = {};
    std::memcpy(header, kTraceMagic, sizeof(kTraceMagic));
    const std::uint32_t version = kTraceVersion;
    std::memcpy(header + sizeof(kTraceMagic), &version, sizeof(version));
    stream_.write(reinterpret_cast<const char*>(header),
                  static_cast<std::streamsize>(kTraceHeaderSize));
    if (!stream_.good()) {
        error_ = "写入语料文件头失败";
        error  = error_;
        stream_.close();
        return false;
    }
    error.clear();
    return true;
}

inline bool TraceWriter::write(const void* data, std::size_t size)
{
    if (size < 1 || size > kTraceMaxPayloadSize) {
        error_ = "记录长度必须在 [1, 65535] 字节";
        return false;
    }
    if (!stream_.is_open()) {
        error_ = "语料文件未打开";
        return false;
    }
    if (!error_.empty()) {
        return false;
    }

    const std::uint32_t length = static_cast<std::uint32_t>(size);
    stream_.write(reinterpret_cast<const char*>(&length), sizeof(length));
    stream_.write(static_cast<const char*>(data),
                  static_cast<std::streamsize>(size));
    if (!stream_.good()) {
        error_ = "写入语料记录失败";
        return false;
    }
    ++records_;
    payload_bytes_ += size;
    return true;
}

inline void TraceWriter::close()
{
    if (!stream_.is_open()) {
        return;
    }
    stream_.flush();
    if (!stream_.good() && error_.empty()) {
        error_ = "冲刷语料文件失败";
    }
    stream_.close();
}

inline std::uint64_t TraceWriter::records() const { return records_; }

inline std::uint64_t TraceWriter::payload_bytes() const { return payload_bytes_; }

inline const std::string& TraceWriter::error() const { return error_; }

inline bool TraceReader::open(const std::string& path, std::string& error)
{
    if (stream_.is_open()) {
        stream_.close();
    }
    stream_.clear();
    records_       = 0;
    payload_bytes_ = 0;

    stream_.open(path, std::ios::binary);
    if (!stream_.is_open()) {
        error = "无法打开语料文件";
        return false;
    }

    unsigned char header[kTraceHeaderSize] = {};
    stream_.read(reinterpret_cast<char*>(header),
                 static_cast<std::streamsize>(kTraceHeaderSize));
    if (stream_.gcount() != static_cast<std::streamsize>(kTraceHeaderSize)) {
        error = "语料文件头不完整";
        stream_.close();
        return false;
    }
    if (std::memcmp(header, kTraceMagic, sizeof(kTraceMagic)) != 0) {
        error = "语料文件头 magic 不匹配";
        stream_.close();
        return false;
    }
    std::uint32_t version = 0;
    std::memcpy(&version, header + sizeof(kTraceMagic), sizeof(version));
    if (version != kTraceVersion) {
        error = "不支持的语料版本 " + std::to_string(version);
        stream_.close();
        return false;
    }
    error.clear();
    return true;
}

inline bool TraceReader::next(std::vector<char>& out, std::string& error)
{
    error.clear();
    out.clear();
    if (!stream_.is_open()) {
        error = "语料文件未打开";
        return false;
    }

    unsigned char length_bytes[sizeof(std::uint32_t)] = {};
    stream_.read(reinterpret_cast<char*>(length_bytes),
                 static_cast<std::streamsize>(sizeof(length_bytes)));
    const std::streamsize got = stream_.gcount();
    if (got == 0) {
        if (stream_.eof()) {
            return false;
        }
        error = "读取记录长度失败";
        return false;
    }
    if (got != static_cast<std::streamsize>(sizeof(length_bytes))) {
        error = "记录长度不完整";
        return false;
    }

    std::uint32_t length = 0;
    std::memcpy(&length, length_bytes, sizeof(length));
    if (length == 0 || length > kTraceMaxPayloadSize) {
        error = "记录长度非法";
        return false;
    }

    out.resize(length);
    stream_.read(out.data(), static_cast<std::streamsize>(length));
    if (stream_.gcount() != static_cast<std::streamsize>(length)) {
        error = "记录负载不完整";
        return false;
    }
    ++records_;
    payload_bytes_ += length;
    return true;
}

inline std::uint64_t TraceReader::records() const { return records_; }

inline std::uint64_t TraceReader::payload_bytes() const { return payload_bytes_; }

}  // namespace bench

#endif  // HNG_TEST_BENCH_BENCH_TRACE_HPP_

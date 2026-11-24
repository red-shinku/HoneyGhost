/**
 * @file stages.hpp
 * @brief 事件流水线压测的 stage 描述
 * @details
 * 入口只解析公共选项，把剩余参数原样交给选中的 stage；每个 stage 自己解析
 * 私有选项、执行测量并输出结果。新增引擎/CLI 段时在入口的 stage 表里加一行。
 */

#ifndef HNG_TEST_BENCH_STAGES_HPP_
#define HNG_TEST_BENCH_STAGES_HPP_

#include <string>
#include <vector>

#include "test/bench/support.hpp"

namespace bench {

/// @brief 一个压测段的描述
struct StageSpec {
    const char* name;        ///< stage 名，供 --stage 选择
    const char* extra_help;  ///< 私有选项的多行用法，供 --help 聚合打印
    /// 是否要求 --trace；不读语料的段为 false
    bool requires_trace;
    /// 是否支持 --fidelity l2；只接真实控制面的段为 true
    bool supports_l2;
    /// @brief 执行入口；rest 是入口未识别的原始参数
    int (*run)(const CommonOptions&, const std::vector<std::string>& rest);
};

/// @brief 语义段：原始通道 → 语义聚合 → 语义通道
const StageSpec& semantic_stage();

/// @brief 引擎段：语义通道 → 运行时引擎 → 订阅端
const StageSpec& engine_stage();

/// @brief chain 段：语料回放 → 语义 → 运行时引擎（sink 后端）或整链 CLI 后端
const StageSpec& chain_stage();

#ifdef HNG_BENCH_CLI_STAGE
/// @brief CLI 段：子进程 CLI 服务端 + 裸 grpc++ 客户端的事件流
const StageSpec& cli_stage();
#endif

}  // namespace bench

#endif  // HNG_TEST_BENCH_STAGES_HPP_

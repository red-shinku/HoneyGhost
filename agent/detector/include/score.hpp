/**
 * @file score.hpp
 * @brief 异常评分结构
 * @author red_shinku
 * @date 2026.9.3
 */

#ifndef DETECT_SCORE_HPP_
#define DETECT_SCORE_HPP_

/**
 * @brief 异常评分结构
 */
struct Score {
    float fusion_score        = 0.0f;  ///< 多维度融合评分

    float syscall_seq_score   = 0.0f;
    float file_visiting_score = 0.0f;
    float network_score       = 0.0f;
    float ipc_score           = 0.0f;
    float context_seq_score   = 0.0f;  ///< 针对context派生序列的评分
};

#endif  // DETECT_SCORE_HPP_
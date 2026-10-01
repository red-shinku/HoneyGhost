/**
 * @file token_validator.hpp
 * @brief 槽位（token）类型与相应的文法谓词，作为规则引擎的类型字典
 * @details
 *
 * 本模块在 path_rule.cc 中被使用：
 * 规则引擎对外唯一入口是 path_rule.hpp 的 semanticize()，本模块是它的依赖，
 *
 * 如果需要扩展新槽位类型：
 *   1. 在 TokenId 中增加枚举值；
 *   2. validate() 增加对应 case，写清文法谓词（如 ^[0-9a-f]{32}$）；
 *   3. label() 增加对应 case，返回输出占位符名；
 *   4. path_rule.cc 规则表增加要对新槽位类型进行应用的规则；
 * 若新类型只在兜底场景出现（无固定结构位置），则只加兜底谓词，不触碰
 * validate / label 与规则表。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#ifndef TOKEN_VALIDATOR_HPP
#define TOKEN_VALIDATOR_HPP

#include <string>
#include <string_view>

namespace hng {
namespace path {

// 槽位类型：规则 {name} 占位符对应的实例类别
enum class TokenId {
    kPid,     ///< 进程号
    kTid,     ///< 线程号
    kUid,     ///< 用户号
    kFd,      ///< 文件描述符
    kN,       ///< 数字后缀（card{n} / cpu{n} / event{n} ...）
    kUuid,    ///< UUID
    kHex64,   ///< 64 位 hex（container / snapshot / layer id）
    kPci,     ///< PCI 总线地址
    kUsb,     ///< USB 设备号
    kIface,   ///< 网卡名（决策点 2：全量匹配，仅作标签）
    kDevice,  ///< 块设备名
    kId,      ///< by-id 任意标识（仅作标签）
};

/**
 * @brief 槽位文法校验
 * @details
 * 规则 {name} 槽位是否匹配由文法谓词决定，是"防误伤"的闸门：token 不满足文法则
 * 该规则分支不匹配，走更短的规则或兜底。槽位文法是匹配精准性的保障。
 * @param id 槽位类型
 * @param seg 待校验路径段
 * @return seg 是否符合该槽位的文法
 */
bool validate(TokenId id, std::string_view seg);

/**
 * @brief 槽位在输出路径中的占位符名
 * @details 用于重建语义化路径：/proc/1234 的 {pid} 槽位输出占位符名 "pid"，
 * 与重建逻辑共同作用，生成带槽位与通配符的语义化路径。
 * @param id 槽位类型
 * @return 占位符名（不含花括号）
 */
std::string_view label(TokenId id);

// ---- fallback 扫描器谓词（不绑定 trie 槽位）----

/**
 * @brief 独立 UUID 段判定
 * @details 兼容大小写（/dev/disk/by-uuid 的 symlink 为 blkid 输出的大写 UUID）。
 */
bool is_uuid(std::string_view seg);

/**
 * @brief ≥32 位纯 hex 段判定（container / snapshot / layer id）
 * @details 与槽位 {hex64} 的文法（恰好 64 位）不同：兜底更宽松，≥32 位即视为
 * 机器生成的 id，用于覆盖结构规则未精确描述但特征无歧义的路径。
 */
bool is_hex_ge32(std::string_view seg);

/**
 * @brief 段是否具有"随机性"（/tmp 族通配为 * 的判定）
 * @details 稳定基线要求 /tmp 等临时文件名不构成稳定特征，凡名字有随机性即应通配：
 * 纯数字、UUID、≥32 位 hex、字母数字混合、无元音的长字母串均为随机性信号；
 */
bool is_random_like(std::string_view seg);

/**
 * @brief systemd 实例单元判定 name@<digits>.<unit>
 * @details 实例部分必须是数字（如 foo@2.service）；命中时 out 输出替换数字后的
 * 模板 name@{n}.<unit>，保留模板名与单元类型，消除实例号。
 * @param out 命中时输出替换后的段
 * @return 是否命中
 */
bool systemd_instance(std::string_view seg, std::string& out);

}  // namespace path
}  // namespace hng

#endif  // TOKEN_VALIDATOR_HPP

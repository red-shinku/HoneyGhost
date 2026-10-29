/**
 * @file
 * @brief 通用 INI 子集配置文档的解析与类型读取。
 * @author inless427
 */
#ifndef HNG_CONFIG_DOCUMENT_HPP_
#define HNG_CONFIG_DOCUMENT_HPP_
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <istream>
#include <map>
#include <string>
#include <string_view>

namespace hng {
/** @brief 配置项的节名与键名，用于声明某个 schema 允许的键。 */
struct ConfigKey {
    std::string_view section;  ///< 节名。
    std::string_view key;      ///< 键名。
};

/**
 * @brief 严格 INI 子集文档。
 * @details 支持 `[节]`、`键 = 值` 与整行 `#` 注释。节名与键名区分大小写，
 * 只允许小写字母、数字、`_`、`-`、`.`；空名、未闭合的 `[` 以及 `]` 之后的
 * 多余字符都是错误。同一节可重复出现，同一 (节, 键) 重复出现即错误。
 * 键值行必须位于某个节内。值取第一个 `=` 之后的内容并去掉两端空格与制表符，
 * 允许再出现 `=` 与 `#`；不支持行尾注释。
 * 读取上限为总输入 1 MiB、单行 8192 字节；拒绝 NUL，行尾 `\r` 被去掉。
 * 空值在文档层合法，是否允许由调用方的 schema 决定。解析完成后文档不再变化。
 * @see ConfigKey
 * @see parse_agent_config
 */
class ConfigDocument final {
   public:
    /**
     * @brief 从输入流解析文档。
     * @param[in,out] input 借用的流，读取推进当前位置，不接管所有权。
     * @param[in] source 错误消息中的来源名称，通常为文件路径。
     * @return 解析完成的文档。
     * @throws std::runtime_error 语法错误、重复键或超出读取上限；消息格式为
     * `<来源>:<行号>: <原因>`。
     */
    static ConfigDocument parse(std::istream& input, const std::string& source);

    /**
     * @brief 判断某个 (节, 键) 是否出现。
     * @param[in] section 节名。
     * @param[in] key 键名。
     * @return 键存在时返回 true；节或键缺失返回 false。
     */
    bool contains(std::string_view section, std::string_view key) const;

    /**
     * @brief 返回某个 (节, 键) 所在的行号。
     * @param[in] section 节名。
     * @param[in] key 键名。
     * @return 键值行的行号，从 1 开始；键不存在时返回 0。
     */
    std::size_t line_of(std::string_view section, std::string_view key) const;

    /**
     * @brief 读取字符串值。
     * @param[in] section 节名。
     * @param[in] key 键名。
     * @param[in] default_value 键缺失时的返回值。
     * @return 键存在时返回其值，可能为空串；否则返回 @p default_value。
     */
    std::string get_string(std::string_view section, std::string_view key,
                           std::string default_value = {}) const;

    /**
     * @brief 读取布尔值。
     * @details 接受 `true`、`false`、`1`、`0`，不区分大小写。
     * @param[in] section 节名。
     * @param[in] key 键名。
     * @param[in] default_value 键缺失时的返回值。
     * @return 解析后的布尔值。
     * @throws std::runtime_error 键存在但值为空或格式非法；消息含来源、行号与
     * `<节>.<键>`。
     */
    bool get_bool(std::string_view section, std::string_view key,
                  bool default_value) const;

    /**
     * @brief 读取无符号十进制整数。
     * @param[in] section 节名。
     * @param[in] key 键名。
     * @param[in] default_value 键缺失时的返回值。
     * @return 解析后的整数，取值范围为 std::uint32_t。
     * @throws std::runtime_error 键存在但值为空、不是十进制数字或超出
     * std::uint32_t 范围；消息含来源、行号与 `<节>.<键>`。
     */
    std::uint32_t get_uint(std::string_view section, std::string_view key,
                           std::uint32_t default_value) const;

    /**
     * @brief 读取时长。
     * @details 值为无符号十进制整数加 `ms`、`s`、`m` 或 `h` 之一。
     * @param[in] section 节名。
     * @param[in] key 键名。
     * @param[in] default_value 键缺失时的返回值。
     * @return 解析后的时长。
     * @throws std::runtime_error 键存在但值为空、缺少或未知单位、数字非法或
     * 溢出；消息含来源、行号与 `<节>.<键>`。
     */
    std::chrono::milliseconds get_duration(
        std::string_view section, std::string_view key,
        std::chrono::milliseconds default_value) const;

    /**
     * @brief 拒绝未在 @p allowed 中声明的节或键。
     * @details 节只要被 @p allowed 中任一键引用即视为已声明；只有节头的空节
     * 同样参与检查。出现未声明的节或键立即抛错。
     * @param[in] allowed 本 schema 允许的 (节, 键) 列表。
     * @throws std::runtime_error 出现未声明的节或键；消息附来源与行号。
     */
    void reject_unknown_keys(std::initializer_list<ConfigKey> allowed) const;

   private:
    /** @brief 一个键的值及其所在行号。 */
    struct Entry {
        std::string value;     ///< 去除两端空白后的值。
        std::size_t line = 0;  ///< 键值行的行号，从 1 开始。
    };
    using Section = std::map<std::string, Entry, std::less<>>;

    /** @brief 按来源与行号抛出解析或取值错误。 */
    [[noreturn]] void fail_at(std::size_t line, const std::string& reason) const;
    /** @brief 查找键对应的条目；缺失时返回 nullptr。 */
    const Entry* find_entry(std::string_view section, std::string_view key) const;

    std::string source_;  ///< 错误消息中的来源名称。
    std::map<std::string, Section, std::less<>> sections_;  ///< 节 → 键 → 条目。
    std::map<std::string, std::size_t, std::less<>>
        section_lines_;  ///< 节首次出现的行号。
};

}  // namespace hng
#endif

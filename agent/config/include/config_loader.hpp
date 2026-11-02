/**
 * @file
 * @brief 主配置的来源定位、读取、环境变量覆盖与路径解析接口。
 * @author inless427
 */
#ifndef HNG_CONFIG_LOADER_HPP_
#define HNG_CONFIG_LOADER_HPP_
#include "agent/config/include/agent_config.hpp"
#include <istream>
#include <map>
#include <string>

namespace hng {

/** @brief 受支持的环境变量集合；未设置的变量不出现。 */
using ConfigEnvironment = std::map<std::string, std::string>;

/**
 * @brief 收集全部受支持的环境变量。
 * @details 读取 `HNG_CONFIG` 与由「`HNG_` + 节名 + `_` + 键名全大写」派生的
 * 变量；其余变量既不读取也不报错。进程环境在调用时取一次快照。
 * @return 变量名到值的映射，包含已设置但值为空的变量。
 * @see ConfigEnvironment
 */
ConfigEnvironment collect_environment();

/** @brief 主配置的来源；`path` 为空表示只使用内建默认值。 */
struct AgentConfigSource {
    std::string path;       ///< 主配置文件路径，空表示只使用内建默认值。
    bool required = false;  ///< 显式指定时缺失即错误。
};

/**
 * @brief 按命令行、`HNG_CONFIG`、默认路径的顺序解析主配置来源。
 * @param[in] command_line_path `--config` 给出的路径，空表示未给出。
 * @param[in] environment 环境变量集合。
 * @return 选中的来源；默认路径为 `/etc/honeyghost/agent.conf` 且非必需。
 */
AgentConfigSource resolve_agent_config_source(
    const std::string& command_line_path, const ConfigEnvironment& environment);

/**
 * @brief 解析主配置文本。
 * @details 只做语法、类型与取值范围检查：拒绝未知节与未知键，缺失的键取
 * 内建默认值。相对路径保持原样，引用文件的可读性不在此检查。
 * @param[in,out] input 借用的流，读取推进当前位置，不接管所有权。
 * @param[in] source 错误消息中的来源名称，通常为文件路径。
 * @return 解析得到的配置。
 * @throws std::runtime_error 语法、未知键、类型或路径校验失败。
 * @see ConfigDocument
 * @see load_agent_config
 */
AgentConfig parse_agent_config(std::istream& input, const std::string& source);

/**
 * @brief 用环境变量覆盖同名字段。
 * @details 只处理受支持的变量，值为空的变量视为未设置；类型与路径校验与
 * 文件一致。`HNG_CONFIG` 是引导项，不写入配置。
 * @param[in,out] config 被覆盖的配置。
 * @param[in] environment 环境变量集合。
 * @throws std::runtime_error 值非法；消息以环境变量名开头。
 */
void apply_config_environment(AgentConfig& config,
                              const ConfigEnvironment& environment);

/**
 * @brief 启动期唯一入口：读文件、应用环境变量、解析相对路径并检查引用。
 * @details 来源为空时取内建默认值；文件存在时解析，缺失且必需时报错，缺失
 * 且可选时取内建默认值，存在但不是普通文件时报错。相对路径以主配置文件所在
 * 目录为基准，没有主配置文件时以进程工作目录为基准。被引用的角色过滤配置与
 * CLI 服务端配置非空时必须是可读的普通文件。
 * @param[in] source 主配置来源。
 * @param[in] environment 环境变量集合。
 * @return 路径均已解析为绝对路径的配置。
 * @throws std::runtime_error 文件、配置内容、环境变量或引用文件不合法。
 * @see resolve_agent_config_source
 * @see parse_agent_config
 * @see apply_config_environment
 */
AgentConfig load_agent_config(const AgentConfigSource& source,
                              const ConfigEnvironment& environment);

}  // namespace hng
#endif

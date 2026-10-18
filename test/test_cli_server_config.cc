/**
 * @file test_cli_server_config.cc
 * @brief CLIServer 静态配置 schema 的冒烟测试
 * @details
 * schema 以 YAML 文本写成，平时只在组件注册时解析；此处直接取来解析，使格式错误
 * 或配置项漏写能在单测里暴露，而不是等到进程启动。
 * @author red-shinku
 * @date 2026.10.18
 */

#include "agent/cli_server/src/cli_server.hpp"

#include <cstdio>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

void run_schema()
{
    const userver::yaml_config::Schema schema =
        CLIServer::GetStaticConfigSchema();

    CHECK(schema.type == userver::yaml_config::FieldType::kObject,
          "顶层应为对象");
    CHECK(schema.properties.has_value(), "应声明配置项");
    if (!schema.properties.has_value()) {
        return;
    }

    const auto& properties = *schema.properties;
    CHECK(properties.count("max-concurrent-streams") == 1, "应声明并发流上限");
    CHECK(properties.count("queue-capacity") == 1, "应声明每流队列容量");
    CHECK(properties.count("drain-timeout") == 1, "应声明停机等待上界");

    CHECK(properties.at("max-concurrent-streams")->type ==
              userver::yaml_config::FieldType::kInteger,
          "并发流上限应为整数");
    CHECK(properties.at("queue-capacity")->type ==
              userver::yaml_config::FieldType::kInteger,
          "每流队列容量应为整数");
    CHECK(properties.at("drain-timeout")->type ==
              userver::yaml_config::FieldType::kString,
          "停机等待上界应为时长字符串");
}

}  // namespace

int main()
{
    run_schema();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}

/**
 * @file agent_services.hpp
 * @brief 装配层运行期导出的服务接口
 * @author red_shinku
 * @date 2026.10.28
 */

#ifndef HNG_AGENT_SERVICES_HPP_
#define HNG_AGENT_SERVICES_HPP_

class RoleLookupService;
class ContextLookupService;
class ProcessLookupService;
class SubscriberRegService;

namespace hng {

class PipelineStatsService;

/**
 * @brief 装配层运行期导出的服务接口
 * @details 只在 running() 期间有效，所指对象由装配层拥有，须在 stop() 前
 *          使用完毕；不返回组件，也不替代组件的生命周期。
 */
struct AgentServices final {
    /// 角色归属查询
    const ::RoleLookupService* role       = nullptr;
    /// 上下文归属查询
    const ::ContextLookupService* context = nullptr;
    /// 进程结构查询
    const ::ProcessLookupService* process = nullptr;
    /// 引擎订阅入口（写侧）
    ::SubscriberRegService* subscriber    = nullptr;
    /// 流水线统计查询
    const hng::PipelineStatsService* stats = nullptr;
};

}  // namespace hng

#endif  // HNG_AGENT_SERVICES_HPP_

/**
 * @file assembly.hpp
 * @brief 装配层的公共接口与构造选项
 * @details 装配层负责构造组件、跨模块接线、线程与启停顺序；不向外部返回
 *          组件，查询面经服务接口接入。
 * @author red_shinku
 * @date 2026.10.27
 */

#ifndef HNG_ASSEMBLY_HPP_
#define HNG_ASSEMBLY_HPP_

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

#include "agent/assembly/include/agent_services.hpp"
#include "agent/assembly/include/init_report.hpp"
#include "agent/assembly/include/initialization_coordinator.hpp"
#include "agent/role_filter/include/role_filter_component.hpp"
#include "agent/role_filter/include/role_filter_config.hpp"

namespace hng {

/**
 * @brief 装配层的构造选项
 * @details 队列容量在构造时生效，其余字段在 start() 时生效。
 */
struct AssemblyOptions {
    /// 每条原始事件队列的容量
    std::size_t raw_queue_capacity      = 8192;
    /// 每条语义事件队列的容量
    std::size_t semantic_queue_capacity = 8192;
    /// false：不加载探针，只跑控制面与引擎
    bool collect                        = true;
    /// 已解析的规则；空表示拒绝普通事件采集
    RoleFilterConfig role_filter_config;
    /// 刷新周期与进程存活检查
    RoleFilterOptions role_filter_options;
    /// 角色源等待时长等初始化参数
    InitializationOptions initialization;
    /// 是否启用 systemd 角色发现源
    bool enable_systemd                = true;
    /// 是否启用 containerd 角色发现源
    bool enable_containerd             = true;
    /// 翻译进程的 Unix socket 路径
    std::string containerd_socket_path = "/run/honeyghost/containerd-bridge.sock";
    /// systemd 周期快照间隔
    std::chrono::milliseconds systemd_snapshot_interval{600000};
};

/**
 * @brief 装配层
 * @details 独占持有五条事件通道、全部组件、组件线程与角色源屏障；对外只
 *          提供启动、停机、运行状态、初始化报告与服务接口。构造后不构造
 *          组件、不启动线程。
 * @note 组件线程由本层创建并 join，stop() 会 join 组件线程，不得从组件线
 *       程调用。
 * @see AssemblyOptions, AgentServices, InitReport
 */
class Assembly final {
   public:
    /// @brief 保存选项并按容量创建五条事件通道
    /// @param options 通道容量与启动参数
    /// @throws std::system_error 通道唤醒 fd 创建失败
    explicit Assembly(AssemblyOptions options);

    /// @brief 未 stop() 时按停机顺序收尾
    ~Assembly();

    Assembly(const Assembly&)            = delete;
    Assembly& operator=(const Assembly&) = delete;
    Assembly(Assembly&&)                 = delete;
    Assembly& operator=(Assembly&&)      = delete;

    /**
     * @brief 执行一次启动：构造组件、接线、初始化并启动线程
     * @return 初始化报告；state 为 FAILED 时不启动消费线程，组件已释放
     * @throws std::logic_error 已调用过 start()，或已 stop()
     * @throws std::runtime_error 采集器未编入构建却要求采集、目标内核不满足
     *         探针加载要求，或 prepare() / attach() 失败
     * @throws 构造、map 创建、策略编译或线程创建失败时按原样传播
     * @note 只调用一次；失败路径已释放全部已构造组件
     */
    InitReport start();

    /**
     * @brief 按停机顺序停止并 join 全部组件，再逆序释放组件
     * @note 幂等；内部会 join 组件线程，不得从组件线程调用
     */
    void stop();

    /// @brief 是否已启动且尚未停机
    bool running() const;

    /// @brief 装配层持有的服务接口
    /// @return 四个服务指针
    /// @throws std::logic_error 未处于运行状态
    /// @note 只在 running() 期间有效
    AgentServices services() const;

    /// @brief 最近一次 start() 的初始化报告；未启动时为默认值
    const InitReport& init_report() const;

   private:
    struct Impl;

    std::unique_ptr<Impl> impl_;
};

}  // namespace hng

#endif  // HNG_ASSEMBLY_HPP_

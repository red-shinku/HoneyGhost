/**
 * @file runtime_event.hpp
 * @brief 带运行时信息的事件类型
 * @author red-shinku
 * @date 2026.10.10
 */
#ifndef HNG_RUNTIME_EVENT_HPP_
#define HNG_RUNTIME_EVENT_HPP_

#include "agent/event_data/include/process.hpp"
#include "agent/event_data/include/role.hpp"
#include "agent/event_data/include/syscall_event.hpp"

namespace hng {

struct RuntimeInformation {
    hng::Process process;  ///< 事件主体进程
    /// 事件发生时刻的父进程，取自事件头的 (ppid, ppid_start_time)
    /// @note 只表示该时刻的父进程：父进程先退出后子进程被 re-parent，后续
    /// 事件的 ppid 随之改变；父进程的 pid 被复用后还会误命中另一个实体。
    /// 故它不是稳定的祖先链。
    hng::Process parent;
    hng::EventType etype;  ///< 事件来源；系统调用采集线恒为 SYSCALL_EVENT
    /// 语义子类型，取自事件头，不由载荷 variant 索引推导
    enum syscall_event_type subtype = UNKNOWN_EVENT;
    uint32_t roleID;  ///< 0 表示此刻未落定
    /// 归属角色在包装时刻的标签快照；未落定时为空
    /// @note 与 roleID 同属角色维度，取同一个归属快照
    hng::role_label_t roleLabel;
    uint32_t contextID;  ///< 0 表示此刻未落定
    /// 事件时刻的进程镜像绝对路径；未知时为空
    /// @note 归属快照语义：EXEC 事件取本事件刚换上的镜像，其余事件取当刻
    /// 已落库的镜像（进程自身优先，未落库时回退父进程）；它不随后续 exec
    /// 改变，也不保证与 ProcessManager 的当前值一致。
    std::string exe;
};

struct RuntimeEvent {
    RuntimeInformation runtimeInfo;
    hng::syscall_semantic_data data;
};

}  // namespace hng

#endif  // HNG_RUNTIME_EVENT_HPP_
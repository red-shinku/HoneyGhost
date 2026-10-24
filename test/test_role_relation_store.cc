/**
 * @file test_role_relation_store.cc
 * @brief 角色关系表的单元测试
 * @details
 * 覆盖 RoleRelationStore：
 *  - JOIN 建表：归属、角色视图、身份三处命中；
 *  - 重放：同实例键同锚点不换 roleID、不产跃迁，但仍按成员集修正归属；
 *  - 归一：命中已有实例键的 JOIN 按锚点更换处理，与 MAIN_PROCESS_CHANGE 同路；
 *  - 锚点更换：roleID 不变、记录锚点被覆盖、反向索引并入不丢键；
 *  - LEAVE：按反向索引定向删净，核对当前值故不误删他角色条目；
 *  - bind_to_role：父已归属则继承，未归属则暂存，父落地后应用；
 *  - 等待子树：锚点落地递归收敛，父退出丢弃整棵子树，LEAVE 取消等待项；
 *  - 墓碑：拒绝迟到 adopt 与 bind，同 pid 不同 start_time 不误伤，过期后放行；
 *  - 容量为 0 与 TTL 过期降级，墓碑深度为当前值；
 *  - on_process_exited：归属条目消失而角色记录仍在；
 *  - 锚点 gauge：锚点退出时计入、重复上报不重复计入、换锚点与退出时退出计数；
 *  - 成员新增报告：首次加入、成员漂移、锚点更换、bind 与父落地应用，只报告
 *    真正新归属的进程；
 *  - 入口拒收与异常态计数；roleID 从 1 起单调递增、不复用；
 *  - roleLabel：按来源取 unit 名 / 镜像引用，缺镜像与未声明来源各退到类型键，
 *    锚点更换时随新身份重算。
 * @author red_shinku
 * @date 2026.9.17
 */

#include "agent/control_plane/src/role_relation_store.hpp"

#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

using hng::role::RolePayload;
using hng::role::RoleSource;
using Kind = RoleTransition::Kind;

hng::Process proc(uint32_t pid, uint64_t start)
{
    return hng::Process{pid, start};
}

RolePayload mk_payload(const char* key, uint32_t pid, uint64_t start)
{
    RolePayload payload;
    payload.identity.instance_key     = key;
    payload.identity.type_key         = "nginx";
    payload.identity.attributes["ns"] = "hng";
    payload.identity.source           = RoleSource::SYSTEMD;
    payload.main_process              = proc(pid, start);
    payload.cgroup_path = std::string("/system.slice/") + key + ".service";
    return payload;
}

/// JOIN 并断言产出为新增，返回其 roleID
uint32_t join_new(RoleRelationStore& store, const char* key, uint32_t pid,
                  uint64_t start, const std::vector<hng::Process>& members)
{
    RoleTransition transition = store.join(mk_payload(key, pid, start), members);
    CHECK(transition.kind == Kind::JOINED, "首次加入应产出 JOINED");
    return transition.role.roleID;
}

/// 谓词：该进程归属给定的 roleID
bool owned_by(const RoleRelationStore& store, hng::Process p, uint32_t role_id)
{
    return store.lookup(p).value_or(0) == role_id;
}

void run_join()
{
    RoleRelationStore store;
    const uint32_t role =
        join_new(store, "a", 100, 1000, {proc(100, 1000), proc(101, 1001)});
    CHECK(role == 1, "roleID 应从 1 起");

    CHECK(owned_by(store, proc(100, 1000), role), "锚点应写入归属表");
    CHECK(owned_by(store, proc(101, 1001), role), "成员应写入归属表");
    CHECK(!store.lookup(proc(999, 9)).has_value(), "未归属进程应失配");

    std::optional<hng::Role> view = store.role(role);
    CHECK(view.has_value() && view->roleID == role && view->roleLabel == "a",
          "systemd 角色的 roleLabel 应取 unit 名（实例键）");
    CHECK(!store.role(role + 1).has_value(), "不存在的 roleID 应失配");

    std::optional<hng::role::RoleIdentity> identity = store.identity(role);
    CHECK(identity.has_value() && identity->instance_key == "a" &&
              identity->type_key == "nginx" &&
              identity->attributes.at("ns") == "hng",
          "身份应原样保留");
}

void run_roles_snapshot()
{
    RoleRelationStore store;

    CHECK(store.roles().empty(), "空表应返回空快照");

    const uint32_t role_a      = join_new(store, "a", 100, 1000, {});
    const uint32_t role_b      = join_new(store, "b", 200, 2000, {});
    const uint32_t role_c      = join_new(store, "c", 300, 3000, {});

    std::vector<hng::Role> all = store.roles();
    CHECK(all.size() == 3, "应枚举全部角色");
    CHECK(all[0].roleID == role_a && all[1].roleID == role_b &&
              all[2].roleID == role_c,
          "应按 roleID 升序");
    CHECK(all[0].roleLabel == "a" && all[1].roleLabel == "b" &&
              all[2].roleLabel == "c",
          "应携带 roleLabel");

    CHECK(store.leave("b").kind == Kind::LEFT, "存活角色应能退出");
    all = store.roles();
    CHECK(all.size() == 2 && all[0].roleID == role_a && all[1].roleID == role_c,
          "退出后快照不应含该角色");
}

void run_supervision()
{
    RoleRelationStore store;
    const uint32_t role_a = join_new(store, "a", 100, 1000, {});
    const uint32_t role_b = join_new(store, "b", 200, 2000, {});

    CHECK(store.supervised_roles().empty(), "未登记时应为空");

    store.set_supervised(role_a + 100, true);
    CHECK(store.supervised_roles().empty(), "未知 roleID 应忽略");

    store.set_supervised(role_a, true);
    std::vector<hng::Role> supervised = store.supervised_roles();
    CHECK(supervised.size() == 1 && supervised[0].roleID == role_a &&
              supervised[0].roleLabel == "a",
          "应返回已登记角色及其标签");

    store.set_supervised(role_b, true);
    supervised = store.supervised_roles();
    CHECK(supervised.size() == 2 && supervised[0].roleID == role_a &&
              supervised[1].roleID == role_b,
          "多个角色应按 roleID 升序");

    store.set_supervised(role_a, false);
    supervised = store.supervised_roles();
    CHECK(supervised.size() == 1 && supervised[0].roleID == role_b,
          "移除后不应含该角色");

    // 快照读取当前角色记录：锚点更换重算后的标签应反映出来
    RolePayload changed                  = mk_payload("b", 201, 2001);
    changed.identity.source              = RoleSource::CONTAINERD;
    changed.identity.attributes["image"] = "hng/nginx:v2";
    CHECK(store.main_process_change(changed, {proc(201, 2001)}).kind ==
              Kind::MAIN_PROCESS_CHANGED,
          "锚点更换应成功");
    supervised = store.supervised_roles();
    CHECK(supervised.size() == 1 && supervised[0].roleLabel == "hng/nginx:v2",
          "监管快照应读取当前角色记录");

    CHECK(store.leave("b").kind == Kind::LEFT, "存活角色应能退出");
    CHECK(store.supervised_roles().empty(), "角色退出后应自动移除登记");
}

void run_idempotent()
{
    RoleRelationStore store;
    const uint32_t role =
        join_new(store, "a", 100, 1000, {proc(100, 1000), proc(101, 1001)});

    RoleTransition again = store.join(mk_payload("a", 100, 1000),
                                      {proc(100, 1000), proc(101, 1001)});
    CHECK(again.kind == Kind::NONE, "同实例键同锚点重复投递不应产出跃迁");
    CHECK(store.lookup(proc(100, 1000)).value_or(0) == role,
          "重复投递不应换 roleID");

    // 同锚点的重复投递仍按本次成员集修正归属：修正成员漂移
    store.join(mk_payload("a", 100, 1000),
               {proc(100, 1000), proc(101, 1001), proc(102, 1002)});
    CHECK(owned_by(store, proc(102, 1002), role),
          "同锚点重复投递应按本次成员集补写归属");
}

void run_join_normalize()
{
    RoleRelationStore store;
    const uint32_t role = join_new(store, "a", 100, 1000, {proc(100, 1000)});

    // 命中已有实例键且锚点不同：与 MAIN_PROCESS_CHANGE 同路
    RoleTransition moved =
        store.join(mk_payload("a", 200, 2000), {proc(200, 2000)});
    CHECK(moved.kind == Kind::MAIN_PROCESS_CHANGED,
          "异锚点的 JOIN 应归一为锚点更换");
    CHECK(moved.role.roleID == role, "归一不得换 roleID");
    CHECK(owned_by(store, proc(200, 2000), role), "新锚点应写入");
    CHECK(owned_by(store, proc(100, 1000), role),
          "旧条目不得被删，清理由 on_process_exited 负责");

    // 记录锚点已被覆盖：再用新锚点投递是幂等，用旧锚点投递是锚点更换
    CHECK(store.join(mk_payload("a", 200, 2000), {}).kind == Kind::NONE,
          "记录锚点应已覆盖为新锚点");
    CHECK(store.join(mk_payload("a", 100, 1000), {}).kind ==
              Kind::MAIN_PROCESS_CHANGED,
          "记录锚点不应停留在旧值");
}

void run_main_process_change()
{
    RoleRelationStore store;
    const uint32_t role =
        join_new(store, "a", 100, 1000, {proc(100, 1000), proc(101, 1001)});

    RoleTransition moved =
        store.main_process_change(mk_payload("a", 200, 2000), {proc(200, 2000)});
    CHECK(moved.kind == Kind::MAIN_PROCESS_CHANGED && moved.role.roleID == role,
          "锚点更换应保持 roleID");
    CHECK(owned_by(store, proc(200, 2000), role), "锚点更换应写入新成员");
    CHECK(owned_by(store, proc(101, 1001), role), "反向索引并入不得丢旧键");

    CHECK(store.main_process_change(mk_payload("b", 300, 3000), {}).kind ==
              Kind::NONE,
          "未知实例键应空操作");
    CHECK(store.stats().unknown_instance == 1, "未知实例键应计数");

    CHECK(store.main_process_change(mk_payload("a", 200, 2000), {proc(999, 9)})
                  .kind == Kind::NONE,
          "锚点未变应返回 NONE");
    CHECK(owned_by(store, proc(999, 9), role),
          "锚点未变仍应按本次成员集修正归属");

    CHECK(store.leave("a").kind == Kind::LEFT, "锚点更换后仍应能退出");
    CHECK(!store.lookup(proc(200, 2000)).has_value() &&
              !store.lookup(proc(101, 1001)).has_value(),
          "LEAVE 应按反向索引删净新旧条目");
}

void run_leave()
{
    RoleRelationStore store;
    const uint32_t role_a = join_new(store, "a", 100, 1000, {proc(100, 1000)});
    store.bind_to_role(proc(101, 1001), proc(100, 1000));

    // 同一个进程被另一个角色的成员集认领
    const uint32_t role_b = join_new(store, "b", 100, 1000, {proc(100, 1000)});
    CHECK(store.stats().owner_conflict == 1, "归属冲突应计数");
    CHECK(owned_by(store, proc(100, 1000), role_b), "冲突应改判为新角色");

    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应产出退出");
    CHECK(owned_by(store, proc(100, 1000), role_b),
          "核对当前值，故不得误删已被别的角色认领的条目");
    CHECK(!store.lookup(proc(101, 1001)).has_value(),
          "bind_to_role 写入的条目应按反向索引删净");
    CHECK(!store.role(role_a).has_value() && !store.identity(role_a).has_value(),
          "退出后角色视图与身份应一并失配");

    CHECK(store.leave("b").kind == Kind::LEFT, "第二个角色应能退出");
    CHECK(!store.lookup(proc(100, 1000)).has_value(), "退出后归属应无残留");
    CHECK(store.leave("b").kind == Kind::NONE, "重复退出应空操作");
    CHECK(store.stats().unknown_instance == 1, "重复退出应计数");
}

void run_bind_to_role()
{
    RoleRelationStore store;

    // 父未归属：暂存，等父所属角色落地后应用
    store.bind_to_role(proc(101, 1001), proc(100, 1000));
    CHECK(!store.lookup(proc(101, 1001)).has_value(),
          "父未归属时子进程应暂存而非归属");
    CHECK(store.stats().bind_deferred == 1, "暂存应计数");

    const uint32_t role = join_new(store, "a", 100, 1000, {proc(100, 1000)});
    CHECK(owned_by(store, proc(101, 1001), role),
          "父 JOIN 后暂存的 bind 应被应用");
    CHECK(store.stats().bind_resolved == 1, "应用暂存 bind 应计数");

    store.bind_to_role(proc(102, 1002), proc(100, 1000));
    CHECK(owned_by(store, proc(102, 1002), role), "父已归属时应继承");

    // 子已有归属：保留现有归属，不改写
    const uint32_t other = join_new(store, "b", 200, 2000, {proc(102, 1002)});
    store.bind_to_role(proc(102, 1002), proc(100, 1000));
    CHECK(owned_by(store, proc(102, 1002), other), "已有归属的子进程不应被改写");
    CHECK(store.stats().bind_ignored == 1, "已有归属应计数");
}

void run_process_removed()
{
    RoleRelationStore store;
    const uint32_t role =
        join_new(store, "a", 100, 1000, {proc(100, 1000), proc(101, 1001)});

    store.on_process_exited(proc(101, 1001));
    CHECK(!store.lookup(proc(101, 1001)).has_value(), "退出的进程应无归属残留");
    CHECK(store.role(role).has_value(), "成员退出不改变角色存在性");
    CHECK(store.stats().anchors_removed == 0, "成员不是锚点，不计入");

    store.on_process_exited(proc(100, 1000));
    CHECK(!store.lookup(proc(100, 1000)).has_value(), "锚点的归属条目应被删");
    CHECK(store.role(role).has_value(), "锚点退出，角色仍等 LEAVE 才退出");
    CHECK(store.stats().anchors_removed == 1, "锚点已删而角色未退出应计入");

    CHECK(store.leave("a").kind == Kind::LEFT, "锚点退出后仍应能退出角色");
    CHECK(!store.role(role).has_value(), "退出后角色记录应删除");
    CHECK(store.stats().anchors_removed == 0, "退出后应退出该计数");
}

void run_anchor_gauge()
{
    RoleRelationStore store;
    const uint32_t role_a = join_new(store, "a", 100, 1000, {proc(100, 1000)});
    const uint32_t role_b = join_new(store, "b", 200, 2000, {proc(200, 2000)});

    store.on_process_exited(proc(100, 1000));
    CHECK(store.stats().anchors_removed == 1, "锚点已删的角色应计入");
    store.on_process_exited(proc(100, 1000));
    CHECK(store.stats().anchors_removed == 1, "同一锚点重复上报不得重复计入");

    // 换锚点后该角色不再是「锚点已删」：那个状态说的是旧锚点
    RoleTransition moved =
        store.main_process_change(mk_payload("a", 300, 3000), {proc(300, 3000)});
    CHECK(moved.kind == Kind::MAIN_PROCESS_CHANGED && moved.role.roleID == role_a,
          "锚点已删的角色仍应能更换锚点");
    CHECK(store.stats().anchors_removed == 0, "换锚点后应退出该计数");

    store.on_process_exited(proc(300, 3000));
    CHECK(store.stats().anchors_removed == 1, "新锚点退出应重新计入");
    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应能退出");
    CHECK(store.stats().anchors_removed == 0, "角色退出后应退出该计数");

    CHECK(store.role(role_b).has_value(), "另一角色不受影响");
    CHECK(store.stats().anchors_removed == 0, "锚点未退出的角色不计入");
}

void run_main_process()
{
    RoleRelationStore store;

    CHECK(!store.main_process(1).has_value(), "未知 roleID 应返回空");

    const uint32_t role = join_new(store, "a", 100, 1000, {proc(101, 1001)});
    std::optional<hng::Process> main = store.main_process(role);
    CHECK(main.has_value() && *main == proc(100, 1000), "应返回锚点");

    CHECK(store.main_process_change(mk_payload("a", 200, 2000), {proc(200, 2000)})
                  .kind == Kind::MAIN_PROCESS_CHANGED,
          "锚点更换应成功");
    main = store.main_process(role);
    CHECK(main.has_value() && *main == proc(200, 2000), "应返回新锚点");

    store.on_process_exited(proc(200, 2000));
    CHECK(!store.main_process(role).has_value(), "锚点退出后应为空");
    CHECK(store.role(role).has_value(), "锚点退出不改变角色存在性");

    CHECK(store.main_process_change(mk_payload("a", 300, 3000), {proc(300, 3000)})
                  .kind == Kind::MAIN_PROCESS_CHANGED,
          "锚点已删的角色仍可更换锚点");
    main = store.main_process(role);
    CHECK(main.has_value() && *main == proc(300, 3000), "更换后应返回新锚点");

    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应能退出");
    CHECK(!store.main_process(role).has_value(), "角色退出后应为空");
}

void run_reject_and_ids()
{
    RoleRelationStore store;

    CHECK(store.join(mk_payload("", 100, 1000), {}).kind == Kind::NONE,
          "缺实例键应拒收");
    CHECK(store.join(mk_payload("a", 0, 1000), {}).kind == Kind::NONE,
          "pid 为 0 应拒收");
    CHECK(store.join(mk_payload("a", 100, 0), {}).kind == Kind::NONE,
          "start_time 为 0 应拒收");
    CHECK(store.main_process_change(mk_payload("", 100, 1000), {}).kind ==
              Kind::NONE,
          "锚点更换同样拒收");
    CHECK(store.stats().rejected == 4 && store.stats().unknown_instance == 0,
          "拒收应计数，且不得记成未知实例键");
    CHECK(!store.role(1).has_value(), "拒收不得占用 roleID");

    const uint32_t role_a = join_new(store, "a", 100, 1000, {});
    const uint32_t role_b = join_new(store, "b", 200, 2000, {});
    CHECK(role_a == 1 && role_b == 2, "roleID 应自 1 起单调递增");
    CHECK(owned_by(store, proc(100, 1000), role_a),
          "锚点无条件写入：成员集为空也自指");

    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应产出退出");
    const uint32_t role_c = join_new(store, "c", 300, 3000, {});
    CHECK(role_c == 3, "退出的 roleID 不得复用");
}

void run_label_rules()
{
    RoleRelationStore store;

    // 容器：roleLabel 取镜像引用
    RolePayload container                  = mk_payload("c1", 200, 2000);
    container.identity.source              = RoleSource::CONTAINERD;
    container.identity.attributes["image"] = "hng/nginx:v1.2";
    RoleTransition joined = store.join(container, {proc(200, 2000)});
    CHECK(joined.role.roleLabel == "hng/nginx:v1.2", "容器应取镜像引用");

    // 容器缺镜像：退到类型键
    RolePayload no_image     = mk_payload("c2", 300, 3000);
    no_image.identity.source = RoleSource::CONTAINERD;
    joined                   = store.join(no_image, {proc(300, 3000)});
    CHECK(joined.role.roleLabel == "nginx", "容器缺镜像应退到类型键");

    // 未声明来源：退到类型键
    RolePayload unknown     = mk_payload("c3", 400, 4000);
    unknown.identity.source = RoleSource::UNSPECIFIED;
    joined                  = store.join(unknown, {proc(400, 4000)});
    CHECK(joined.role.roleLabel == "nginx", "未声明来源应退到类型键");

    // 锚点更换：roleLabel 随更换后的身份重算
    container.identity.attributes["image"] = "hng/nginx:v1.3";
    container.main_process                 = proc(201, 2001);
    RoleTransition moved =
        store.main_process_change(container, {proc(201, 2001)});
    CHECK(moved.kind == Kind::MAIN_PROCESS_CHANGED &&
              moved.role.roleLabel == "hng/nginx:v1.3",
          "锚点更换应重算 roleLabel");
}

/// 可控时钟：只随测试推进，供延迟表与墓碑的寿命用例
struct FakeClock {
    hng::RelationTimePoint now{};
};

void run_bind_drop_on_exit()
{
    RoleRelationStore store;

    // 两级的等待子树：孙等子、子等父
    store.bind_to_role(proc(101, 1001), proc(100, 1000));
    store.bind_to_role(proc(102, 1002), proc(101, 1001));
    CHECK(store.stats().bind_deferred == 2, "两级等待都应暂存");

    store.on_process_exited(proc(100, 1000));
    CHECK(store.stats().bind_rejected == 2, "父退出应丢弃整棵等待子树");
    CHECK(!store.lookup(proc(101, 1001)).has_value() &&
              !store.lookup(proc(102, 1002)).has_value(),
          "被丢弃的等待项不得产生归属");
}

void run_leave_cancels_waiter()
{
    RoleRelationStore store;

    // 子先等一个尚未归属的父；随后子被另一角色收编，等待项仍在
    store.bind_to_role(proc(101, 1001), proc(200, 2000));
    CHECK(store.stats().bind_deferred == 1, "应先暂存");
    const uint32_t role = join_new(store, "a", 100, 1000, {proc(101, 1001)});
    CHECK(owned_by(store, proc(101, 1001), role), "子应被角色收编");

    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应能退出");
    CHECK(!store.lookup(proc(101, 1001)).has_value(), "退出后应无归属残留");

    // 原等待锚点此时才落地：被 LEAVE 取消的等待项不得复活
    join_new(store, "b", 200, 2000, {proc(200, 2000)});
    CHECK(!store.lookup(proc(101, 1001)).has_value(),
          "LEAVE 应取消已释放进程的等待项");
    CHECK(store.stats().bind_resolved == 0,
          "被取消的等待项不得在后续 JOIN 中被应用");
}

void run_leave_fails_deep_waiters()
{
    RoleRelationStore store;

    // 33 级等待链：超出 drain 深度上限的最后一级留在等待表中
    for (uint32_t i = 1; i <= 33; ++i) {
        store.bind_to_role(proc(100 + i, 1000 + i), proc(99 + i, 999 + i));
    }
    CHECK(store.stats().bind_deferred == 33, "整条链应先暂存");

    const uint32_t role = join_new(store, "a", 100, 1000, {proc(100, 1000)});
    CHECK(owned_by(store, proc(132, 1032), role), "深度上限内的等待项应被收敛");
    CHECK(!store.lookup(proc(133, 1033)).has_value(),
          "超出深度上限的等待项应保持未归属");
    CHECK(store.stats().bind_rejected == 0, "收敛过程不应丢弃等待项");

    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应能退出");
    CHECK(store.stats().bind_rejected == 1, "LEAVE 应丢弃角色进程上残留的等待项");
    CHECK(!store.lookup(proc(133, 1033)).has_value(), "退出后不得有归属残留");
}

void run_late_adopt()
{
    RoleRelationStore store;

    store.on_process_exited(proc(101, 1001));
    CHECK(store.is_dead(proc(101, 1001)), "退出应先写墓碑");

    const uint32_t role = join_new(store, "a", 100, 1000, {proc(101, 1001)});
    CHECK(owned_by(store, proc(100, 1000), role), "锚点仍应归属");
    CHECK(!store.lookup(proc(101, 1001)).has_value(), "已退出成员不得被加入归属");
    CHECK(store.stats().late_adopt_rejected == 1, "迟到 adopt 应计数");

    // 子进程墓碑：迟到 bind 丢弃
    store.bind_to_role(proc(101, 1001), proc(100, 1000));
    CHECK(store.stats().bind_rejected == 1, "已退出子进程的 bind 应丢弃");

    // 父进程墓碑：再无归属可继承时丢弃
    store.on_process_exited(proc(102, 1002));
    store.bind_to_role(proc(103, 1003), proc(102, 1002));
    CHECK(store.stats().bind_rejected == 2, "已退出父进程的 bind 应丢弃");
    CHECK(!store.lookup(proc(103, 1003)).has_value(), "不得产生归属");
}

void run_store_tombstone()
{
    RoleRelationStore store;

    CHECK(!store.is_dead(proc(100, 1000)), "未退出进程不应命中墓碑");
    store.on_process_exited(proc(100, 1000));
    CHECK(store.is_dead(proc(100, 1000)), "退出后应命中墓碑");
    CHECK(!store.is_dead(proc(100, 9999)),
          "同 pid 不同 start_time 不应被墓碑误伤");
    CHECK(store.stats().tombstone_depth == 1, "墓碑深度应为当前条数");

    store.on_process_exited(proc(100, 1000));
    CHECK(store.stats().tombstone_depth == 1, "重复退出不得重复计入深度");

    FakeClock clock;
    RoleRelationOptions options;
    options.tombstones.ttl = std::chrono::milliseconds(100);
    options.now            = [&clock] { return clock.now; };
    RoleRelationStore expiring(options);

    expiring.on_process_exited(proc(200, 2000));
    CHECK(expiring.is_dead(proc(200, 2000)), "过期前应命中");
    CHECK(expiring.stats().tombstone_depth == 1, "过期前应计入深度");

    clock.now += std::chrono::milliseconds(101);
    CHECK(!expiring.is_dead(proc(200, 2000)), "过期墓碑不应命中");
    CHECK(expiring.stats().tombstone_depth == 0, "过期墓碑应退出深度");

    // 墓碑过期后，同一身份可重新被 adopt
    join_new(expiring, "a", 300, 3000, {proc(200, 2000)});
    CHECK(expiring.lookup(proc(200, 2000)).has_value(),
          "墓碑过期后应允许重新归属");
    CHECK(expiring.stats().late_adopt_rejected == 0, "过期后不应计迟到 adopt");
}

void run_capacity_and_expiry()
{
    RoleRelationOptions no_capacity;
    no_capacity.bind_pending.capacity = 0;
    RoleRelationStore capped(no_capacity);

    capped.bind_to_role(proc(101, 1001), proc(100, 1000));
    CHECK(capped.stats().bind_rejected == 1, "容量为 0 时 bind 应被拒绝");
    CHECK(capped.stats().bind_deferred == 0, "容量为 0 时不得暂存");
    CHECK(capped.join(mk_payload("a", 100, 1000), {proc(100, 1000)}).kind ==
              Kind::JOINED,
          "bind 被拒不应影响角色加入");
    CHECK(!capped.lookup(proc(101, 1001)).has_value(),
          "被拒绝的 bind 不得产生归属");

    FakeClock clock;
    RoleRelationOptions ttl;
    ttl.bind_pending.ttl = std::chrono::milliseconds(100);
    ttl.now              = [&clock] { return clock.now; };
    RoleRelationStore expiring(ttl);

    expiring.bind_to_role(proc(102, 1002), proc(100, 1000));
    CHECK(expiring.stats().bind_deferred == 1, "应先暂存");
    clock.now += std::chrono::milliseconds(101);
    expiring.expire();
    CHECK(expiring.stats().bind_expired == 1, "过期等待项应计数");

    const uint32_t role = join_new(expiring, "a", 100, 1000, {});
    CHECK(owned_by(expiring, proc(100, 1000), role), "锚点仍应归属");
    CHECK(!expiring.lookup(proc(102, 1002)).has_value(),
          "过期等待项不得在锚点落地时被应用");
    CHECK(expiring.stats().bind_resolved == 0, "过期等待项不计为已应用");
}

/// 谓词：changes 恰好是给定角色的这些新增成员
bool only_role(const RoleMemberChanges& changes, uint32_t role_id,
               const std::vector<hng::Process>& expected)
{
    return changes.entries.size() == 1 && changes.entries[0].role_id == role_id &&
           changes.entries[0].members == expected;
}

void run_member_changes()
{
    RoleRelationStore store;

    // 首次加入：锚点与成员都算新增
    RoleTransition joined = store.join(mk_payload("a", 100, 1000),
                                       {proc(100, 1000), proc(101, 1001)});
    const uint32_t role   = joined.role.roleID;
    CHECK(only_role(joined.members, role, {proc(100, 1000), proc(101, 1001)}),
          "首次加入应报告锚点与载荷成员");

    // 同锚点重放且成员集不变：无新增
    RoleTransition replay = store.join(mk_payload("a", 100, 1000),
                                       {proc(100, 1000), proc(101, 1001)});
    CHECK(replay.kind == Kind::NONE && replay.members.entries.empty(),
          "重复投递不得报告新增");

    // 同锚点重放且成员集变宽：只报告新成员
    RoleTransition drift =
        store.join(mk_payload("a", 100, 1000),
                   {proc(100, 1000), proc(101, 1001), proc(102, 1002)});
    CHECK(drift.kind == Kind::NONE &&
              only_role(drift.members, role, {proc(102, 1002)}),
          "成员漂移只报告新增成员");

    // 锚点更换：新锚点算新增
    RoleTransition moved =
        store.main_process_change(mk_payload("a", 200, 2000), {proc(200, 2000)});
    CHECK(moved.kind == Kind::MAIN_PROCESS_CHANGED &&
              only_role(moved.members, role, {proc(200, 2000)}),
          "锚点更换应报告新锚点");

    // 父已归属的 bind：立即报告子进程
    RoleMemberChanges bound =
        store.bind_to_role(proc(103, 1003), proc(100, 1000));
    CHECK(only_role(bound, role, {proc(103, 1003)}), "bind 应报告继承的子进程");

    // 已有归属的子进程：不报告
    RoleMemberChanges again =
        store.bind_to_role(proc(103, 1003), proc(100, 1000));
    CHECK(again.entries.empty(), "已有归属的 bind 不得报告新增");
    CHECK(store.stats().bind_ignored == 1, "已有归属应计数");

    // 父未归属的暂存 bind：父落地时随该次落地报告
    RoleMemberChanges deferred =
        store.bind_to_role(proc(302, 3002), proc(300, 3000));
    CHECK(deferred.entries.empty(), "暂存的 bind 落地前不得报告");
    RoleTransition landed =
        store.join(mk_payload("d", 300, 3000), {proc(300, 3000)});
    CHECK(landed.kind == Kind::JOINED &&
              only_role(landed.members, landed.role.roleID,
                        {proc(300, 3000), proc(302, 3002)}),
          "父落地应用暂存 bind 时应一并报告子进程");

    // 墓碑拒绝的写入不得出现在报告里
    RoleRelationStore blocked_store;
    blocked_store.on_process_exited(proc(401, 4001));
    RoleTransition blocked = blocked_store.join(
        mk_payload("e", 400, 4000), {proc(400, 4000), proc(401, 4001)});
    CHECK(blocked.kind == Kind::JOINED &&
              only_role(blocked.members, blocked.role.roleID, {proc(400, 4000)}),
          "墓碑拒绝的成员不得进入新增报告");
}

}  // namespace

int main()
{
    run_join();
    run_roles_snapshot();
    run_supervision();
    run_idempotent();
    run_join_normalize();
    run_main_process_change();
    run_leave();
    run_bind_to_role();
    run_process_removed();
    run_anchor_gauge();
    run_main_process();
    run_reject_and_ids();
    run_label_rules();
    run_bind_drop_on_exit();
    run_leave_cancels_waiter();
    run_leave_fails_deep_waiters();
    run_late_adopt();
    run_store_tombstone();
    run_capacity_and_expiry();
    run_member_changes();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}

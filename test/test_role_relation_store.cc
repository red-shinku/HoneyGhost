/**
 * @file test_role_relation_store.cc
 * @brief 角色关系表的单元测试
 * @details
 * 覆盖 RoleRelationStore：
 *  - JOIN 建表：归属、角色视图、身份三处命中；
 *  - 幂等：同实例键同锚点重复投递不换 roleID、不写表、不产跃迁；
 *  - 归一：命中已有实例键的 JOIN 按锚点更换处理，与 MAIN_PROCESS_CHANGE 同路；
 *  - 锚点更换：roleID 不变、记录锚点被覆盖、反向索引并入不丢键；
 *  - LEAVE：按反向索引定向删净，核对当前值故不误删他角色条目；
 *  - bind_to_role：父已归属则继承，未归属则丢弃；
 *  - on_process_removed：归属条目消失而角色记录仍在；
 *  - 锚点 gauge：锚点被删时计入、重复上报不重复计入、换锚点与退出时退出计数；
 *  - 入口拒收与异常态计数；roleID 从 1 起单调递增、不复用；
 *  - roleLabel：按来源取 unit 名 / 镜像引用，缺镜像与未声明来源各退到类型键，
 *    锚点更换时随新身份重算。
 * @author red_shinku
 * @date 2026.9.17
 */

#include "agent/control_plane/src/role_relation_store.hpp"

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

    const uint32_t role_a = join_new(store, "a", 100, 1000, {});
    const uint32_t role_b = join_new(store, "b", 200, 2000, {});
    const uint32_t role_c = join_new(store, "c", 300, 3000, {});

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

    // 用更宽的成员集探测：幂等重放不做任何写入，新成员不得被写进表
    store.join(mk_payload("a", 100, 1000),
               {proc(100, 1000), proc(101, 1001), proc(102, 1002)});
    CHECK(!store.lookup(proc(102, 1002)).has_value(), "幂等重放不得写表");
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
          "旧条目不得被删，清理由 on_process_removed 负责");

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
          "锚点未变应空操作");
    CHECK(!store.lookup(proc(999, 9)).has_value(), "锚点未变不得写表");

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

    // 父未归属：丢弃
    store.bind_to_role(proc(101, 1001), proc(100, 1000));
    CHECK(!store.lookup(proc(101, 1001)).has_value(), "父未归属时子进程应被丢弃");

    const uint32_t role = join_new(store, "a", 100, 1000, {proc(100, 1000)});
    CHECK(!store.lookup(proc(101, 1001)).has_value(),
          "被丢弃的 fork 不被补账，等下一次 JOIN 的重读");

    store.bind_to_role(proc(102, 1002), proc(100, 1000));
    CHECK(owned_by(store, proc(102, 1002), role), "父已归属时应继承");
}

void run_process_removed()
{
    RoleRelationStore store;
    const uint32_t role =
        join_new(store, "a", 100, 1000, {proc(100, 1000), proc(101, 1001)});

    store.on_process_removed(proc(101, 1001));
    CHECK(!store.lookup(proc(101, 1001)).has_value(),
          "完全删除的进程应无归属残留");
    CHECK(store.role(role).has_value(), "成员被删不改变角色存在性");
    CHECK(store.stats().anchors_removed == 0, "成员不是锚点，不计入");

    store.on_process_removed(proc(100, 1000));
    CHECK(!store.lookup(proc(100, 1000)).has_value(), "锚点的归属条目应被删");
    CHECK(store.role(role).has_value(), "锚点被删，角色仍等 LEAVE 才退出");
    CHECK(store.stats().anchors_removed == 1, "锚点已删而角色未退出应计入");

    CHECK(store.leave("a").kind == Kind::LEFT, "锚点被删后仍应能退出");
    CHECK(!store.role(role).has_value(), "退出后角色记录应删除");
    CHECK(store.stats().anchors_removed == 0, "退出后应退出该计数");
}

void run_anchor_gauge()
{
    RoleRelationStore store;
    const uint32_t role_a = join_new(store, "a", 100, 1000, {proc(100, 1000)});
    const uint32_t role_b = join_new(store, "b", 200, 2000, {proc(200, 2000)});

    store.on_process_removed(proc(100, 1000));
    CHECK(store.stats().anchors_removed == 1, "锚点已删的角色应计入");
    store.on_process_removed(proc(100, 1000));
    CHECK(store.stats().anchors_removed == 1, "同一锚点重复上报不得重复计入");

    // 换锚点后该角色不再是「锚点已删」：那个状态说的是旧锚点
    RoleTransition moved =
        store.main_process_change(mk_payload("a", 300, 3000), {proc(300, 3000)});
    CHECK(moved.kind == Kind::MAIN_PROCESS_CHANGED && moved.role.roleID == role_a,
          "锚点已删的角色仍应能更换锚点");
    CHECK(store.stats().anchors_removed == 0, "换锚点后应退出该计数");

    store.on_process_removed(proc(300, 3000));
    CHECK(store.stats().anchors_removed == 1, "新锚点被删应重新计入");
    CHECK(store.leave("a").kind == Kind::LEFT, "存活角色应能退出");
    CHECK(store.stats().anchors_removed == 0, "角色退出后应退出该计数");

    CHECK(store.role(role_b).has_value(), "另一角色不受影响");
    CHECK(store.stats().anchors_removed == 0, "锚点未被删的角色不计入");
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

}  // namespace

int main()
{
    run_join();
    run_roles_snapshot();
    run_idempotent();
    run_join_normalize();
    run_main_process_change();
    run_leave();
    run_bind_to_role();
    run_process_removed();
    run_anchor_gauge();
    run_reject_and_ids();
    run_label_rules();

    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS\n");
    return 0;
}

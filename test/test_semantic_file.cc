/**
 * @file test_semantic_file.cc
 * @brief 文件语义化表驱动单元测试
 * @details
 * 三张表覆盖规则引擎所有分支：
 *  - 归一化表：normalize() 的词法边界（合并 //、./..、/var/run 别名、相对路径透传）；
 *  - 语义化表：raw → 期望语义路径，覆盖规则表全分支、静态守卫、兜底扫描、快路径负例；
 *  - 文法表：token_validator 各槽位谓词与兜底谓词。
 * Semantic_file::work() 的队列往返将在集成验证中覆盖。
 *
 * @author red_shinku
 * @date 2026.08.14
 */

#include "agent/semantic/path/include/path_normalizer.hpp"
#include "agent/semantic/path/include/path_rule.hpp"
#include "agent/semantic/path/include/token_validator.hpp"

#include <cstdio>
#include <string>

namespace {

int g_fail = 0;

#define CHECK(cond, msg)                                                         \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_fail;                                                            \
            std::fprintf(stderr, "[FAIL] %s:%d  %s\n", __FILE__, __LINE__, msg); \
        }                                                                        \
    } while (0)

struct Case {
    const char* raw;
    const char* expect;
};

// ---- 归一化表 ----
constexpr Case kNormalizeCases[] = {
    {"/proc//1234//cmdline/", "/proc/1234/cmdline"},
    {"/a/b/../c", "/a/c"},
    {"/a/../../x", "/x"},
    {"/./a", "/a"},
    {"/a/..", "/"},
    {"/", "/"},
    {"//", "/"},
    {"/var/run", "/run"},
    {"/var/run/user/1000", "/run/user/1000"},
    {"/var/runx", "/var/runx"},          // 部分前缀不别名
    {"relative/path", "relative/path"},  // 相对路径原样
    {"/run/netns//ns0/", "/run/netns/ns0"},
};

// ---- 语义化表 ----
constexpr Case kSemanticCases[] = {
    // proc 结构规则：pid 槽位与长短回退
    {"/proc/1234/cmdline", "/proc/{pid}/**"},
    {"/proc/1234", "/proc/{pid}/**"},
    {"/proc/1234/", "/proc/{pid}/**"},
    {"/proc/1234/fd/3", "/proc/{pid}/fd/{fd}/**"},
    {"/proc/1234/fd/3/info", "/proc/{pid}/fd/{fd}/**"},
    {"/proc/1234/fdinfo/5", "/proc/{pid}/fdinfo/{fd}/**"},
    {"/proc/1234/task/5678", "/proc/{pid}/task/{tid}/**"},
    {"/proc/1234/task/5678/fd/9/x", "/proc/{pid}/task/{tid}/fd/{fd}/**"},
    {"/proc/1234/fd", "/proc/{pid}/**"},  // fd 目录本身，回退 pid 通配
    {"/proc/1234/task", "/proc/{pid}/**"},
    // proc 静态守卫：原样输出
    {"/proc/self", "/proc/self"},
    {"/proc/self/cmdline", "/proc/self/cmdline"},
    {"/proc/self/fd/3", "/proc/self/fd/3"},
    {"/proc/thread-self/mem", "/proc/thread-self/mem"},
    // proc 负例：非数字不被 pid 槽位吃掉
    {"/proc/kcore", "/proc/kcore"},
    {"/proc/sys/kernel/pid_max", "/proc/sys/kernel/pid_max"},
    {"/proc/12345678/x", "/proc/12345678/x"},  // 8 位数字超 pid 上限
    // run
    {"/run/user/1000/dbus-1", "/run/user/{uid}/**"},
    {"/run/user/1000", "/run/user/{uid}/**"},
    {"/run/user/root/x", "/run/user/root/x"},  // 非数字 uid
    {"/run/netns/ns0", "/run/netns/**"},
    {"/run/netns/foo/bar/baz", "/run/netns/**"},
    // var：kubernetes / docker
    {"/var/lib/kubelet/pods/abcd1234-ef56-7890-ab12-cd34ef567890/volumes/foo", "/var/lib/kubelet/pods/{uuid}/**"},
    {"/var/lib/docker/containers/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/a/b",
     "/var/lib/docker/containers/{hex64}/**"},
    {"/var/lib/docker/overlay2/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/x",
     "/var/lib/docker/overlay2/{hex64}/**"},
    // dev：精确规则 / 前缀数字后缀
    {"/dev/disk/by-uuid/1A2B3C4D-1234-5678-9abc-def012345678", "/dev/disk/by-uuid/{uuid}"},
    {"/dev/disk/by-uuid/1A2B3C4D-1234-5678-9abc-def012345678/sub", "/dev/disk/by-uuid/{uuid}/sub"},
    {"/dev/disk/by-id/ata-WDC_WDS100T2B0A-00SM50_ABC123", "/dev/disk/by-id/{id}"},
    {"/dev/dri/card0", "/dev/dri/card{n}"},
    {"/dev/dri/renderD128", "/dev/dri/renderD{n}"},
    {"/dev/dri/cardx", "/dev/dri/cardx"},  // 非数字后缀不命中
    {"/dev/input/event5", "/dev/input/event{n}"},
    {"/dev/input/event", "/dev/input/event"},
    {"/dev/video2", "/dev/video{n}"},
    {"/dev/pts/1", "/dev/pts/{n}"},
    {"/dev/dri/card0/modes", "/dev/dri/card0/modes"},  // 精确规则，多余段不命中
    // sys
    {"/sys/class/net/lo/address", "/sys/class/net/{iface}/**"},
    {"/sys/class/block/sda1/stat", "/sys/class/block/{device}/**"},
    {"/sys/devices/system/cpu/cpu3/cache", "/sys/devices/system/cpu/cpu{n}/**"},
    {"/sys/devices/system/node/node0/meminfo", "/sys/devices/system/node/node{n}/**"},
    {"/sys/bus/pci/devices/0000:00:1f.2/resource", "/sys/bus/pci/devices/{pci}/**"},
    {"/sys/bus/pci/devices/0000:00:1f.2", "/sys/bus/pci/devices/{pci}/**"},
    {"/sys/bus/pci/devices/0000:00:1f/x", "/sys/bus/pci/devices/0000:00:1f/x"},  // 非法 pci
    {"/sys/bus/usb/devices/1-1:1.0/uevent", "/sys/bus/usb/devices/{usb}/**"},
    {"/sys/bus/usb/devices/1-1.3/x", "/sys/bus/usb/devices/{usb}/**"},
    {"/sys/bus/usb/devices/usb1/x", "/sys/bus/usb/devices/usb1/x"},  // 非 usb 设备号
    // 兜底：containerd 深层 hex、systemd 实例
    {"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/containers/"
     "1111111111111111111111111111111111111111111111111111111111111111/x",
     "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/containers/{hex64}/x"},
    {"/etc/systemd/system/foo@2.service", "/etc/systemd/system/foo@{n}.service"},
    {"/usr/lib/systemd/system/foo@2.socket", "/usr/lib/systemd/system/foo@{n}.socket"},
    {"/etc/systemd/system/getty@tty1.service", "/etc/systemd/system/getty@tty1.service"},  // 实例非数字
    // /tmp 族：有随机性即 *
    {"/tmp/1234", "/tmp/*"},
    {"/tmp/xxxxxx", "/tmp/*"},
    {"/tmp/abc123def456", "/tmp/*"},
    {"/tmp/20260814", "/tmp/*"},
    {"/tmp/abc/20260814", "/tmp/abc/*"},
    {"/tmp/abcd1234-ef56-7890-ab12-cd34ef567890", "/tmp/{uuid}"},  // uuid 优先于 *
    {"/tmp/nginx.sock", "/tmp/nginx.sock"},                        // 有意义名保留
    {"/tmp/.Xauthority", "/tmp/.Xauthority"},
    {"/tmp/app.log", "/tmp/app.log"},
    {"/var/tmp/abc123def456", "/var/tmp/*"},
    {"/dev/shm/sem.app", "/dev/shm/sem.app"},
    {"/dev/shm/1234", "/dev/shm/*"},
    // 快路径负例：门控内无命中 / 门控外透传
    {"/etc/passwd", "/etc/passwd"},
    {"/usr/lib/libc.so.6", "/usr/lib/libc.so.6"},
    {"/home/kktori/file.txt", "/home/kktori/file.txt"},
    {"/opt/app/bin/x", "/opt/app/bin/x"},
    {"/srv/backup/abcd1234-ef56-7890-ab12-cd34ef567890/inc",
     "/srv/backup/abcd1234-ef56-7890-ab12-cd34ef567890/inc"},  // srv 不在门控集合
    {"/", "/"},
    // 归一化 + 语义化 全链
    {"/proc//1234//cmdline/", "/proc/{pid}/**"},
    {"/var/run/user/1000/foo", "/run/user/{uid}/**"},
};

void run_normalize()
{
    for (const Case& c : kNormalizeCases) {
        std::string out;
        hng::path::normalize(c.raw, out);
        CHECK(out == c.expect, (std::string("normalize: ") + c.raw).c_str());
    }
}

void run_semantic()
{
    for (const Case& c : kSemanticCases) {
        std::string norm, sem;
        hng::path::normalize(c.raw, norm);
        hng::path::semanticize(norm, sem);
        if (sem != c.expect) {
            ++g_fail;
            std::fprintf(stderr, "[FAIL] semantic: %s -> %s (expect %s)\n", c.raw, sem.c_str(), c.expect);
        }
    }
}

// ---- 槽位文法 ----
void run_validator()
{
    using hng::path::TokenId;
    // 槽位文法
    CHECK(hng::path::validate(TokenId::kPid, "1234"), "pid 1234");
    CHECK(hng::path::validate(TokenId::kPid, "4194304"), "pid 上限");
    CHECK(!hng::path::validate(TokenId::kPid, "12345678"), "pid 超 7 位");
    CHECK(!hng::path::validate(TokenId::kPid, "12a4"), "pid 含字母");
    CHECK(hng::path::validate(TokenId::kUuid, "abcd1234-ef56-7890-ab12-cd34ef567890"), "uuid");
    CHECK(hng::path::validate(TokenId::kUuid, "1A2B3C4D-1234-5678-9abc-def012345678"), "uuid 大写");
    CHECK(!hng::path::validate(TokenId::kUuid, "abcd1234ef567890ab12cd34ef567890"), "uuid 无连字符");
    CHECK(hng::path::validate(TokenId::kHex64, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
          "hex64 64 位");
    CHECK(!hng::path::validate(TokenId::kHex64, "0123456789abcdef0123456789abcdef"), "hex64 32 位");
    CHECK(hng::path::validate(TokenId::kPci, "0000:00:1f.2"), "pci");
    CHECK(!hng::path::validate(TokenId::kPci, "0000:00:1f"), "pci 缺函数号");
    CHECK(!hng::path::validate(TokenId::kPci, "g000:00:1f.2"), "pci 非 hex");
    CHECK(hng::path::validate(TokenId::kUsb, "1-1"), "usb 1-1");
    CHECK(hng::path::validate(TokenId::kUsb, "1-1:1.0"), "usb 1-1:1.0");
    CHECK(hng::path::validate(TokenId::kUsb, "3-1.4.2"), "usb 3-1.4.2");
    CHECK(!hng::path::validate(TokenId::kUsb, "1"), "usb 无分隔符");
    CHECK(!hng::path::validate(TokenId::kUsb, "usb1"), "usb 字母开头");
    CHECK(hng::path::validate(TokenId::kIface, "lo"), "iface");
    CHECK(hng::path::validate(TokenId::kDevice, "sda1"), "device sda1");
    CHECK(hng::path::validate(TokenId::kDevice, "dm-0"), "device dm-0");
    CHECK(!hng::path::validate(TokenId::kDevice, ""), "device 空");
    CHECK(hng::path::validate(TokenId::kId, "anything"), "id 标签类");
    // 占位符名
    CHECK(hng::path::label(TokenId::kPid) == "pid", "label pid");
    CHECK(hng::path::label(TokenId::kN) == "n", "label n");
    CHECK(hng::path::label(TokenId::kUuid) == "uuid", "label uuid");
    // 兜底谓词
    CHECK(hng::path::is_uuid("1A2B3C4D-1234-5678-9abc-def012345678"), "is_uuid 大写");
    CHECK(hng::path::is_hex_ge32("0123456789abcdef0123456789abcdef"), "is_hex_ge32");
    CHECK(!hng::path::is_hex_ge32("0123456789abcdef0123456789abcde"), "is_hex_ge32 31 位");
    CHECK(hng::path::is_random_like("1234"), "random digits");
    CHECK(hng::path::is_random_like("xxxxxx"), "random 无元音");
    CHECK(hng::path::is_random_like("abc123def456"), "random 混合");
    CHECK(!hng::path::is_random_like("nginx.sock"), "random nginx.sock");
    CHECK(!hng::path::is_random_like("app"), "random app");
    std::string out;
    CHECK(hng::path::systemd_instance("foo@2.service", out) && out == "foo@{n}.service", "systemd 实例");
    CHECK(!hng::path::systemd_instance("foo@tty1.service", out), "systemd 实例非数字");
    CHECK(!hng::path::systemd_instance("foo@2.exe", out), "systemd 未知单元类型");
    CHECK(!hng::path::systemd_instance("foo@2", out), "systemd 无单元类型");
}

}  // namespace

int main()
{
    run_normalize();
    run_semantic();
    run_validator();
    if (g_fail) {
        std::fprintf(stderr, "TOTAL FAILURES: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL PASS (normalize=%zu semantic=%zu)\n", sizeof(kNormalizeCases) / sizeof(Case),
                sizeof(kSemanticCases) / sizeof(Case));
    return 0;
}

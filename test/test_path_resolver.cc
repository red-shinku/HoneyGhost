/**
 * @file test_path_resolver.cc
 * @brief 包含真实路径解析头，验证有界 dentry 走查与用户路径拼接。
 * @note 使用 CO-RE/helper 替身在主机上执行，不验证 eBPF verifier 或真实加载。
 * @details 替身的返回语义与内核一致：字符串 helper 返回含 NUL 的写入长度，
 *          缓冲不够时写满并返回缓冲容量；读取失败返回负的 errno。
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct qstr {
    const char* name;
};

struct dentry {
    struct dentry* d_parent;
    struct qstr d_name;
};

struct vfsmount {
    struct dentry* mnt_root;
};

/// @note mnt 不在偏移 0，用于验证由 vfsmount 反推 mount 的偏移换算
struct mount {
    struct mount* mnt_parent;
    struct dentry* mnt_mountpoint;
    struct vfsmount mnt;
};

struct path {
    struct vfsmount* mnt;
    struct dentry* dentry;
};

struct fs_struct {
    struct path root;
    struct path pwd;
};

struct file {
    struct path f_path;
};

struct mm_struct {
    struct file* exe_file;
};

struct fdtable {
    __u32 max_fds;
    struct file** fd;
};

struct files_struct {
    struct fdtable* fdt;
};

struct task_struct {
    struct fs_struct* fs;
    struct files_struct* files;
    struct mm_struct* mm;
};

static struct task_struct* bpf_get_current_task();
static long bpf_probe_read_kernel(void* dst, __u32 size, const void* src);
static long bpf_probe_read_kernel_str(void* dst, __u32 size, const void* src);
static long bpf_probe_read_user(void* dst, __u32 size, const void* src);
static long bpf_probe_read_user_str(void* dst, __u32 size, const void* src);

//! @note 不定义 __bpf__：只测路径解析与镜像快照，事件结构仅取类型定义
#include "kernel/include/path_resolver.bpf.h"

struct task_struct* current = nullptr;
bool user_read_fails        = false;

static long bpf_probe_read_kernel(void* dst, __u32 size, const void* src)
{
    if (!dst || size == 0) {
        return -EINVAL;
    }
    if (!src) {
        std::memset(dst, 0, size);
        return -EFAULT;
    }
    std::memcpy(dst, src, size);
    return 0;
}

static long bpf_probe_read_kernel_str(void* dst, __u32 size, const void* src)
{
    if (!dst || size == 0) {
        return -EINVAL;
    }
    if (!src) {
        std::memset(dst, 0, size);
        return -EFAULT;
    }
    const char* text      = static_cast<const char*>(src);
    const std::size_t len = std::strlen(text) + 1;
    if (len > size) {
        std::memcpy(dst, text, size);
        return static_cast<long>(size);
    }
    std::memcpy(dst, text, len);
    return static_cast<long>(len);
}

static long bpf_probe_read_user(void* dst, __u32 size, const void* src)
{
    if (!dst || size == 0) {
        return -EINVAL;
    }
    if (user_read_fails || !src) {
        std::memset(dst, 0, size);
        return -EFAULT;
    }
    std::memcpy(dst, src, size);
    return 0;
}

static long bpf_probe_read_user_str(void* dst, __u32 size, const void* src)
{
    if (!dst || size == 0) {
        return -EINVAL;
    }
    if (user_read_fails || !src) {
        std::memset(dst, 0, size);
        return -EFAULT;
    }
    const char* text      = static_cast<const char*>(src);
    const std::size_t len = std::strlen(text) + 1;
    if (len > size) {
        std::memcpy(dst, text, size);
        return static_cast<long>(size);
    }
    std::memcpy(dst, text, len);
    return static_cast<long>(len);
}

static struct task_struct* bpf_get_current_task() { return current; }

namespace {

int checks = 0;

/// @brief 记一次检查；失败即终止当前用例
void require(bool condition, const char* what)
{
    ++checks;
    if (!condition) {
        throw std::runtime_error(what);
    }
}

// ---- 伪造的内核对象 ----

std::vector<std::unique_ptr<dentry>> g_dentries;
std::vector<std::unique_ptr<char[]>> g_names;

/// @brief 分配一个 dentry；默认父指向自身（文件系统根），调用者按需改
dentry* add_dentry(const char* name)
{
    auto owned = std::make_unique<dentry>();
    auto text  = std::make_unique<char[]>(std::strlen(name) + 1);
    std::strcpy(text.get(), name);
    owned->d_name.name = text.get();
    owned->d_parent    = owned.get();
    dentry* raw        = owned.get();
    g_names.push_back(std::move(text));
    g_dentries.push_back(std::move(owned));
    return raw;
}

/// @brief 一棵最小的挂载树：根挂载 + /mnt/data 上的子挂载
struct World {
    dentry* root      = nullptr;
    dentry* tmp       = nullptr;
    dentry* tmp_x     = nullptr;
    dentry* mnt       = nullptr;
    dentry* data_mp   = nullptr;
    dentry* var       = nullptr;
    dentry* var_log   = nullptr;
    dentry* data_root = nullptr;
    dentry* data_file = nullptr;

    mount root_mount{};
    mount data_mount{};

    fs_struct fs{};
    file log_file{};
    file exe_file{};
    mm_struct mm{};
    file* fd_array[8] = {};
    fdtable fdt{};
    files_struct files{};
    task_struct task{};
};

std::unique_ptr<World> make_world()
{
    auto world                       = std::make_unique<World>();

    world->root                      = add_dentry("/");
    world->tmp                       = add_dentry("tmp");
    world->tmp->d_parent             = world->root;
    world->tmp_x                     = add_dentry("x");
    world->tmp_x->d_parent           = world->tmp;

    world->mnt                       = add_dentry("mnt");
    world->mnt->d_parent             = world->root;
    world->data_mp                   = add_dentry("data");
    world->data_mp->d_parent         = world->mnt;

    world->var                       = add_dentry("var");
    world->var->d_parent             = world->root;
    world->var_log                   = add_dentry("log");
    world->var_log->d_parent         = world->var;

    world->data_root                 = add_dentry("data");
    world->data_file                 = add_dentry("file");
    world->data_file->d_parent       = world->data_root;

    world->root_mount.mnt_parent     = &world->root_mount;
    world->root_mount.mnt_mountpoint = world->root;
    world->root_mount.mnt.mnt_root   = world->root;

    world->data_mount.mnt_parent     = &world->root_mount;
    world->data_mount.mnt_mountpoint = world->data_mp;
    world->data_mount.mnt.mnt_root   = world->data_root;

    world->fs.root                   = path{&world->root_mount.mnt, world->root};
    world->fs.pwd                    = world->fs.root;

    world->log_file.f_path = path{&world->root_mount.mnt, world->var_log};
    world->exe_file.f_path = path{&world->root_mount.mnt, world->tmp_x};
    world->fd_array[3]     = &world->log_file;
    world->fdt.max_fds     = 8;
    world->fdt.fd          = world->fd_array;
    world->files.fdt       = &world->fdt;

    world->task.fs         = &world->fs;
    world->task.files      = &world->files;
    world->task.mm         = &world->mm;
    world->mm.exe_file     = &world->exe_file;
    current                = &world->task;
    user_read_fails        = false;
    return world;
}

// ---- 断言辅助 ----

/// @brief 断言解析结果与期望绝对路径完全一致，且返回长度为含 NUL 长度
void expect_resolve(const char* user_path, int dirfd, const char* want)
{
    char dst[256] = {};
    const long written =
        hng_resolve_user_path(dst, sizeof(dst), user_path, dirfd);
    require(written == static_cast<long>(std::strlen(want)) + 1,
            "解析长度与期望不符");
    require(std::strcmp(dst, want) == 0, "解析结果与期望不符");
}

/// @brief 断言无法解析且 dst 保留用户原始串
void expect_unresolved(const char* user_path, int dirfd)
{
    char dst[256] = {};
    const long written =
        hng_resolve_user_path(dst, sizeof(dst), user_path, dirfd);
    require(written == -1, "无法解析时应返回 -1");
    require(std::strcmp(dst, user_path) == 0, "无法解析时应保留原始串");
}

/// @brief 断言 struct path 解析为期望绝对路径
void expect_path_str(const struct path& start, const struct path& root,
                     const char* want)
{
    char dst[256]      = {};
    const long written = hng_path_str(dst, sizeof(dst), &start, &root);
    require(written == static_cast<long>(std::strlen(want)) + 1,
            "path 解析长度与期望不符");
    require(std::strcmp(dst, want) == 0, "path 解析结果与期望不符");
}

// ---- 用例 ----

/// @brief 绝对路径直通，且不依赖当前任务
void absolute_paths()
{
    auto world = make_world();

    expect_resolve("/etc/passwd", AT_FDCWD, "/etc/passwd");
    expect_resolve("/", AT_FDCWD, "/");
    //! @note 词法归一（尾斜杠、//、.、..）全部交给用户态 path::normalize，
    //!       内核只保证结果是绝对路径
    expect_resolve("///", AT_FDCWD, "///");
    expect_resolve("/tmp/x///", AT_FDCWD, "/tmp/x///");
    expect_resolve("/tmp//x", AT_FDCWD, "/tmp//x");

    current = nullptr;
    expect_resolve("/etc/passwd", AT_FDCWD, "/etc/passwd");
    current = &world->task;
}

/// @brief 相对路径以 fs->pwd 为基准，根与普通目录两种基准
void relative_against_cwd()
{
    auto world    = make_world();

    world->fs.pwd = path{&world->root_mount.mnt, world->root};
    expect_resolve("ping", AT_FDCWD, "/ping");

    world->fs.pwd = path{&world->root_mount.mnt, world->tmp};
    expect_resolve("foo", AT_FDCWD, "/tmp/foo");
    expect_resolve("foo/bar", AT_FDCWD, "/tmp/foo/bar");
    expect_resolve("foo/", AT_FDCWD, "/tmp/foo/");
    expect_resolve("foo/bar///", AT_FDCWD, "/tmp/foo/bar///");
    //! @note 相对串的 "." 由用户态归一，内核侧原样拼接
    expect_resolve("./foo", AT_FDCWD, "/tmp/./foo");
}

/// @brief dirfd 指向 /var/log，以及 fd 越界 / 未打开 / 负值
void relative_against_dirfd()
{
    auto world = make_world();

    expect_resolve("nginx/access.log", 3, "/var/log/nginx/access.log");
    expect_resolve("/absolute", 3, "/absolute");

    expect_unresolved("rel", 4);
    expect_unresolved("rel", 9);
    expect_unresolved("rel", -1);

    world->files.fdt = nullptr;
    expect_unresolved("rel", 3);
}

/// @brief 跨挂载点：/mnt/data 挂在 /mnt 下
void mount_crossing()
{
    auto world = make_world();

    const struct path file_on_data{&world->data_mount.mnt, world->data_file};
    const struct path data_root_on_data{&world->data_mount.mnt, world->data_root};
    expect_path_str(file_on_data, world->fs.root, "/mnt/data/file");
    expect_path_str(data_root_on_data, world->fs.root, "/mnt/data");

    // 根是以 /mnt/data 为根的挂载：结果相对该挂载
    expect_path_str(file_on_data, data_root_on_data, "/file");

    // 根是父挂载的 /mnt：跨挂载后落在根上，挂载点本身不再成段
    const struct path mnt_on_root{&world->root_mount.mnt, world->mnt};
    expect_path_str(file_on_data, mnt_on_root, "/data/file");

    // 相对路径的基准目录位于子挂载内
    world->fs.pwd = path{&world->data_mount.mnt, world->data_root};
    expect_resolve("file", AT_FDCWD, "/mnt/data/file");
}

/// @brief 上溯级数上限：32 段仍可解析，33 段无法解析
void depth_limit()
{
    auto world = make_world();

    std::vector<dentry*> chain;
    for (int i = 0; i < 33; ++i) {
        chain.push_back(add_dentry("d"));
    }
    for (int i = 0; i < 32; ++i) {
        chain[i]->d_parent = chain[i + 1];
    }
    chain[32]->d_parent = world->root;

    char dst[256]       = {};
    const struct path deep{&world->root_mount.mnt, chain[0]};
    require(hng_path_str(dst, sizeof(dst), &deep, &world->fs.root) == -1,
            "超过 32 级应返回 -1");

    // 基准目录无法解析时保留用户原始串
    world->log_file.f_path = deep;
    expect_unresolved("deep", 3);

    // 32 段正好到根：可解析，结果由 32 个 "d" 组成
    std::string want = "/d";
    for (int i = 1; i < 32; ++i) {
        want += "/d";
    }
    const struct path exact{&world->root_mount.mnt, chain[1]};
    expect_path_str(exact, world->fs.root, want.c_str());
}

/// @brief 结果超出缓冲：返回 -2，dst 保留绝对前缀
void truncation()
{
    auto world = make_world();

    const struct path tmp_x{&world->root_mount.mnt, world->tmp_x};
    char small[6] = {};
    require(hng_path_str(small, sizeof(small), &tmp_x, &world->fs.root) == -2,
            "缓冲不足应返回 -2");
    require(small[0] == '/', "截断结果仍以 '/' 开头");
    require(small[sizeof(small) - 1] == '\0', "截断结果以 NUL 结尾");

    const std::string long_absolute = "/" + std::string(300, 'a');
    char dst[256]                   = {};
    require(hng_resolve_user_path(dst, sizeof(dst), long_absolute.c_str(),
                                  AT_FDCWD) == -2,
            "绝对串超长应返回 -2");
    require(dst[0] == '/' && dst[sizeof(dst) - 1] == '\0',
            "绝对串截断仍为 NUL 结尾的前缀");

    world->fs.pwd = path{&world->root_mount.mnt, world->tmp};
    const std::string long_relative(300, 'b');
    std::memset(dst, 0, sizeof(dst));
    require(hng_resolve_user_path(dst, sizeof(dst), long_relative.c_str(),
                                  AT_FDCWD) == -2,
            "相对串超长应返回 -2");
    require(std::strncmp(dst, "/tmp/", 5) == 0, "相对串截断保留绝对前缀");
}

/// @brief 空串、空指针、fs 缺失与用户串读不到
void edge_cases()
{
    auto world   = make_world();

    char dst[16] = {};
    require(hng_resolve_user_path(dst, sizeof(dst), "", AT_FDCWD) == 1,
            "空串应返回 1");
    require(dst[0] == '\0', "空串只写入 NUL");

    std::memset(dst, 'x', sizeof(dst));
    require(hng_resolve_user_path(dst, sizeof(dst), nullptr, AT_FDCWD) == -1,
            "空指针应返回 -1");
    require(dst[0] == '\0', "空指针时 dst 为空串");

    // fs 缺失：相对路径无法解析，保留原始串
    world->task.fs = nullptr;
    expect_unresolved("rel", AT_FDCWD);

    world->task.fs    = &world->fs;
    world->task.files = nullptr;
    expect_unresolved("rel", 3);
    world->task.files = &world->files;

    // 用户串读不到：无法解析且 dst 为空
    user_read_fails   = true;
    std::memset(dst, 'x', sizeof(dst));
    require(hng_resolve_user_path(dst, sizeof(dst), "rel", AT_FDCWD) == -1,
            "用户串读不到应返回 -1");
    require(dst[0] == '\0', "用户串读不到时 dst 为空串");
    user_read_fails = false;
}

/// @brief fd → struct file 的读取边界
void file_from_fd()
{
    auto world = make_world();

    require(hng_file_from_fd(3) == &world->log_file, "fd 3 应取到文件");
    require(hng_file_from_fd(4) == nullptr, "未打开的 fd 返回 NULL");
    require(hng_file_from_fd(-1) == nullptr, "负 fd 返回 NULL");
    require(hng_file_from_fd(9) == nullptr, "越界 fd 返回 NULL");

    world->task.files = nullptr;
    require(hng_file_from_fd(3) == nullptr, "files 缺失返回 NULL");
    world->task.files = &world->files;

    world->fdt.fd     = nullptr;
    require(hng_file_from_fd(3) == nullptr, "fd 数组缺失返回 NULL");
}

/// @brief hng_fill_exec_image：镜像来源缺失、正常解析、失败与截断
void exec_image()
{
    auto world                     = make_world();

    // 正常镜像：取 exe_file 的 f_path，按进程根解析
    struct syscall_event pending   = {};
    pending.exec_event.image_flags = 0xFFFF;
    hng_fill_exec_image(&pending);
    require(std::strcmp(pending.exec_event.image, "/tmp/x") == 0,
            "镜像应解析为绝对路径");
    require(pending.exec_event.image_flags == 0, "解析成功不置状态位");

    // mm 缺失
    world->task.mm = nullptr;
    pending        = {};
    hng_fill_exec_image(&pending);
    require(pending.exec_event.image_flags == PATH_UNRESOLVED,
            "mm 缺失应置 PATH_UNRESOLVED");
    require(pending.exec_event.image[0] == '\0', "mm 缺失时镜像为空串");

    // exe_file 缺失
    world->task.mm     = &world->mm;
    world->mm.exe_file = nullptr;
    pending            = {};
    hng_fill_exec_image(&pending);
    require(pending.exec_event.image_flags == PATH_UNRESOLVED,
            "exe_file 缺失应置 PATH_UNRESOLVED");

    // fs 缺失
    world->mm.exe_file = &world->exe_file;
    world->task.fs     = nullptr;
    pending            = {};
    hng_fill_exec_image(&pending);
    require(pending.exec_event.image_flags == PATH_UNRESOLVED,
            "fs 缺失应置 PATH_UNRESOLVED");

    // 解析失败：起点 path 为空
    world->task.fs         = &world->fs;
    world->exe_file.f_path = path{};
    pending                = {};
    hng_fill_exec_image(&pending);
    require(pending.exec_event.image_flags == PATH_UNRESOLVED,
            "解析失败应置 PATH_UNRESOLVED");
    require(pending.exec_event.image[0] == '\0', "解析失败时镜像为空串");

    // 截断：超长路径保留绝对前缀并置 PATH_TRUNCATED
    const std::string long_name(300, 'a');
    dentry* deep_name      = add_dentry(long_name.c_str());
    deep_name->d_parent    = world->root;
    world->exe_file.f_path = path{&world->root_mount.mnt, deep_name};
    pending                = {};
    hng_fill_exec_image(&pending);
    require(pending.exec_event.image_flags == PATH_TRUNCATED,
            "超长路径应置 PATH_TRUNCATED");
    require(pending.exec_event.image[0] == '/', "截断结果仍以 '/' 开头");
    require(
        pending.exec_event.image[sizeof(pending.exec_event.image) - 1] == '\0',
        "截断结果以 NUL 结尾");
}

}  // namespace

int main()
{
    try {
        absolute_paths();
        relative_against_cwd();
        relative_against_dirfd();
        mount_crossing();
        depth_limit();
        truncation();
        edge_cases();
        file_from_fd();
        exec_image();
        std::printf("PASS: path resolver, %d checks (helper mocks)\n", checks);
        return 0;
    }
    catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}

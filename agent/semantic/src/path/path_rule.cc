#include "agent/semantic/src/path/path_rule.hpp"
#include "agent/semantic/src/path/token_validator.hpp"

#include <array>
#include <memory>
#include <vector>

namespace hng {
namespace path {

namespace {

// ---- 规则表：一行一条，{name} 为槽位，** 为递归终点 ----
// passthrough=true：命中后原样输出（静态守卫，如 /proc/self/** —— 已无可消除的实例）
struct RuleSpec {
    const char* pattern;
    bool passthrough;
};

constexpr RuleSpec kRules[] = {
    {"/proc/self/**", true},
    {"/proc/thread-self/**", true},
    {"/proc/{pid}/task/{tid}/fd/{fd}/**", false},
    {"/proc/{pid}/task/{tid}/**", false},
    {"/proc/{pid}/fd/{fd}/**", false},
    {"/proc/{pid}/fdinfo/{fd}/**", false},
    {"/proc/{pid}/**", false},
    {"/run/user/{uid}/**", false},
    {"/run/netns/**", false},
    {"/var/lib/kubelet/pods/{uuid}/**", false},
    {"/var/lib/docker/containers/{hex64}/**", false},
    {"/var/lib/docker/overlay2/{hex64}/**", false},
    {"/dev/disk/by-uuid/{uuid}", false},
    {"/dev/disk/by-id/{id}", false},
    {"/dev/dri/card{n}", false},
    {"/dev/dri/renderD{n}", false},
    {"/dev/input/event{n}", false},
    {"/dev/video{n}", false},
    {"/dev/pts/{n}", false},
    {"/sys/class/net/{iface}/**", false},
    {"/sys/class/block/{device}/**", false},
    {"/sys/devices/system/cpu/cpu{n}/**", false},
    {"/sys/devices/system/node/node{n}/**", false},
    {"/sys/bus/pci/devices/{pci}/**", false},
    {"/sys/bus/usb/devices/{usb}/**", false},
};

// 快路径门控：首段不在该集合内的路径直接透传（绝大多数普通文件路径）。
// 集合 = 结构规则首段 ∪ 需要兜底扫描的首段（etc/usr 用于 systemd 实例）
constexpr std::string_view kRootSet[] = {
    "dev", "etc", "proc", "run", "sys", "tmp", "usr", "var",
};

// 归一化路径最大段数（filename 缓冲 256 字节，每段至少 1 字符 + '/'）
constexpr size_t kMaxSegs = 128;

// ---- trie ----
struct TrieNode {
    std::vector<std::pair<std::string, TrieNode*>> statics;   //< 精确静态串
    std::vector<std::pair<TokenId, TrieNode*>> slots;         //< 整段槽位
    std::vector<std::pair<std::string, TrieNode*>> prefixes;  //< 静态前缀 + 数字后缀
    bool terminal_glob        = false;                        //< /** 终点：重建输出 + "/**"
    bool terminal_exact       = false;                        //< 精确终点
    bool terminal_passthrough = false;                        //< 静态守卫：原样输出
};

using Arena = std::vector<std::unique_ptr<TrieNode>>;

TrieNode* new_node(Arena& arena)
{
    arena.push_back(std::make_unique<TrieNode>());
    return arena.back().get();
}

bool parse_token(std::string_view name, TokenId& id)
{
    if (name == "pid") {
        id = TokenId::kPid;
    }
    else if (name == "tid") {
        id = TokenId::kTid;
    }
    else if (name == "uid") {
        id = TokenId::kUid;
    }
    else if (name == "fd") {
        id = TokenId::kFd;
    }
    else if (name == "n") {
        id = TokenId::kN;
    }
    else if (name == "uuid") {
        id = TokenId::kUuid;
    }
    else if (name == "hex64") {
        id = TokenId::kHex64;
    }
    else if (name == "pci") {
        id = TokenId::kPci;
    }
    else if (name == "usb") {
        id = TokenId::kUsb;
    }
    else if (name == "iface") {
        id = TokenId::kIface;
    }
    else if (name == "device") {
        id = TokenId::kDevice;
    }
    else if (name == "id") {
        id = TokenId::kId;
    }
    else {
        return false;
    }
    return true;
}

/**
 * @brief 将规则 pattern 的一个段解析并挂到 node 下，返回对应子节点
 * @details
 * 段有三种形态，决定边类型：静态串（精确匹配）、整段槽位 {name}（文法校验）、
 * 前缀+数字后缀 prefix{n}（如 card{n}）。已存在的边复用，保证多规则共享前缀时
 * trie 合并。规则的扩展边界由此函数体现：新增段形态只需在此追加。
 * @param seg 去掉 '/' 后的单个段
 */
TrieNode* get_or_insert_child(TrieNode* node, std::string_view seg, Arena& arena)
{
    // 整段槽位
    if (seg.size() >= 3 && seg.front() == '{' && seg.back() == '}') {
        TokenId id;
        if (parse_token(seg.substr(1, seg.size() - 2), id)) {
            for (auto& [tid, c] : node->slots) {
                if (tid == id) {
                    return c;
                }
            }
            TrieNode* c = new_node(arena);
            node->slots.emplace_back(id, c);
            return c;
        }
    }
    // 前缀 + 数字后缀（card{n} / cpu{n} / event{n} ...）
    size_t brace = seg.find('{');
    if (brace != std::string_view::npos && brace > 0 && seg.back() == '}' &&
        seg.substr(brace + 1, seg.size() - brace - 2) == "n") {
        std::string prefix(seg.substr(0, brace));
        for (auto& [p, c] : node->prefixes) {
            if (p == prefix) {
                return c;
            }
        }
        TrieNode* c = new_node(arena);
        node->prefixes.emplace_back(std::move(prefix), c);
        return c;
    }
    // 静态串
    std::string s(seg);
    for (auto& [k, c] : node->statics) {
        if (k == s) {
            return c;
        }
    }
    TrieNode* c = new_node(arena);
    node->statics.emplace_back(std::move(s), c);
    return c;
}

/**
 * @brief 由规则表 kRules 构建 trie
 * @details
 * 每条规则逐段插入；以 ** 结尾的规则标记 glob 终点，否则标记精确终点。
 * 根节点是 arena[0]，与规则表一一对应，规则表即规则引擎的配置面。
 */
void build_trie(Arena& arena)
{
    for (const RuleSpec& spec : kRules) {
        std::string_view p = spec.pattern;
        TrieNode* cur      = arena.front().get();
        size_t i           = 1;  // 跳过开头 '/'
        bool glob_end      = false;
        while (i < p.size()) {
            size_t j             = p.find('/', i);
            std::string_view seg = (j == std::string_view::npos) ? p.substr(i) : p.substr(i, j - i);
            if (seg == "**") {
                glob_end = true;
                break;
            }
            cur = get_or_insert_child(cur, seg, arena);
            i   = (j == std::string_view::npos) ? p.size() : j + 1;
        }
        if (glob_end) {
            if (spec.passthrough) {
                cur->terminal_passthrough = true;
            }
            else {
                cur->terminal_glob = true;
            }
        }
        else {
            cur->terminal_exact = true;
        }
    }
}

const TrieNode& trie_root()
{
    static Arena arena = [] {
        Arena a;
        a.push_back(std::make_unique<TrieNode>());  // 根节点
        build_trie(a);
        return a;
    }();
    return *arena.front();
}

// ---- 匹配 ----

bool matches_prefix_digit(std::string_view seg, std::string_view prefix)
{
    if (seg.size() <= prefix.size() || seg.substr(0, prefix.size()) != prefix) {
        return false;
    }
    for (size_t k = prefix.size(); k < seg.size(); ++k) {
        if (seg[k] < '0' || seg[k] > '9') {
            return false;
        }
    }
    return true;
}

void append_segment(std::string& out, std::string_view s)
{
    if (out.back() != '/') {
        out += '/';
    }
    out += s;
}

void append_placeholder(std::string& out, std::string_view name)
{
    out += '{';
    out += name;
    out += '}';
}

// 追加一个整段槽位：分隔符 + "{name}"
void append_token(std::string& out, std::string_view name)
{
    if (out.back() != '/') {
        out += '/';
    }
    out += '{';
    out += name;
    out += '}';
}

enum MatchResult { kNoMatch, kReconstruct, kPassthrough };

/**
 * @brief 在 trie 上递归匹配，out 累计重建路径
 * @details
 * 匹配次序即语义约束：静态边先于槽位边（/proc/self 不被 {pid} 误盖，因静态关键字
 * 与数字/UUID 文法互斥故无竞争）；子节点先于节点自身终点（保证最长匹配，如 fd
 * 分支规则深于 pid 通配规则）；节点自身的 glob 终点在子节点全部失败后兜底。
 * kPassthrough 命中表示静态守卫规则，调用方应输出原路径而非重建结果。
 */
MatchResult match_node(const TrieNode* n, const std::string_view* segs, size_t i, size_t nseg, std::string& out)
{
    if (i == nseg) {
        if (n->terminal_passthrough) {
            return kPassthrough;
        }
        if (n->terminal_glob) {
            append_segment(out, "**");
            return kReconstruct;
        }
        if (n->terminal_exact) {
            return kReconstruct;
        }
        return kNoMatch;
    }

    std::string_view seg = segs[i];

    // 1. 静态边优先
    for (const auto& [s, c] : n->statics) {
        if (seg == s) {
            size_t mark = out.size();
            append_segment(out, s);
            MatchResult r = match_node(c, segs, i + 1, nseg, out);
            if (r != kNoMatch) {
                return r;
            }
            out.resize(mark);
        }
    }
    // 2. 槽位边
    for (const auto& [id, c] : n->slots) {
        if (validate(id, seg)) {
            size_t mark = out.size();
            append_token(out, label(id));
            MatchResult r = match_node(c, segs, i + 1, nseg, out);
            if (r != kNoMatch) {
                return r;
            }
            out.resize(mark);
        }
    }
    // 3. 前缀+数字边
    for (const auto& [prefix, c] : n->prefixes) {
        if (matches_prefix_digit(seg, prefix)) {
            size_t mark = out.size();
            append_segment(out, prefix);
            append_placeholder(out, "n");
            MatchResult r = match_node(c, segs, i + 1, nseg, out);
            if (r != kNoMatch) {
                return r;
            }
            out.resize(mark);
        }
    }
    // 4. 自身终点兜底（子节点全部失败后才可收缩）
    if (n->terminal_passthrough) {
        return kPassthrough;
    }
    if (n->terminal_glob) {
        append_segment(out, "**");
        return kReconstruct;
    }
    return kNoMatch;
}

// ---- 快路径与拆分 ----

std::string_view first_segment(std::string_view p)
{
    size_t end = p.find('/', 1);
    if (end == std::string_view::npos) {
        end = p.size();
    }
    return p.substr(1, end - 1);
}

bool in_root_set(std::string_view seg)
{
    for (std::string_view r : kRootSet) {
        if (r == seg) {
            return true;
        }
    }
    return false;
}

size_t split(std::string_view p, std::string_view* out, size_t cap)
{
    size_t n = 0;
    size_t i = 1;  // 跳过开头 '/'
    while (i < p.size() && n < cap) {
        size_t j             = p.find('/', i);
        std::string_view seg = (j == std::string_view::npos) ? p.substr(i) : p.substr(i, j - i);
        if (!seg.empty()) {
            out[n++] = seg;
        }
        i = (j == std::string_view::npos) ? p.size() : j + 1;
    }
    return n;
}

// ---- 兜底扫描 ----

/**
 * @brief 兜底扫描：对结构规则未覆盖、但实例特征无歧义的段做保守替换
 * @details
 * 仅对通过快路径门控的路径执行（本函数由 semanticize 在 trie 未命中后调用）。
 * 对每个段依次判定：独立 UUID → {uuid}、≥32 位 hex → {hex64}、systemd 实例 →
 * name@{n}.unit；/tmp 族（/tmp、/var/tmp、/dev/shm）下另按随机性通配为 *。
 * 任一段未替换则整体不改写。
 * @param out 改写后的路径；未改写时保持不变
 * @return 是否发生改写
 */
bool fallback_scan(const std::string_view* segs, size_t nseg, std::string& out)
{
    // /tmp 族根：仅对该族下的段做保守通配
    bool tmp_family = false;
    if (nseg >= 1 && segs[0] == "tmp") {
        tmp_family = true;
    }
    else if (nseg >= 2 && segs[0] == "var" && segs[1] == "tmp") {
        tmp_family = true;
    }
    else if (nseg >= 2 && segs[0] == "dev" && segs[1] == "shm") {
        tmp_family = true;
    }

    std::string buf;
    bool changed = false;
    for (size_t i = 0; i < nseg; ++i) {
        std::string_view seg = segs[i];
        std::string piece;
        bool replaced = false;
        if (is_uuid(seg)) {
            piece    = "{uuid}";
            replaced = true;
        }
        else if (is_hex_ge32(seg)) {
            piece    = "{hex64}";
            replaced = true;
        }
        else if (tmp_family && is_random_like(seg)) {
            piece    = "*";
            replaced = true;
        }
        else if (systemd_instance(seg, piece)) {
            replaced = true;
        }
        else {
            piece.assign(seg);
        }
        if (replaced) {
            changed = true;
        }
        buf += '/';
        buf += piece;
    }
    if (!changed) {
        return false;
    }
    out = std::move(buf);
    return true;
}

}  // namespace

bool semanticize(std::string_view norm, std::string& out)
{
    if (norm.empty() || norm.front() != '/') {
        out.assign(norm);
        return false;
    }

    // 快路径门控：首段不在根集合内，绝大多数普通文件路径直接透传
    if (!in_root_set(first_segment(norm))) {
        out.assign(norm);
        return false;
    }

    std::array<std::string_view, kMaxSegs> segs;
    size_t nseg     = split(norm, segs.data(), segs.size());

    // 结构规则匹配
    std::string buf = "/";
    MatchResult r   = match_node(&trie_root(), segs.data(), 0, nseg, buf);
    if (r == kPassthrough) {
        out.assign(norm);  // 静态守卫：原样输出
        return false;
    }
    if (r == kReconstruct) {
        out = std::move(buf);
        return true;
    }

    // 兜底扫描；未改写则原样输出
    if (fallback_scan(segs.data(), nseg, out)) {
        return true;
    }
    out.assign(norm);
    return false;
}

}  // namespace path
}  // namespace hng

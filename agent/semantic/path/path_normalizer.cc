#include "include/path_normalizer.hpp"

#include <vector>

namespace hng {
namespace path {

namespace {

// /var/run 是 /run 的真实符号链接，两种写法指向同一目录，统一为 /run
constexpr std::string_view kVarRunAlias  = "/var/run";
constexpr std::string_view kRunCanonical = "/run";

}  // namespace

bool normalize(std::string_view raw, std::string& out)
{
    if (raw.empty()) {
        out.clear();
        return false;
    }
    // 相对路径不做语义化：探针侧拿不到 CWD，无法还原绝对路径
    if (raw.front() != '/') {
        out.assign(raw);
        return false;
    }

    // 词法解析：收集组件，处理 //、.、..
    std::vector<std::string_view> comps;
    size_t i = 1;  // 跳过开头 '/'
    while (i < raw.size()) {
        size_t j           = raw.find('/', i);
        std::string_view c = (j == std::string_view::npos) ? raw.substr(i) : raw.substr(i, j - i);
        if (c.empty() || c == ".") {
            // 连续 '/' 或当前目录，跳过
        }
        else if (c == "..") {
            if (!comps.empty()) {
                comps.pop_back();
            }
        }
        else {
            comps.push_back(c);
        }
        i = (j == std::string_view::npos) ? raw.size() : j + 1;
    }

    std::string result = "/";
    for (std::string_view c : comps) {
        result += c;
        result += '/';
    }
    if (result.size() > 1) {
        result.pop_back();  // 去尾部 '/'
    }

    // 符号链接别名
    if (result.compare(0, kVarRunAlias.size(), kVarRunAlias) == 0 &&
        (result.size() == kVarRunAlias.size() || result[kVarRunAlias.size()] == '/')) {
        result.replace(0, kVarRunAlias.size(), kRunCanonical);
    }

    bool changed = (result != raw);
    out          = std::move(result);
    return changed;
}

}  // namespace path
}  // namespace hng

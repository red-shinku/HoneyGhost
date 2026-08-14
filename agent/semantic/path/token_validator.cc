#include "include/token_validator.hpp"

namespace hng {
namespace path {

namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }

bool all_digits(std::string_view s)
{
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (!is_digit(c)) {
            return false;
        }
    }
    return true;
}

bool all_hex(std::string_view s)
{
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (!(is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool has_digit(std::string_view s)
{
    for (char c : s) {
        if (is_digit(c)) {
            return true;
        }
    }
    return false;
}

bool has_letter(std::string_view s)
{
    for (char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            return true;
        }
    }
    return false;
}

bool is_vowel(char c)
{
    c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u';
}

// 无元音的长字母串（xxxxxx、gqzmwqknfq）：天然语言词必含元音，此类形态是强随机信号
bool letters_no_vowel_long(std::string_view s)
{
    if (s.size() < 6) {
        return false;
    }
    for (char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) || is_vowel(c)) {
            return false;
        }
    }
    return true;
}

// systemd 实例单元的已知类型后缀
constexpr std::string_view kSystemdUnits[] = {
    "automount", "busname", "device", "mount", "path", "scope", "service", "slice", "socket", "swap", "target", "timer",
};

}  // namespace

bool validate(TokenId id, std::string_view seg)
{
    switch (id) {
        case TokenId::kPid:
            // 内核 pid_max 上限 2^22（7 位数字）
            return seg.size() >= 1 && seg.size() <= 7 && all_digits(seg);
        case TokenId::kTid:
        case TokenId::kUid:
        case TokenId::kFd:
        case TokenId::kN:
            return all_digits(seg);
        case TokenId::kUuid:
            return is_uuid(seg);
        case TokenId::kHex64:
            return seg.size() == 64 && all_hex(seg);
        case TokenId::kPci: {
            // DDDD:BB:DD.F，形如 0000:00:1f.2
            if (seg.size() != 12) {
                return false;
            }
            return all_hex(seg.substr(0, 4)) && seg[4] == ':' && all_hex(seg.substr(5, 2)) && seg[7] == ':' &&
                   all_hex(seg.substr(8, 2)) && seg[10] == '.' && all_hex(seg.substr(11, 1));
        }
        case TokenId::kUsb: {
            // 形如 1-1、1-1.3、1-1:1.0；必须以数字开头且含分隔符
            if (seg.empty() || !is_digit(seg[0])) {
                return false;
            }
            size_t i = 0;
            while (i < seg.size() && is_digit(seg[i])) {
                ++i;
            }
            bool saw_sep = false;
            while (i < seg.size()) {
                char c = seg[i];
                if (c == '-' || c == '.') {
                    saw_sep = true;
                    ++i;
                    if (i >= seg.size() || !is_digit(seg[i])) {
                        return false;
                    }
                    while (i < seg.size() && is_digit(seg[i])) {
                        ++i;
                    }
                }
                else if (c == ':') {
                    // :n.n（接口号）
                    saw_sep = true;
                    ++i;
                    if (i >= seg.size() || !is_digit(seg[i])) {
                        return false;
                    }
                    while (i < seg.size() && is_digit(seg[i])) {
                        ++i;
                    }
                    if (i >= seg.size() || seg[i] != '.') {
                        return false;
                    }
                    ++i;
                    if (i >= seg.size() || !is_digit(seg[i])) {
                        return false;
                    }
                    while (i < seg.size() && is_digit(seg[i])) {
                        ++i;
                    }
                }
                else {
                    return false;
                }
            }
            return saw_sep;
        }
        case TokenId::kIface:
        case TokenId::kId:
            return !seg.empty();
        case TokenId::kDevice: {
            // 块设备名：sda / nvme0n1 / mmcblk0 / dm-0
            if (seg.empty()) {
                return false;
            }
            for (char c : seg) {
                if (!((c >= 'a' && c <= 'z') || is_digit(c) || c == '-')) {
                    return false;
                }
            }
            return true;
        }
    }
    return false;
}

std::string_view label(TokenId id)
{
    switch (id) {
        case TokenId::kPid:
            return "pid";
        case TokenId::kTid:
            return "tid";
        case TokenId::kUid:
            return "uid";
        case TokenId::kFd:
            return "fd";
        case TokenId::kN:
            return "n";
        case TokenId::kUuid:
            return "uuid";
        case TokenId::kHex64:
            return "hex64";
        case TokenId::kPci:
            return "pci";
        case TokenId::kUsb:
            return "usb";
        case TokenId::kIface:
            return "iface";
        case TokenId::kDevice:
            return "device";
        case TokenId::kId:
            return "id";
    }
    return "";
}

bool is_uuid(std::string_view seg)
{
    // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx，兼容大小写（blkid 输出大写）
    if (seg.size() != 36) {
        return false;
    }
    const size_t dash_pos[] = {8, 13, 18, 23};
    size_t prev             = 0;
    for (int d = 0; d < 4; ++d) {
        size_t p = dash_pos[d];
        if (seg[p] != '-' || !all_hex(seg.substr(prev, p - prev))) {
            return false;
        }
        prev = p + 1;
    }
    return all_hex(seg.substr(prev));
}

bool is_hex_ge32(std::string_view seg) { return seg.size() >= 32 && all_hex(seg); }

bool is_random_like(std::string_view seg)
{
    // 稳定基线要求：/tmp 族文件多为临时机器名，名字有随机性即应通配为 *
    return all_digits(seg) || is_uuid(seg) || is_hex_ge32(seg) || (has_digit(seg) && has_letter(seg)) ||
           letters_no_vowel_long(seg);
}

bool systemd_instance(std::string_view seg, std::string& out)
{
    // name@<digits>.<unit>，实例部分必须是数字
    size_t at = seg.find('@');
    if (at == std::string_view::npos || at == 0) {
        return false;
    }
    size_t dot = seg.rfind('.');
    if (dot == std::string_view::npos || dot <= at + 1) {
        return false;
    }
    if (!all_digits(seg.substr(at + 1, dot - at - 1))) {
        return false;
    }
    std::string_view ext = seg.substr(dot + 1);
    bool known           = false;
    for (std::string_view u : kSystemdUnits) {
        if (u == ext) {
            known = true;
            break;
        }
    }
    if (!known) {
        return false;
    }
    out.assign(seg.substr(0, at));
    out += "@{n}.";
    out += ext;
    return true;
}

}  // namespace path
}  // namespace hng

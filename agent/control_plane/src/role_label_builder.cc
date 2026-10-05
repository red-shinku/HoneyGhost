#include "agent/control_plane/src/role_label_builder.hpp"

namespace {

/// 取字典里该键的非空值；键不存在或值为空时返回空串
std::string attribute(const hng::role::RoleIdentity& identity, const char* key)
{
    auto it = identity.attributes.find(key);
    return it == identity.attributes.end() ? std::string() : it->second;
}

}  // namespace

hng::role_label_t RoleLabelBuilder::build(const hng::role::RoleIdentity& identity)
{
    switch (identity.source) {
        case hng::role::RoleSource::SYSTEMD:
            return identity.instance_key;
        case hng::role::RoleSource::CONTAINERD: {
            const std::string image = attribute(identity, "image");
            return image.empty() ? identity.type_key : image;
        }
        case hng::role::RoleSource::UNSPECIFIED:
            break;
    }
    return identity.type_key;
}

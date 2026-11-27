// SPDX-License-Identifier: Apache-2.0
#include "fusehide/policy/data_path.hpp"

#include <unistd.h>

#ifndef NDEBUG
#include <android/log.h>
#endif

#include <charconv>
#include <mutex>
#include <shared_mutex>

namespace fusehide::data_path {
namespace {
constexpr uint32_t kPerUserRange = 100000;
Owners packageOwners;
std::shared_mutex ownersMutex;
}  // namespace

void ReplaceOwners(Owners owners) {
    std::unique_lock lock(ownersMutex);
    packageOwners.swap(owners);
#ifndef NDEBUG
    __android_log_print(ANDROID_LOG_INFO, "FuseHideProbe",
                        "owner snapshot refreshed test.one=%d test.oneplus=%d",
                        packageOwners.contains("dev.fuseprobe.one"),
                        packageOwners.contains("dev.fuseprobe.oneplus"));
#endif
}

std::optional<uint32_t> PackageUid(std::string_view path, [[maybe_unused]] uint32_t caller,
                                   [[maybe_unused]] const char* operation) {
    [[maybe_unused]] const auto absolutePath = path;
    constexpr std::string_view prefix = "/storage/emulated/";
    if (!path.starts_with(prefix))
        return {};
    path.remove_prefix(prefix.size());
    const auto slash = path.find('/');
    if (slash == path.npos)
        return {};
    uint32_t user;
    const auto end = path.data() + slash;
    const auto parsed = std::from_chars(path.data(), end, user);
    if (parsed.ec != std::errc{} || parsed.ptr != end)
        return {};
    path.remove_prefix(slash + 1);
    constexpr std::string_view data = "Android/data/", obb = "Android/obb/";
    if (path.starts_with(data))
        path.remove_prefix(data.size());
    else if (path.starts_with(obb))
        path.remove_prefix(obb.size());
    else
        return {};
    const auto package = path.substr(0, path.find('/'));
    std::shared_lock lock(ownersMutex);
    const auto it = packageOwners.find(package);
    std::optional<uint32_t> owner;
    if (it != packageOwners.end() && it->second / kPerUserRange == user)
        owner = it->second;
#ifndef NDEBUG
    if (package == "dev.fuseprobe.one" || package == "dev.fuseprobe.oneplus" ||
        package == "dev.fuseprobe.shared.one" || package == "dev.fuseprobe.shared.oneplus") {
        __android_log_print(ANDROID_LOG_INFO, "FuseHideProbe",
                            "op=%s caller=%u owner=%d decision=%s path=%.*s", operation, caller,
                            owner ? static_cast<int>(*owner) : -1,
                            HideFrom(caller, owner) ? "hide" : "delegate",
                            static_cast<int>(absolutePath.size()), absolutePath.data());
    }
#endif
    return owner;
}

bool HideFrom(uint32_t caller, std::optional<uint32_t> owner) {
    // MediaProvider itself is explicitly trusted by its stock access gate.
    static const uid_t providerUid = getuid();
    const auto appId = caller % kPerUserRange;
    return owner && caller != providerUid && appId >= 10000 && appId <= 19999 && appId != *owner % kPerUserRange;
}

}  // namespace fusehide::data_path

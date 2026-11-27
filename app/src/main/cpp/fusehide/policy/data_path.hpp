// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace fusehide::data_path {

using Owners = std::map<std::string, uint32_t, std::less<>>;
void ReplaceOwners(Owners owners);
std::optional<uint32_t> PackageUid(std::string_view path, uint32_t caller, const char* operation);
bool HideFrom(uint32_t caller, std::optional<uint32_t> owner);

}  // namespace fusehide::data_path

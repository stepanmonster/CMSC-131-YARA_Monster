/*
 * YARA monster (c) 2025 Stefan Niedes and Dale Louize Almonia
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace traverse {
    // Recursively collect regular files under root; if exts is empty, take all.
    std::vector<std::filesystem::path>
    list_files(const std::filesystem::path& root,
               const std::vector<std::string>& exts = {});
}

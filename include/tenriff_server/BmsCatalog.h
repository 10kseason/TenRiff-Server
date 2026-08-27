#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace tenriff::server {

struct BmsCatalogEntry {
    std::string chart_sha256;
    std::string chart_path;
};

struct BmsCatalogLoadResult {
    std::vector<BmsCatalogEntry> charts;
    std::size_t excluded_count = 0;
    std::size_t duplicate_count = 0;
    std::size_t skipped_symlink_count = 0;
};

[[nodiscard]] bool load_bms_catalog(
    const std::filesystem::path& chart_root,
    const std::filesystem::path& excluded_chart_file,
    BmsCatalogLoadResult& result,
    std::string& error);

}  // namespace tenriff::server

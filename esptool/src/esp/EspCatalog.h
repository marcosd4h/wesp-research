#pragma once

#include <array>

namespace esptool::esp {

inline constexpr auto kTypedFilterExports = std::to_array<const char*>({
    "",
    "EspCreateClientFilter",
    "EspCreateDesktopFilter",
    "EspCreateDiskFilter",
    "EspCreateEventFilter",
    "EspCreateFileFilter",
    "EspCreateFileObjectFilter",
    "EspCreateFileStreamFilter",
    "EspCreateRegistryKeyFilter",
    "EspCreateRegistryKeyObjectFilter",
    "EspCreateProcessFilter",
    "EspCreateThreadFilter",
    "EspCreateTokenFilter",
    "EspCreateVolumeFilter",
    "EspCreatePipeFilter",
    "EspCreateMailslotFilter",
    "EspCreateKtmTransactionFilter",
});

inline constexpr auto kPropertyQueryExports = std::to_array<const char*>({
    "EspQueryClientProperties",
    "EspQueryDesktopProperties",
    "EspQueryDiskProperties",
    "EspQueryFileObjectProperties",
    "EspQueryFileProperties",
    "EspQueryFileStreamProperties",
    "EspQueryKtmTransactionProperties",
    "EspQueryMailslotProperties",
    "EspQueryPipeProperties",
    "EspQueryProcessProperties",
    "EspQueryRegistryKeyObjectProperties",
    "EspQueryRegistryKeyProperties",
    "EspQueryThreadProperties",
    "EspQueryTokenProperties",
    "EspQueryVolumeProperties",
});

}  // namespace esptool::esp

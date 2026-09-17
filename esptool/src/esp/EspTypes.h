#pragma once

#include <type_traits>

#include "esp/EspCore.h"
#include "esp/EspEventIds.h"
#include "esp/EspFilterAbi.h"
#include "esp/EspIoConfigAbi.h"
#include "esp/EspNotifyAbi.h"
#include "esp/EspRuleAbi.h"

namespace esptool::esp {

using RawExportFn = std::int64_t(__fastcall*)(std::uintptr_t, std::uintptr_t,
                                              std::uintptr_t, std::uintptr_t);

static_assert(kProcessQueryCountRequired <=
              std::extent_v<decltype(PropertyQueryStore::process_ids)>);

}  // namespace esptool::esp

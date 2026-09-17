#pragma once

#include "esp/EspTypes.h"

namespace esptool::esp {

template <class... Args>
using EspCall = EspResult(__fastcall*)(Args...);

using UnaryObjectFn = EspCall<void*>;
using CloseOutFn = EspCall<void**>;

using ConnectClientFn = EspCall<Guid*, void**>;
using DisconnectClientFn = CloseOutFn;
using RegisterClientFn = EspCall<ClientRegisterDescriptor*>;
using UnregisterClientFn = EspCall<Guid*>;
using EnumerateClientsFn = EspCall<int*, void**>;
using QueryClientDescriptorFn = EspCall<Guid*, void**>;

using CreateEventQueueFn = EspCall<void**, void*, void**>;
using OpenEventQueueFn = EspCall<void**, Guid*, void**>;
using CloseEventQueueFn = CloseOutFn;
using DisconnectEventQueueFn = CloseOutFn;
using ConnectQueueIocpFn = EspCall<void**, void*, void**>;
using ConnectQueueCallbackFn = EspCall<void**, void*, void*, void*>;
using SetStateChangeCallbackFn = EspCall<void**, void*, void*, char, char>;
using RemoveStateChangeCallbackFn = CloseOutFn;
using GetEventQueueIdFn = EspCall<void**, Guid*>;
using EnumerateEventQueueIdsFn = EspCall<void*, int, int*, void**>;

using AllocateNotificationFn = void*(__stdcall*)();
using ArmNotificationFn = EspCall<void**, void*>;
using CompleteNotificationFn = UnaryObjectFn;
using FreeNotificationFn = UnaryObjectFn;
using ClearEventQueueFn = CloseOutFn;
using GetEventCapabilitiesFn = EspCall<void*, int, int*>;

using CreateFilterFn = EspCall<int, void*, void**>;
using CreateTypedFilterFn = EspCall<int, int, void*, void**>;
using CreateBinaryFilterFn = EspCall<void**, void**, void**>;
using CreateNotFilterFn = EspCall<void**, void**>;
using CloseFilterFn = CloseOutFn;

using CreateRuleFn = EspCall<RuleDescriptor*, void**>;
using CloseRuleFn = CloseOutFn;
using UpdateRulesFn =
    EspCall<void**, unsigned, unsigned, const RuleUpdateEntry*>;
using EnumerateRuleIdsFn = EspCall<void*, int, int*, void**>;
using EnumerateAllRulesFn = EspCall<void*, int*, void**>;
using GetRuleIdFn = EspCall<void*, Guid*>;
using RemoveRulesFn = EspCall<void*, int>;
using RemoveAllRulesFn = UnaryObjectFn;

using CreateReferenceFn = EspCall<void*, void*, void**>;
using CreateObjectReferenceFn = EspCall<void*, void**>;
using CreateReferenceByIdFn = EspCall<void*, void*, void*, void**>;
using CreateReferenceByPathFn = EspCall<void*, void*, void**>;
using CreatePidReferenceFn = EspCall<void**, int, void**>;
using CreatePathDescriptorReferenceFn = EspCall<void**, void*, void**>;
using CreateFileIdReferenceFn = EspCall<void**, void*, void*, void**>;
using CreateStreamByIdFn = EspCall<void**, void*, void*, const wchar_t*, void**>;
using CreateEventByIdFn = EspCall<void**, std::uint64_t, void**>;
using CreateVolumeReferenceFn = EspCall<void**, Guid*, void**>;
using CreateDesktopReferenceFn = EspCall<void**, const wchar_t*, void**>;
using CloseReferenceFn = CloseOutFn;
using DuplicateReferenceFn = EspCall<void**, void**>;
using GetEventObjectFn = EspCall<void**, void**>;
using GetEventObjectIdFn = EspCall<void*, void*>;
using GetEventObjectTypeFn = EspCall<void*, int*>;

using QueryPropertiesFn = EspCall<void**, unsigned, const unsigned*, void*>;
using IsPropertySupportedFn = EspCall<void*, unsigned, void*>;

using CreateCollectionFn = EspCall<void**, void*, void**>;
using OpenCollectionFn = EspCall<void*, Guid*, void**>;
using CloseCollectionFn = CloseOutFn;
using UpdateCollectionFn = EspCall<void**, unsigned, unsigned, void*>;
using EnumerateCollectionEntriesFn = EspCall<void**, int*, void**>;
using EnumerateCollectionIdsFn = EspCall<void*, int, int*, void**>;
using GetCollectionIdFn = EspCall<void**, Guid*>;
using GetCollectionTypeFn = EspCall<void**, int*>;

using SetContextKeyFn = EspCall<void**, void*>;
using EnumerateContextKeysFn = EspCall<void**, int*, void**>;

using InitUnicodeStringFn = EspCall<void*, void*>;
using StringMatchesPatternFn = EspCall<void*, void*, void*>;
using FreeMemoryFn = UnaryObjectFn;

}  // namespace esptool::esp

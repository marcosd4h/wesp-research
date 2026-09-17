// XmlLite rule parser. Empty <rule .../> has no EndElement. Unknown event=
// becomes 0 and is not a parse error.

#include "model/RuleParser.h"

#include <Windows.h>
#include <shlwapi.h>
#include <wrl/client.h>
#include <xmllite.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <ranges>
#include <string_view>
#include <utility>
#include <vector>

#include "esp/EspFilterAbi.h"
#include "esp/EspRefAbi.h"
#include "esp/EspTypes.h"
#include "util/StrHelpers.h"
#include "util/UniqueWin.h"

#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "shlwapi.lib")

namespace esptool::model {
namespace {

using Microsoft::WRL::ComPtr;

constexpr std::size_t kMaxDepth = 16;
constexpr std::uint64_t kMaxRuleFileBytes = 64 * 1024 * 1024;

[[nodiscard]] HRESULT MakeXmlReader(ComPtr<IXmlReader>& reader) noexcept {
  return CreateXmlReader(__uuidof(IXmlReader),
                         reinterpret_cast<void**>(reader.GetAddressOf()),
                         nullptr);
}

[[nodiscard]] ComPtr<IStream> MemoryStream(std::string_view text) {
  ComPtr<IStream> stream;
  stream.Attach(SHCreateMemStream(reinterpret_cast<const BYTE*>(text.data()),
                                  static_cast<UINT>(text.size())));
  return stream;
}

[[nodiscard]] std::string MakeError(std::string_view message,
                                    std::uint32_t line) {
  if (line == 0) {
    return std::string(message);
  }
  return std::format("{} (line {})", message, line);
}

class AttributeReader {
 public:
  explicit AttributeReader(IXmlReader& reader) : reader_(reader) {}

  void Collect() {
    items_.clear();
    if (reader_.MoveToFirstAttribute() != S_OK) {
      return;
    }
    do {
      const wchar_t* name = nullptr;
      const wchar_t* value = nullptr;
      if (reader_.GetLocalName(&name, nullptr) == S_OK &&
          reader_.GetValue(&value, nullptr) == S_OK && name != nullptr &&
          value != nullptr) {
        items_.emplace_back(text::ToLowerAscii(text::ToUtf8(name)),
                            text::ToUtf8(value));
      }
    } while (reader_.MoveToNextAttribute() == S_OK);
    reader_.MoveToElement();
  }

  [[nodiscard]] const std::string* Find(std::string_view name) const noexcept {
    const auto found = std::ranges::find_if(
        items_, [&](const auto& item) { return item.first == name; });
    return found == items_.end() ? nullptr : &found->second;
  }

  [[nodiscard]] std::string Get(std::string_view name,
                                std::string_view fallback = {}) const {
    const std::string* value = Find(name);
    return value != nullptr ? *value : std::string(fallback);
  }

 private:
  IXmlReader& reader_;
  std::vector<std::pair<std::string, std::string>> items_;
};

[[nodiscard]] bool ParseSigned32(std::string_view text,
                                 std::int32_t& out) noexcept {
  std::uint64_t parsed = 0;
  if (text.empty()) {
    return false;
  }
  bool negative = text.front() == '-';
  const std::string_view body = negative ? text.substr(1) : text;
  if (!text::ParseUnsigned(body, parsed)) {
    return false;
  }
  if (negative ? parsed > (1ull << 31)
               : parsed > static_cast<std::uint64_t>(
                              std::numeric_limits<std::int32_t>::max())) {
    return false;
  }
  out = negative
            ? static_cast<std::int32_t>(0u - static_cast<std::uint32_t>(parsed))
            : static_cast<std::int32_t>(parsed);
  return true;
}

[[nodiscard]] bool ParseUnsigned32(std::string_view text,
                                   std::uint32_t& out) noexcept {
  std::uint64_t parsed = 0;
  if (!text::ParseUnsigned(text, parsed) ||
      parsed > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  out = static_cast<std::uint32_t>(parsed);
  return true;
}

[[nodiscard]] bool ParseUnsigned64(std::string_view text,
                                   std::uint64_t& out) noexcept {
  return text::ParseUnsigned(text, out);
}

// Closed set: processcreate, filecreate/fo_create, regcreatekey. Any other
// event= name becomes 0 and is not a parse error; InstallRules then skips that
// rule.
constexpr std::string_view kDocumentRoot = "esptool";

[[nodiscard]] std::uint32_t EventTypeFromName(std::string_view name) noexcept {
  if (text::EqualsIgnoreCase(name, "processcreate")) {
    return esp::kEventProcessCreate;
  }
  if (text::EqualsIgnoreCase(name, "filecreate") ||
      text::EqualsIgnoreCase(name, "fo_create")) {
    return esp::kEventFoCreate;
  }
  if (text::EqualsIgnoreCase(name, "regcreatekey")) {
    return esp::kEventRegCreateKey;
  }
  return 0;
}

[[nodiscard]] std::optional<std::string> LocalNameLower(IXmlReader& reader) {
  const wchar_t* raw_name = nullptr;
  if (reader.GetLocalName(&raw_name, nullptr) != S_OK || raw_name == nullptr) {
    return std::nullopt;
  }
  return text::ToLowerAscii(text::ToUtf8(raw_name));
}

[[nodiscard]] std::optional<FilterKind> FilterKindFromTag(
    std::string_view name) noexcept {
  if (name == "and") {
    return FilterKind::And;
  }
  if (name == "or") {
    return FilterKind::Or;
  }
  if (name == "xor") {
    return FilterKind::Xor;
  }
  if (name == "not") {
    return FilterKind::Not;
  }
  return std::nullopt;
}

class DocumentParser {
 public:
  explicit DocumentParser(std::string text) : text_(std::move(text)) {}

  [[nodiscard]] ParseOutcome Run() {
    UniqueComApartment apartment;
    if (!apartment.usable()) {
      ParseOutcome outcome;
      outcome.error = "COM initialization failed";
      return outcome;
    }
    return Parse();
  }

 private:
  [[nodiscard]] ParseOutcome Parse() {
    ParseOutcome outcome;

    ComPtr<IStream> stream = MemoryStream(text_);
    if (!stream) {
      outcome.error = "could not create an input stream for the rule document";
      return outcome;
    }

    ComPtr<IXmlReader> reader;
    if (FAILED(MakeXmlReader(reader))) {
      outcome.error = "could not create the XML reader";
      return outcome;
    }
    if (FAILED(reader->SetInput(stream.Get()))) {
      outcome.error = "could not bind the rule document to the XML reader";
      return outcome;
    }

    std::vector<FilterNode> stack;
    std::vector<FilterNode> roots;
    RuleSpec* current_rule = nullptr;
    CollectionSpec* current_collection = nullptr;
    bool in_entry = false;
    std::string entry_text;
    bool saw_root = false;
    bool root_closed = false;

    XmlNodeType node_type = XmlNodeType_None;
    HRESULT read_result = S_OK;
    while ((read_result = reader->Read(&node_type)) == S_OK) {
      if (node_type == XmlNodeType_Element) {
        const std::optional<std::string> decoded =
            LocalNameLower(*reader.Get());
        if (!decoded) {
          continue;
        }
        const std::string& name = *decoded;
        AttributeReader attributes(*reader.Get());
        attributes.Collect();
        std::uint32_t line = 0;
        reader->GetLineNumber(&line);

        if (!saw_root) {
          if (name != kDocumentRoot) {
            outcome.error = MakeError("root element must be <esptool>", line);
            return outcome;
          }
          saw_root = true;
          continue;
        }

        if (name == "client") {
          if (!ParseClient(attributes, outcome.document.client, outcome.error,
                           line)) {
            return outcome;
          }
        } else if (name == "rule") {
          if (current_rule != nullptr) {
            outcome.error = MakeError("<rule> cannot be nested", line);
            return outcome;
          }
          outcome.document.rules.emplace_back();
          current_rule = &outcome.document.rules.back();
          if (!ParseRuleAttributes(attributes, *current_rule, outcome.error,
                                   line)) {
            return outcome;
          }
          stack.clear();
          roots.clear();
          // XmlLite does not emit EndElement for <rule .../>.
          if (reader->IsEmptyElement()) {
            FinalizeRule(*current_rule, roots);
            current_rule = nullptr;
          }
        } else if (name == "collections") {
          if (current_rule != nullptr) {
            outcome.error =
                MakeError("<collections> cannot appear inside <rule>", line);
            return outcome;
          }
        } else if (name == "collection") {
          if (current_rule != nullptr) {
            outcome.error =
                MakeError("<collection> cannot appear inside <rule>", line);
            return outcome;
          }
          outcome.document.collections.emplace_back();
          current_collection = &outcome.document.collections.back();
          if (!ParseCollectionAttributes(attributes, *current_collection,
                                         outcome.error, line)) {
            return outcome;
          }
          if (reader->IsEmptyElement()) {
            current_collection = nullptr;
          }
        } else if (name == "entry") {
          if (current_collection == nullptr) {
            outcome.error =
                MakeError("<entry> must appear inside <collection>", line);
            return outcome;
          }
          in_entry = true;
          entry_text.clear();
          if (reader->IsEmptyElement()) {
            current_collection->entries.emplace_back();
            in_entry = false;
          }
        } else if (name == "query") {
          if (current_rule == nullptr) {
            outcome.error =
                MakeError("<query> must appear inside <rule>", line);
            return outcome;
          }
          QueryRecipe recipe;
          if (!ParseQueryAttributes(attributes, recipe, outcome.error, line)) {
            return outcome;
          }
          current_rule->queries.push_back(std::move(recipe));
        } else if (name == "filter") {
          if (current_rule == nullptr) {
            outcome.error =
                MakeError("<filter> must appear inside <rule>", line);
            return outcome;
          }
          FilterNode leaf;
          leaf.kind = FilterKind::Leaf;
          if (!ParseLeafAttributes(attributes, leaf, outcome.error, line)) {
            return outcome;
          }
          Append(stack, roots, std::move(leaf));
        } else if (const std::optional<FilterKind> kind =
                       FilterKindFromTag(name)) {
          if (current_rule == nullptr) {
            outcome.error = MakeError(
                std::format("<{}> must appear inside <rule>", name), line);
            return outcome;
          }
          if (stack.size() >= kMaxDepth) {
            outcome.error = MakeError("filter nesting is too deep", line);
            return outcome;
          }
          FilterNode node;
          node.kind = *kind;
          stack.push_back(std::move(node));
          if (reader->IsEmptyElement()) {
            FilterNode empty = std::move(stack.back());
            stack.pop_back();
            Append(stack, roots, std::move(empty));
          }
        }
        // Unknown elements are ignored so the schema can grow.
      } else if (node_type == XmlNodeType_EndElement) {
        const std::optional<std::string> decoded =
            LocalNameLower(*reader.Get());
        if (!decoded) {
          continue;
        }
        const std::string& name = *decoded;
        if (FilterKindFromTag(name)) {
          if (stack.empty()) {
            std::uint32_t line = 0;
            reader->GetLineNumber(&line);
            outcome.error = MakeError("mismatched </" + name + ">", line);
            return outcome;
          }
          FilterNode node = std::move(stack.back());
          stack.pop_back();
          Append(stack, roots, std::move(node));
        } else if (name == "rule") {
          if (current_rule != nullptr) {
            FinalizeRule(*current_rule, roots);
            roots.clear();
            current_rule = nullptr;
          }
        } else if (name == "entry") {
          if (current_collection != nullptr && in_entry) {
            current_collection->entries.push_back(std::move(entry_text));
          }
          in_entry = false;
          entry_text.clear();
        } else if (name == "collection") {
          current_collection = nullptr;
        } else if (name == kDocumentRoot) {
          root_closed = true;
        }
      } else if (node_type == XmlNodeType_Text ||
                 node_type == XmlNodeType_Whitespace) {
        if (in_entry) {
          const wchar_t* value = nullptr;
          if (reader->GetValue(&value, nullptr) == S_OK && value != nullptr) {
            entry_text.append(text::ToUtf8(value));
          }
        }
      }
    }

    if (!saw_root) {
      outcome.error = "the rule document is empty";
      return outcome;
    }
    if (read_result != S_FALSE) {
      outcome.error = "the XML document is not well formed";
      return outcome;
    }
    if (!root_closed) {
      outcome.error = "the <esptool> root element is not closed";
      return outcome;
    }
    if (current_rule != nullptr) {
      outcome.error = "unterminated <rule> element";
      return outcome;
    }
    outcome.ok = true;
    return outcome;
  }

  static void Append(std::vector<FilterNode>& stack,
                     std::vector<FilterNode>& roots, FilterNode node) {
    if (stack.empty()) {
      roots.push_back(std::move(node));
    } else {
      stack.back().children.push_back(std::move(node));
    }
  }

  // Multiple top-level predicates become one And. CreateFilterTree only uses
  // children[0] and [1]; further siblings are stored and not sent.
  static void FinalizeRule(RuleSpec& rule, std::vector<FilterNode>& roots) {
    if (roots.empty()) {
      rule.filter = FilterNode{};
      return;
    }
    if (roots.size() == 1) {
      rule.filter = std::move(roots.front());
      return;
    }
    FilterNode combined;
    combined.kind = FilterKind::And;
    combined.children = std::move(roots);
    rule.filter = std::move(combined);
  }

  static bool ParseClient(const AttributeReader& attributes, ClientSpec& client,
                          std::string& error, std::uint32_t line) {
    client.name = attributes.Get("name", client.name);
    client.altitude = attributes.Get("altitude", client.altitude);
    const std::string guid = attributes.Get("guid");
    if (!guid.empty()) {
      std::array<std::uint8_t, text::kGuidOctets> bytes{};
      if (!text::ParseGuid(guid, bytes)) {
        error = MakeError("client guid is not a valid GUID", line);
        return false;
      }
      client.guid = std::bit_cast<esp::Guid>(bytes);
      client.hasGuid = true;
    }
    return true;
  }

  static bool ParseRuleAttributes(const AttributeReader& attributes,
                                  RuleSpec& rule, std::string& error,
                                  std::uint32_t line) {
    rule.name = attributes.Get("name");
    rule.eventName = attributes.Get("event");
    if (const std::string* value = attributes.Find("eventtype");
        value != nullptr) {
      if (!ParseUnsigned32(*value, rule.eventType)) {
        error = MakeError("rule eventType is not a number", line);
        return false;
      }
    } else if (!rule.eventName.empty()) {
      rule.eventType = EventTypeFromName(rule.eventName);
    }
    const std::string lifetime = attributes.Get("lifetime");
    if (!lifetime.empty()) {
      if (text::EqualsIgnoreCase(lifetime, "persistent")) {
        rule.lifetime = RuleLifetime::Persistent;
      } else if (text::EqualsIgnoreCase(lifetime, "transient")) {
        rule.lifetime = RuleLifetime::Transient;
      } else {
        error =
            MakeError("rule lifetime must be persistent or transient", line);
        return false;
      }
    }
    if (const std::string* value = attributes.Find("flags"); value != nullptr) {
      if (!ParseUnsigned32(*value, rule.flags)) {
        error = MakeError("rule flags is not a number", line);
        return false;
      }
    }
    if (const std::string* value = attributes.Find("action");
        value != nullptr) {
      rule.action = 0;
      if (!ParseUnsigned64(*value, rule.action)) {
        // Named actions carry enforcement semantics. A numeric action is the
        // raw selector and stays available for experiments.
        if (*value == "deny" || *value == "suppress") {
          rule.actionName = *value;
        } else {
          error = MakeError(
              "rule action is not a number or a known action name "
              "(deny, suppress)",
              line);
          return false;
        }
      }
    }
    if (const std::string* value = attributes.Find("selector");
        value != nullptr) {
      std::uint32_t selector = 0;
      if (!ParseUnsigned32(*value, selector)) {
        error = MakeError("rule selector is not a number", line);
        return false;
      }
      rule.selector_override = selector;
    }
    if (const std::string* value = attributes.Find("modifier");
        value != nullptr) {
      std::uint32_t modifier = 0;
      if (!ParseUnsigned32(*value, modifier)) {
        error = MakeError("rule modifier is not a number", line);
        return false;
      }
      rule.modifier_override = modifier;
    }
    if (const std::string* value = attributes.Find("modifykind");
        value != nullptr) {
      std::uint32_t kind = 0;
      if (!ParseUnsigned32(*value, kind)) {
        error = MakeError("rule modifyKind is not a number", line);
        return false;
      }
      rule.modify_kind_override = kind;
    }
    if (const std::string* value = attributes.Find("disposition");
        value != nullptr) {
      if (text::EqualsIgnoreCase(*value, "access_denied") ||
          text::EqualsIgnoreCase(*value, "denied") ||
          text::EqualsIgnoreCase(*value, "accessdenied")) {
        rule.modify_kind_override = 2;
      } else if (text::EqualsIgnoreCase(*value, "not_found") ||
                 text::EqualsIgnoreCase(*value, "notfound")) {
        rule.modify_kind_override = 3;
      } else if (text::EqualsIgnoreCase(*value, "virus") ||
                 text::EqualsIgnoreCase(*value, "virus_infected")) {
        rule.modify_kind_override = 1;
      } else {
        std::uint32_t disp = 0;
        if (!ParseUnsigned32(*value, disp) || disp < 1 || disp > 5) {
          error = MakeError(
              "rule disposition must be access_denied, not_found, virus, or a "
              "number 1..5",
              line);
          return false;
        }
        rule.modify_kind_override = disp;
      }
    }
    return true;
  }

  static bool ParseLeafAttributes(const AttributeReader& attributes,
                                  FilterNode& leaf, std::string& error,
                                  std::uint32_t line) {
    if (const std::string* value = attributes.Find("type"); value != nullptr) {
      if (!ParseSigned32(*value, leaf.type)) {
        error = MakeError("filter type is not a number", line);
        return false;
      }
    }
    if (const std::string* value = attributes.Find("comparand");
        value != nullptr) {
      if (!ParseSigned32(*value, leaf.comparand)) {
        error = MakeError("filter comparand is not a number", line);
        return false;
      }
    }
    if (const std::string* value = attributes.Find("operand");
        value != nullptr) {
      if (!ParseUnsigned64(*value, leaf.operand)) {
        error = MakeError("filter operand is not a number", line);
        return false;
      }
    }
    if (const std::string* value = attributes.Find("property");
        value != nullptr) {
      if (!ParseUnsigned32(*value, leaf.propertyId)) {
        error = MakeError("filter property is not a number", line);
        return false;
      }
    }
    leaf.propertyName = attributes.Get("propertyname");
    leaf.opName = attributes.Get("op");
    leaf.value = attributes.Get("value");
    leaf.collectionName = attributes.Get("collection");
    if (!leaf.collectionName.empty() && leaf.comparand == 0) {
      leaf.comparand =
          static_cast<std::int32_t>(esp::kStringComparandCollection);
    }
    return true;
  }

  static bool ParseCsvUnsigned(std::string_view text,
                               std::vector<unsigned>& out, std::string& error,
                               std::uint32_t line) {
    out.clear();
    for (const std::string& part : text::Split(text, ',')) {
      const std::string_view trimmed = text::Trim(part);
      std::uint64_t parsed = 0;
      if (!text::ParseUnsigned(trimmed, parsed) ||
          parsed > std::numeric_limits<unsigned>::max()) {
        error = MakeError("query properties must be unsigned integers", line);
        return false;
      }
      out.push_back(static_cast<unsigned>(parsed));
    }
    return true;
  }

  static bool ParseQueryAttributes(const AttributeReader& attributes,
                                   QueryRecipe& recipe, std::string& error,
                                   std::uint32_t line) {
    recipe.kind = text::ToLowerAscii(attributes.Get("kind"));
    if (recipe.kind.empty()) {
      error = MakeError("query kind is required", line);
      return false;
    }
    if (SupportExportForKindMissing(recipe.kind)) {
      error = MakeError("query kind is not recognized", line);
      return false;
    }
    const std::string properties = attributes.Get("properties");
    if (!properties.empty() &&
        !ParseCsvUnsigned(properties, recipe.properties, error, line)) {
      return false;
    }
    const std::string context = text::ToLowerAscii(attributes.Get("context"));
    for (const std::string& part : text::Split(context, ',')) {
      const std::string token = std::string(text::Trim(part));
      if (token == "set") {
        recipe.context_set = true;
      } else if (token == "enum") {
        recipe.context_enum = true;
      } else if (!token.empty()) {
        error = MakeError("query context must be set, enum, or both", line);
        return false;
      }
    }
    return true;
  }

  static bool SupportExportForKindMissing(std::string_view kind) noexcept {
    return esp::SupportExportForKind(kind) == nullptr;
  }

  static bool ParseCollectionType(std::string_view text, std::uint32_t& out,
                                  std::string& error, std::uint32_t line) {
    if (text.empty() || text::EqualsIgnoreCase(text, "string") || text == "2") {
      out = 2;
      return true;
    }
    if (text::EqualsIgnoreCase(text, "integer") || text == "1") {
      out = 1;
      return true;
    }
    if (text::EqualsIgnoreCase(text, "binary") || text == "3") {
      out = 3;
      return true;
    }
    error =
        MakeError("collection type must be integer, string, or binary", line);
    return false;
  }

  static bool ParseCollectionAttributes(const AttributeReader& attributes,
                                        CollectionSpec& spec,
                                        std::string& error,
                                        std::uint32_t line) {
    spec.name = attributes.Get("name");
    if (!ParseCollectionType(attributes.Get("type"), spec.type, error, line)) {
      return false;
    }
    const std::string open = text::ToLowerAscii(attributes.Get("open"));
    spec.open = open == "true" || open == "1";
    const std::string guid = attributes.Get("guid");
    if (!guid.empty()) {
      std::array<std::uint8_t, text::kGuidOctets> bytes{};
      if (!text::ParseGuid(guid, bytes)) {
        error = MakeError("collection guid is not a valid GUID", line);
        return false;
      }
      spec.guid = std::bit_cast<esp::Guid>(bytes);
      spec.hasGuid = true;
    }
    if (spec.open && !spec.hasGuid) {
      error = MakeError("open=\"true\" requires guid", line);
      return false;
    }
    return true;
  }

  std::string text_;
};

}  // namespace

ParseOutcome ParseRuleText(std::string utf8Text) {
  DocumentParser parser(std::move(utf8Text));
  return parser.Run();
}

ParseOutcome ParseRuleFile(std::string_view utf8Path) {
  ParseOutcome outcome;
  const std::wstring wide_path = text::ToUtf16(utf8Path);
  UniqueHandle file(CreateFileW(wide_path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file) {
    outcome.error =
        text::Win32Message("could not open the rule file", GetLastError());
    return outcome;
  }
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 ||
      size.QuadPart > static_cast<LONGLONG>(kMaxRuleFileBytes)) {
    outcome.error = "the rule file is empty or too large";
    return outcome;
  }
  std::string contents(static_cast<std::size_t>(size.QuadPart), '\0');
  DWORD read = 0;
  const BOOL ok = ReadFile(file.get(), contents.data(),
                           static_cast<DWORD>(contents.size()), &read, nullptr);
  if (!ok) {
    outcome.error =
        text::Win32Message("could not read the rule file", GetLastError());
    return outcome;
  }
  contents.resize(read);

  ParseOutcome parsed = ParseRuleText(std::move(contents));
  if (parsed.ok) {
    parsed.document.sourcePath = utf8Path;
  }
  return parsed;
}

}  // namespace esptool::model

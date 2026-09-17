#pragma once

// XmlLite parse of this-tool rule XML. type= is a constructor-table index,
// not FilterType. value= is stored and never read; not a constructor argument.

#include <string>
#include <string_view>

#include "model/RuleDocument.h"

namespace esptool::model {

// Result of parsing a rule file. On failure, error holds a human-readable
// message that names the offending element or attribute and its line number.
struct ParseOutcome {
  bool ok = false;
  RuleDocument document;
  std::string error;
};

// Parses an XML rule document. The parser is strict about numeric attributes:
// a malformed number is reported as an error with its line number. Unknown
// elements are ignored so the schema can grow without breaking older tools.
//
// The numeric fields are authoritative because the corresponding symbolic
// enumerations are not recoverable from the module. String attributes such as
// eventName, typeName, opName, propertyName, and value are labels carried into
// logs and reports.
[[nodiscard]] ParseOutcome ParseRuleFile(std::string_view utf8Path);
[[nodiscard]] ParseOutcome ParseRuleText(std::string utf8Text);

}  // namespace esptool::model

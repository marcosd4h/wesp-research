#include <doctest.h>

#include <array>
#include <bit>
#include <string>
#include <string_view>

#include "TestSupport.h"
#include "esp/EspEventIds.h"
#include "esp/EspFilterAbi.h"
#include "model/RuleParser.h"
#include "util/StrHelpers.h"

using esptool::esp::kCollectionTypeString;
using esptool::esp::kEventFoCreate;
using esptool::esp::kEventProcessCreate;
using esptool::esp::kEventRegCreateKey;
using esptool::esp::kStringComparandCollection;
using esptool::model::FilterKind;
using esptool::model::ParseOutcome;
using esptool::model::ParseRuleFile;
using esptool::model::ParseRuleText;
using esptool::model::RuleLifetime;
using esptool::test::RulesFile;

namespace {

[[nodiscard]] bool Has(const std::string& text, std::string_view needle) {
  return text.find(needle) != std::string::npos;
}

[[nodiscard]] std::string Doc(std::string_view body) {
  std::string xml;
  xml.reserve(body.size() + 20);
  xml += "<esptool>";
  xml += body;
  xml += "</esptool>";
  return xml;
}

[[nodiscard]] ParseOutcome MustOk(std::string xml) {
  ParseOutcome outcome = ParseRuleText(std::move(xml));
  INFO(outcome.error);
  REQUIRE(outcome.ok);
  CHECK(outcome.error.empty());
  return outcome;
}

void MustFail(std::string xml, std::string_view needle) {
  const ParseOutcome outcome = ParseRuleText(std::move(xml));
  REQUIRE_FALSE(outcome.ok);
  CHECK(Has(outcome.error, needle));
}

[[nodiscard]] std::string FormattedGuid(const esptool::esp::Guid& guid) {
  const auto octets = std::bit_cast<std::array<std::uint8_t, 16>>(guid);
  return esptool::text::FormatGuid(octets);
}

}  // namespace

TEST_CASE("ParseRuleText rejects a non-esptool root") {
  MustFail("<rules></rules>", "root element must be <esptool>");
  MustFail("<document><rule name=\"r\" event=\"ProcessCreate\"/></document>",
           "root element must be <esptool>");
}

TEST_CASE("ParseRuleText rejects an empty document") {
  MustFail("", "the rule document is empty");
  MustFail("   \n\t  ", "the rule document is empty");
}

TEST_CASE("ParseRuleText rejects garbage that is not an esptool document") {
  const ParseOutcome text = ParseRuleText("not xml at all");
  REQUIRE_FALSE(text.ok);
  CHECK(text.error == "the rule document is empty");

  const ParseOutcome angles = ParseRuleText("<<<<");
  REQUIRE_FALSE(angles.ok);
  INFO(angles.error);
  CHECK(angles.error == "the rule document is empty");
}

TEST_CASE("ParseRuleText maps ProcessCreate aliases case-insensitively") {
  const auto lower = MustOk(Doc(R"(<rule name="r" event="processcreate"/>)"));
  REQUIRE(lower.document.rules.size() == 1);
  CHECK(lower.document.rules.front().eventType == kEventProcessCreate);

  const auto mixed = MustOk(Doc(R"(<rule name="r" event="ProcessCreate"/>)"));
  REQUIRE(mixed.document.rules.size() == 1);
  CHECK(mixed.document.rules.front().eventType == kEventProcessCreate);

  const auto upper = MustOk(Doc(R"(<rule name="r" event="PROCESSCREATE"/>)"));
  REQUIRE(upper.document.rules.size() == 1);
  CHECK(upper.document.rules.front().eventType == kEventProcessCreate);
}

TEST_CASE("ParseRuleText maps FileCreate and Fo_Create to FoCreate") {
  const auto file_create =
      MustOk(Doc(R"(<rule name="r" event="FileCreate"/>)"));
  REQUIRE(file_create.document.rules.size() == 1);
  CHECK(file_create.document.rules.front().eventType == kEventFoCreate);

  const auto fo_create = MustOk(Doc(R"(<rule name="r" event="Fo_Create"/>)"));
  REQUIRE(fo_create.document.rules.size() == 1);
  CHECK(fo_create.document.rules.front().eventType == kEventFoCreate);

  const auto fo_lower = MustOk(Doc(R"(<rule name="r" event="fo_create"/>)"));
  REQUIRE(fo_lower.document.rules.size() == 1);
  CHECK(fo_lower.document.rules.front().eventType == kEventFoCreate);
}

TEST_CASE("ParseRuleText maps RegCreateKey case-insensitively") {
  const auto mixed = MustOk(Doc(R"(<rule name="r" event="RegCreateKey"/>)"));
  REQUIRE(mixed.document.rules.size() == 1);
  CHECK(mixed.document.rules.front().eventType == kEventRegCreateKey);

  const auto lower = MustOk(Doc(R"(<rule name="r" event="regcreatekey"/>)"));
  REQUIRE(lower.document.rules.size() == 1);
  CHECK(lower.document.rules.front().eventType == kEventRegCreateKey);
}

TEST_CASE("ParseRuleText treats an unknown event name as eventType 0") {
  const auto outcome = MustOk(Doc(R"(<rule name="r" event="ThreadCreate"/>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().eventType == 0);
  CHECK(outcome.document.rules.front().eventName == "ThreadCreate");
}

TEST_CASE("ParseRuleText prefers a numeric eventType over the event name") {
  const auto outcome =
      MustOk(Doc(R"(<rule name="r" event="UnknownEvent" eventType="1000"/>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().eventType == kEventProcessCreate);
}

TEST_CASE("ParseRuleText rejects a non-numeric eventType") {
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate" eventType="not-a-number"/>)"),
      "rule eventType is not a number");
}

TEST_CASE("ParseRuleText accepts persistent and transient lifetimes") {
  const auto persistent = MustOk(
      Doc(R"(<rule name="r" event="ProcessCreate" lifetime="persistent"/>)"));
  REQUIRE(persistent.document.rules.size() == 1);
  CHECK(persistent.document.rules.front().lifetime == RuleLifetime::Persistent);

  const auto transient = MustOk(
      Doc(R"(<rule name="r" event="ProcessCreate" lifetime="TRANSIENT"/>)"));
  REQUIRE(transient.document.rules.size() == 1);
  CHECK(transient.document.rules.front().lifetime == RuleLifetime::Transient);
}

TEST_CASE("ParseRuleText rejects an unknown lifetime") {
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate" lifetime="sticky"/>)"),
           "rule lifetime must be persistent or transient");
}

TEST_CASE("ParseRuleText rejects non-numeric flags and action") {
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate" flags="nope"/>)"),
           "rule flags is not a number");
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate" action="nope"/>)"),
           "rule action is not a number");
}

TEST_CASE("ParseRuleText rejects non-numeric filter selector fields") {
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate"><filter type="x"/></rule>)"),
      "filter type is not a number");
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate"><filter comparand="x"/></rule>)"),
      "filter comparand is not a number");
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate"><filter operand="x"/></rule>)"),
      "filter operand is not a number");
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate"><filter property="x"/></rule>)"),
      "filter property is not a number");
}

TEST_CASE("ParseRuleText stores numeric rule and filter fields") {
  const auto outcome =
      MustOk(Doc(R"(<rule name="r" event="ProcessCreate" flags="8" action="2">)"
                 R"(<filter type="10" comparand="2" operand="7" property="3"/>)"
                 R"(</rule>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  const auto& rule = outcome.document.rules.front();
  CHECK(rule.flags == 8);
  CHECK(rule.action == 2);
  CHECK(rule.filter.kind == FilterKind::Leaf);
  CHECK(rule.filter.type == 10);
  CHECK(rule.filter.comparand == 2);
  CHECK(rule.filter.operand == 7);
  CHECK(rule.filter.propertyId == 3);
}

TEST_CASE("ParseRuleText rejects a nested rule") {
  MustFail(Doc(R"(<rule name="outer" event="ProcessCreate">)"
               R"(<rule name="inner" event="ProcessCreate"/>)"
               R"(</rule>)"),
           "<rule> cannot be nested");
}

TEST_CASE("ParseRuleText requires filter inside a rule") {
  MustFail(Doc(R"(<filter type="10"/><rule name="r" event="ProcessCreate"/>)"),
           "<filter> must appear inside <rule>");
}

TEST_CASE("ParseRuleText missing filter is the empty-filter leaf") {
  const auto outcome = MustOk(Doc(R"(<rule name="r" event="ProcessCreate"/>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().filter.kind == FilterKind::Leaf);
  CHECK(outcome.document.rules.front().filter.type == 0);
  CHECK(outcome.document.rules.front().filter.children.empty());
}

TEST_CASE("ParseRuleText requires query inside a rule") {
  MustFail(Doc(R"(<query kind="process"/>)"),
           "<query> must appear inside <rule>");
}

TEST_CASE("ParseRuleText requires entry inside a collection") {
  MustFail(Doc(R"(<entry>alpha</entry>)"),
           "<entry> must appear inside <collection>");
}

TEST_CASE("ParseRuleText rejects collections inside a rule") {
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate"><collections/></rule>)"),
           "<collections> cannot appear inside <rule>");
}

TEST_CASE("ParseRuleText rejects collection inside a rule") {
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate"><collection name="c"/></rule>)"),
      "<collection> cannot appear inside <rule>");
}

TEST_CASE("ParseRuleText requires a query kind") {
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate"><query/></rule>)"),
           "query kind is required");
}

TEST_CASE("ParseRuleText rejects an unrecognized query kind") {
  MustFail(
      Doc(R"(<rule name="r" event="ProcessCreate"><query kind="not-a-kind"/></rule>)"),
      "query kind is not recognized");
}

TEST_CASE("ParseRuleText parses unsigned query property CSV") {
  const auto outcome =
      MustOk(Doc(R"(<rule name="r" event="ProcessCreate">)"
                 R"(<query kind="process" properties="6,13,2"/>)"
                 R"(</rule>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  REQUIRE(outcome.document.rules.front().queries.size() == 1);
  const auto& query = outcome.document.rules.front().queries.front();
  CHECK(query.kind == "process");
  REQUIRE(query.properties.size() == 3);
  CHECK(query.properties[0] == 6u);
  CHECK(query.properties[1] == 13u);
  CHECK(query.properties[2] == 2u);
}

TEST_CASE("ParseRuleText rejects a non-unsigned query property") {
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate">)"
               R"(<query kind="process" properties="1,nope"/>)"
               R"(</rule>)"),
           "query properties must be unsigned integers");
}

TEST_CASE("ParseRuleText accepts query context set, enum, and both") {
  const auto set_only = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate"><query kind="process" context="set"/></rule>)"));
  REQUIRE(set_only.document.rules.size() == 1);
  REQUIRE(set_only.document.rules.front().queries.size() == 1);
  CHECK(set_only.document.rules.front().queries.front().context_set);
  CHECK_FALSE(set_only.document.rules.front().queries.front().context_enum);

  const auto enum_only = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate"><query kind="process" context="enum"/></rule>)"));
  REQUIRE(enum_only.document.rules.size() == 1);
  REQUIRE(enum_only.document.rules.front().queries.size() == 1);
  CHECK_FALSE(enum_only.document.rules.front().queries.front().context_set);
  CHECK(enum_only.document.rules.front().queries.front().context_enum);

  const auto both = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate"><query kind="fileobject" context="set,enum"/></rule>)"));
  REQUIRE(both.document.rules.size() == 1);
  REQUIRE(both.document.rules.front().queries.size() == 1);
  CHECK(both.document.rules.front().queries.front().context_set);
  CHECK(both.document.rules.front().queries.front().context_enum);
}

TEST_CASE("ParseRuleText rejects an unknown query context token") {
  MustFail(Doc(R"(<rule name="r" event="ProcessCreate">)"
               R"(<query kind="process" context="global"/>)"
               R"(</rule>)"),
           "query context must be set, enum, or both");
}

TEST_CASE("ParseRuleText maps collection types string integer and binary") {
  const auto outcome = MustOk(Doc(R"(<collection name="s" type="string"/>)"
                                  R"(<collection name="s2" type="2"/>)"
                                  R"(<collection name="i" type="integer"/>)"
                                  R"(<collection name="i1" type="1"/>)"
                                  R"(<collection name="b" type="binary"/>)"
                                  R"(<collection name="b3" type="3"/>)"
                                  R"(<collection name="def"/>)"));
  REQUIRE(outcome.document.collections.size() == 7);
  CHECK(outcome.document.collections[0].type == kCollectionTypeString);
  CHECK(outcome.document.collections[1].type == 2);
  CHECK(outcome.document.collections[2].type == 1);
  CHECK(outcome.document.collections[3].type == 1);
  CHECK(outcome.document.collections[4].type == 3);
  CHECK(outcome.document.collections[5].type == 3);
  CHECK(outcome.document.collections[6].type == kCollectionTypeString);
}

TEST_CASE("ParseRuleText rejects an unknown collection type") {
  MustFail(Doc(R"(<collection name="bad" type="blob"/>)"),
           "collection type must be integer, string, or binary");
}

TEST_CASE("ParseRuleText rejects open collection without a guid") {
  MustFail(Doc(R"(<collection name="reopen" open="true"/>)"),
           "open=\"true\" requires guid");
}

TEST_CASE("ParseRuleText accepts an open collection that has a guid") {
  const auto outcome = MustOk(Doc(
      R"(<collection name="reopen" open="true" guid="{a1b2c3d4-e5f6-7890-abcd-ef0123456789}"/>)"));
  REQUIRE(outcome.document.collections.size() == 1);
  CHECK(outcome.document.collections.front().open);
  CHECK(outcome.document.collections.front().hasGuid);
  CHECK(outcome.document.collections.front().name == "reopen");
  CHECK(FormattedGuid(outcome.document.collections.front().guid) ==
        "{a1b2c3d4-e5f6-7890-abcd-ef0123456789}");
}

TEST_CASE("ParseRuleText stores collection entries") {
  const auto outcome = MustOk(Doc(R"(<collection name="names" type="string">)"
                                  R"(<entry>alpha</entry>)"
                                  R"(<entry>beta</entry>)"
                                  R"(</collection>)"));
  REQUIRE(outcome.document.collections.size() == 1);
  REQUIRE(outcome.document.collections.front().entries.size() == 2);
  CHECK(outcome.document.collections.front().entries[0] == "alpha");
  CHECK(outcome.document.collections.front().entries[1] == "beta");
}

TEST_CASE("ParseRuleText rejects an invalid client guid") {
  MustFail(Doc(R"(<client name="n" guid="not-a-guid"/>)"),
           "client guid is not a valid GUID");
}

TEST_CASE("ParseRuleText sets hasGuid for a valid client guid") {
  const auto outcome = MustOk(Doc(
      R"(<client name="named" guid="{a1b2c3d4-e5f6-7890-abcd-ef0123456789}"/>)"));
  CHECK(outcome.document.client.name == "named");
  CHECK(outcome.document.client.hasGuid);
  CHECK(FormattedGuid(outcome.document.client.guid) ==
        "{a1b2c3d4-e5f6-7890-abcd-ef0123456789}");
}

TEST_CASE("ParseRuleText builds and or xor and not filter trees") {
  const auto and_tree = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate">)"
      R"(<and><filter type="10" property="1"/><filter type="10" property="2"/></and>)"
      R"(</rule>)"));
  REQUIRE(and_tree.document.rules.size() == 1);
  CHECK(and_tree.document.rules.front().filter.kind == FilterKind::And);
  REQUIRE(and_tree.document.rules.front().filter.children.size() == 2);

  const auto or_tree = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate">)"
      R"(<or><filter type="10" property="1"/><filter type="8" property="1"/></or>)"
      R"(</rule>)"));
  REQUIRE(or_tree.document.rules.size() == 1);
  CHECK(or_tree.document.rules.front().filter.kind == FilterKind::Or);
  REQUIRE(or_tree.document.rules.front().filter.children.size() == 2);

  const auto xor_tree = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate">)"
      R"(<xor><filter type="10" property="1"/><filter type="10" property="2"/></xor>)"
      R"(</rule>)"));
  REQUIRE(xor_tree.document.rules.size() == 1);
  CHECK(xor_tree.document.rules.front().filter.kind == FilterKind::Xor);

  const auto not_tree =
      MustOk(Doc(R"(<rule name="r" event="ProcessCreate">)"
                 R"(<not><filter type="10" property="1"/></not>)"
                 R"(</rule>)"));
  REQUIRE(not_tree.document.rules.size() == 1);
  CHECK(not_tree.document.rules.front().filter.kind == FilterKind::Not);
  REQUIRE(not_tree.document.rules.front().filter.children.size() == 1);
}

TEST_CASE("ParseRuleText requires combinators inside a rule") {
  MustFail(Doc(R"(<and><filter type="10"/></and>)"),
           "<and> must appear inside <rule>");
}

TEST_CASE("ParseRuleText ignores unknown elements") {
  const auto outcome = MustOk(
      Doc(R"(<meta version="1"/><rules><rule name="r" event="ProcessCreate">)"
          R"(<note>ignored</note></rule></rules>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().name == "r");
}

TEST_CASE("ParseRuleText sets collection comparand when comparand is omitted") {
  const auto omitted =
      MustOk(Doc(R"(<rule name="r" event="ProcessCreate">)"
                 R"(<filter type="10" property="1" collection="names"/>)"
                 R"(</rule>)"));
  REQUIRE(omitted.document.rules.size() == 1);
  CHECK(omitted.document.rules.front().filter.collectionName == "names");
  CHECK(omitted.document.rules.front().filter.comparand ==
        static_cast<std::int32_t>(kStringComparandCollection));

  const auto explicit_comparand =
      MustOk(Doc(R"(<rule name="r" event="ProcessCreate">)"
                 R"(<filter type="10" comparand="1" collection="names"/>)"
                 R"(</rule>)"));
  REQUIRE(explicit_comparand.document.rules.size() == 1);
  CHECK(explicit_comparand.document.rules.front().filter.comparand == 1);
}

TEST_CASE("ParseRuleFile fails when the path cannot be opened") {
  const ParseOutcome outcome =
      ParseRuleFile("C:\\esptool_missing_rules\\no_such_file.xml");
  REQUIRE_FALSE(outcome.ok);
  CHECK(Has(outcome.error, "could not open the rule file"));
}

TEST_CASE("ParseRuleFile loads monitor_process_create.xml") {
  const ParseOutcome outcome =
      ParseRuleFile(RulesFile("monitor_process_create.xml"));
  INFO(outcome.error);
  REQUIRE(outcome.ok);
  CHECK(outcome.document.client.name == "esptool-mon-proc");
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().eventType == kEventProcessCreate);
  CHECK(outcome.document.rules.front().action == 0);
}

TEST_CASE("ParseRuleText combines multiple top-level filter leaves with And") {
  const auto outcome = MustOk(Doc(R"(<rule name="r" event="ProcessCreate">)"
                                  R"(<filter type="10" property="1"/>)"
                                  R"(<filter type="10" property="2"/>)"
                                  R"(</rule>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().filter.kind == FilterKind::And);
  REQUIRE(outcome.document.rules.front().filter.children.size() == 2);
  CHECK(outcome.document.rules.front().filter.children[0].propertyId == 1);
  CHECK(outcome.document.rules.front().filter.children[1].propertyId == 2);
}

TEST_CASE("ParseRuleText rejects a self-closing esptool root") {
  MustFail("<esptool/>", "the <esptool> root element is not closed");
}

TEST_CASE("ParseRuleText rejects malformed XML") {
  MustFail("<esptool><rule", "the XML document is not well formed");
  MustFail("<esptool><rule name=\"r\" event=\"ProcessCreate\"></esptool>",
           "the XML document is not well formed");
}

TEST_CASE("ParseRuleText accepts the deny action name") {
  const auto outcome = MustOk(Doc(
      R"(<rule name="r" event="FoCreate" eventType="2000" action="deny"/>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().actionName == "deny");
  CHECK(outcome.document.rules.front().action == 0);
}

TEST_CASE("ParseRuleText accepts the suppress action name") {
  const auto outcome = MustOk(Doc(
      R"(<rule name="r" event="ProcessCreate" eventType="1000" action="suppress"/>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().actionName == "suppress");
  CHECK(outcome.document.rules.front().action == 0);
}

TEST_CASE("ParseRuleText still accepts a numeric action selector") {
  const auto outcome = MustOk(
      Doc(R"(<rule name="r" event="FoCreate" eventType="2000" action="5"/>)"));
  REQUIRE(outcome.document.rules.size() == 1);
  CHECK(outcome.document.rules.front().action == 5);
  CHECK(outcome.document.rules.front().actionName.empty());
}

TEST_CASE("ParseRuleText rejects an unknown action name") {
  MustFail(Doc(R"(<rule name="r" event="FoCreate" action="block"/>)"),
           "rule action is not a number or a known action name");
}

TEST_CASE("ParseRuleText parses disposition attribute") {
  const auto ad = MustOk(Doc(
      R"(<rule name="r1" event="FoCreate" action="deny" disposition="access_denied"/>)"));
  REQUIRE(ad.document.rules.size() == 1);
  CHECK(ad.document.rules.front().modify_kind_override == 2);

  const auto nf = MustOk(Doc(
      R"(<rule name="r2" event="FoCreate" action="deny" disposition="not_found"/>)"));
  REQUIRE(nf.document.rules.size() == 1);
  CHECK(nf.document.rules.front().modify_kind_override == 3);

  const auto vi = MustOk(Doc(
      R"(<rule name="r3" event="FoCreate" action="deny" disposition="virus"/>)"));
  REQUIRE(vi.document.rules.size() == 1);
  CHECK(vi.document.rules.front().modify_kind_override == 1);

  const auto num = MustOk(Doc(
      R"(<rule name="r4" event="FoCreate" action="deny" disposition="2"/>)"));
  REQUIRE(num.document.rules.size() == 1);
  CHECK(num.document.rules.front().modify_kind_override == 2);

  MustFail(
      Doc(R"(<rule name="r5" event="FoCreate" action="deny" disposition="invalid_disp"/>)"),
      "rule disposition must be access_denied, not_found, virus, or a number "
      "1..5");
}

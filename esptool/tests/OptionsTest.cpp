#include <doctest.h>

#include <string>
#include <string_view>

#include "TestSupport.h"
#include "cli/Commands.h"
#include "cli/Options.h"
#include "util/StrHelpers.h"

using esptool::cli::Options;
using esptool::cli::ParseOptions;
using esptool::test::WideArgv;
using esptool::text::ToUtf8;

namespace {

[[nodiscard]] Options MustParse(std::initializer_list<std::wstring_view> args) {
  WideArgv argv(args);
  Options out;
  std::string error;
  const bool ok = ParseOptions(argv.argc(), argv.argv(), out, error);
  REQUIRE(ok);
  CHECK(error.empty());
  return out;
}

void MustReject(std::initializer_list<std::wstring_view> args,
                std::string_view expected) {
  WideArgv argv(args);
  Options out;
  std::string error;
  const bool ok = ParseOptions(argv.argc(), argv.argv(), out, error);
  REQUIRE_FALSE(ok);
  REQUIRE(error == expected);
}

void CheckDefaults(const Options& out) {
  CHECK(out.pipe_name == "esptool");
  CHECK(out.service_name == "esptool");
  CHECK(out.duration_ms == 5000);
  CHECK(out.max_notifications == 10);
  CHECK(out.collection_type == 2);
  CHECK(out.collection_lifetime == 1);
  CHECK_FALSE(out.duration_set);
  CHECK_FALSE(out.collection_type_set);
  CHECK_FALSE(out.help);
  CHECK_FALSE(out.verbose);
  CHECK_FALSE(out.no_provision);
  CHECK_FALSE(out.isolated);
  CHECK_FALSE(out.json);
  CHECK_FALSE(out.iocp);
  CHECK_FALSE(out.enforce_compat);
  CHECK_FALSE(out.fresh);
  CHECK_FALSE(out.all);
  CHECK_FALSE(out.from_notify);
  CHECK_FALSE(out.duplicate);
  CHECK_FALSE(out.context_set);
  CHECK_FALSE(out.context_enum);
  CHECK_FALSE(out.enum_ids);
  CHECK_FALSE(out.open_collection);
  CHECK_FALSE(out.worker);
}

}  // namespace

TEST_CASE("ParseOptions applies documented defaults") {
  const Options out = MustParse({});
  CHECK(out.command.empty());
  CHECK(out.pipe_name == "esptool");
  CHECK(out.service_name == "esptool");
  CHECK(out.duration_ms == 5000);
  CHECK(out.max_notifications == 10);
  CHECK(out.collection_type == 2);
  CHECK(out.collection_lifetime == 1);
  CHECK_FALSE(out.duration_set);
  CHECK_FALSE(out.collection_type_set);
}

TEST_CASE("ParseOptions treats the first non-flag as the command") {
  const Options out = MustParse({L"monitor", L"extra", L"args"});
  CHECK(out.command == "monitor");
  REQUIRE(out.positional.size() == 2);
  CHECK(out.positional[0] == "extra");
  CHECK(out.positional[1] == "args");
}

TEST_CASE("ParseOptions accepts every string flag as a following token") {
  const Options out = MustParse({
      L"refs",      L"--dll",        L"esp.dll", L"--rules",
      L"rules.xml", L"--log",        L"log.txt", L"--pipe",
      L"pipe-a",    L"--service",    L"svc-a",   L"--level",
      L"debug",     L"--target",     L"sel",     L"--permission",
      L"full",      L"--guid",       L"{guid}",  L"--kind",
      L"file",      L"--pid",        L"self",    L"--tid",
      L"4",         L"--path",       L"C:\\tmp", L"--file-id",
      L"aabb",      L"--volume",     L"{vol}",   L"--stream",
      L":s",        L"--name",       L"Default", L"--event-id",
      L"9",         L"--properties", L"1,2",     L"--supported",
      L"3",
  });
  CHECK(out.command == "refs");
  CHECK(out.dll_path == "esp.dll");
  CHECK(out.rules_path == "rules.xml");
  CHECK(out.log_path == "log.txt");
  CHECK(out.pipe_name == "pipe-a");
  CHECK(out.service_name == "svc-a");
  CHECK(out.level == "debug");
  CHECK(out.target == "sel");
  CHECK(out.permission == "full");
  CHECK(out.guid == "{guid}");
  CHECK(out.kind == "file");
  CHECK(out.pid == "self");
  CHECK(out.tid == "4");
  CHECK(out.path == "C:\\tmp");
  CHECK(out.file_id == "aabb");
  CHECK(out.volume == "{vol}");
  CHECK(out.stream == ":s");
  CHECK(out.object_name == "Default");
  CHECK(out.event_id == "9");
  CHECK(out.properties == "1,2");
  CHECK(out.supported == "3");
}

TEST_CASE("ParseOptions accepts every string flag in equals form") {
  const Options out = MustParse({
      L"query",
      L"--dll=esp2.dll",
      L"--rules=r2.xml",
      L"--log=l2.txt",
      L"--pipe=pipe-b",
      L"--service=svc-b",
      L"--level=warn",
      L"--target=other",
      L"--permission=restricted",
      L"--guid=id2",
      L"--kind=reg",
      L"--pid=8",
      L"--tid=self",
      L"--path=D:\\x",
      L"--file-id=ccdd",
      L"--volume=vol2",
      L"--stream=:alt",
      L"--name=WinSta0",
      L"--event-id=12",
      L"--properties=4,5",
      L"--supported=6",
  });
  CHECK(out.command == "query");
  CHECK(out.dll_path == "esp2.dll");
  CHECK(out.rules_path == "r2.xml");
  CHECK(out.log_path == "l2.txt");
  CHECK(out.pipe_name == "pipe-b");
  CHECK(out.service_name == "svc-b");
  CHECK(out.level == "warn");
  CHECK(out.target == "other");
  CHECK(out.permission == "restricted");
  CHECK(out.guid == "id2");
  CHECK(out.kind == "reg");
  CHECK(out.pid == "8");
  CHECK(out.tid == "self");
  CHECK(out.path == "D:\\x");
  CHECK(out.file_id == "ccdd");
  CHECK(out.volume == "vol2");
  CHECK(out.stream == ":alt");
  CHECK(out.object_name == "WinSta0");
  CHECK(out.event_id == "12");
  CHECK(out.properties == "4,5");
  CHECK(out.supported == "6");
}

TEST_CASE("ParseOptions accepts every bool flag") {
  const Options all = MustParse({
      L"exercise",
      L"--help",
      L"--verbose",
      L"--no-auto-provision",
      L"--isolated",
      L"--json",
      L"--iocp",
      L"--enforce-compat",
      L"--fresh",
      L"--all",
      L"--from-notify",
      L"--duplicate",
      L"--context-set",
      L"--context-enum",
      L"--enum-ids",
      L"--open",
      L"--worker",
  });
  CHECK(all.command == "exercise");
  CHECK(all.help);
  CHECK(all.verbose);
  CHECK(all.no_auto_provision);
  CHECK(all.isolated);
  CHECK(all.json);
  CHECK(all.iocp);
  CHECK(all.enforce_compat);
  CHECK(all.fresh);
  CHECK(all.all);
  CHECK(all.from_notify);
  CHECK(all.duplicate);
  CHECK(all.context_set);
  CHECK(all.context_enum);
  CHECK(all.enum_ids);
  CHECK(all.open_collection);
  CHECK(all.worker);

  const Options prov_flags = MustParse({
      L"exercise",
      L"--no-provision",
      L"--no-hop",
      L"--clear-attribute",
  });
  CHECK(prov_flags.no_provision);
  CHECK(prov_flags.no_hop);
  CHECK(prov_flags.clear_attribute);

  const Options force_flags = MustParse({
      L"exercise",
      L"--force-provision",
      L"--force-hop",
  });
  CHECK(force_flags.force_provision);
  CHECK(force_flags.force_hop);

  const Options shorts = MustParse({L"status", L"-h", L"-v"});
  CHECK(shorts.command == "status");
  CHECK(shorts.help);
  CHECK(shorts.verbose);
}

TEST_CASE("ParseOptions accepts every count flag as a following token") {
  const Options out = MustParse({L"monitor", L"--duration", L"14000", L"--max",
                                 L"20", L"--type", L"3", L"--lifetime", L"2"});
  CHECK(out.command == "monitor");
  CHECK(out.duration_ms == 14000);
  CHECK(out.max_notifications == 20);
  CHECK(out.collection_type == 3);
  CHECK(out.collection_lifetime == 2);
  CHECK(out.duration_set);
  CHECK(out.max_notifications_set);
  CHECK(out.collection_type_set);
}

TEST_CASE("ParseOptions accepts every count flag in equals form") {
  const Options out = MustParse({L"collections", L"--duration=1", L"--max=0",
                                 L"--type=1", L"--lifetime=3"});
  CHECK(out.command == "collections");
  CHECK(out.duration_ms == 1);
  CHECK(out.max_notifications == 0);
  CHECK(out.collection_type == 1);
  CHECK(out.collection_lifetime == 3);
  CHECK(out.duration_set);
  CHECK(out.max_notifications_set);
  CHECK(out.collection_type_set);
}

TEST_CASE(
    "ParseOptions leaves count-set flags false without count options") {
  const Options out = MustParse({L"status"});
  CHECK_FALSE(out.duration_set);
  CHECK_FALSE(out.max_notifications_set);
  CHECK_FALSE(out.collection_type_set);
}

TEST_CASE(
    "ParseOptions sets max_notifications_set when --max is present") {
  const Options out =
      MustParse({L"monitor", L"--max", L"7", L"--lifetime", L"3"});
  CHECK(out.max_notifications == 7);
  CHECK(out.collection_lifetime == 3);
  CHECK(out.max_notifications_set);
  CHECK_FALSE(out.duration_set);
  CHECK_FALSE(out.collection_type_set);
  CHECK(out.duration_ms == 5000);
  CHECK(out.collection_type == 2);
}

TEST_CASE("ParseOptions rejects a missing value for every string flag") {
  const wchar_t* flags[] = {
      L"--dll",        L"--rules", L"--log",      L"--pipe",
      L"--service",    L"--level", L"--target",   L"--permission",
      L"--guid",       L"--kind",  L"--pid",      L"--tid",
      L"--path",       L"--file-id", L"--volume", L"--stream",
      L"--name",       L"--event-id", L"--properties", L"--supported",
  };
  for (const wchar_t* flag : flags) {
    MustReject({flag}, std::string("missing value for ") + ToUtf8(flag));
  }
}

TEST_CASE("ParseOptions rejects a missing value for every count flag") {
  const wchar_t* flags[] = {L"--duration", L"--max", L"--type", L"--lifetime"};
  for (const wchar_t* flag : flags) {
    MustReject({flag}, std::string("missing value for ") + ToUtf8(flag));
  }
}

TEST_CASE("ParseOptions rejects an invalid count") {
  MustReject({L"--duration", L"abc"}, "invalid value for --duration: abc");
  MustReject({L"--max", L"-1"}, "invalid value for --max: -1");
  MustReject({L"--type="}, "invalid value for --type: ");
  MustReject({L"--lifetime", L"nope"}, "invalid value for --lifetime: nope");
  MustReject({L"--duration=0x100000000"},
             "invalid value for --duration: 0x100000000");
}

TEST_CASE("ParseOptions rejects an unknown option") {
  MustReject({L"--not-a-flag"}, "unknown option: --not-a-flag");
  MustReject({L"status", L"-x"}, "unknown option: -x");
}

TEST_CASE("ParseOptions treats a lone dash as a non-flag token") {
  const Options as_command = MustParse({L"-", L"--dll", L"esp.dll"});
  CHECK(as_command.command == "-");
  CHECK(as_command.dll_path == "esp.dll");
  CHECK(as_command.positional.empty());

  const Options as_positional = MustParse({L"refs", L"-"});
  CHECK(as_positional.command == "refs");
  REQUIRE(as_positional.positional.size() == 1);
  CHECK(as_positional.positional[0] == "-");
}

TEST_CASE("ParseOptions stops option parsing at a double dash") {
  const Options out = MustParse(
      {L"monitor", L"--verbose", L"--", L"--dll", L"not-a-flag", L"-v"});
  CHECK(out.command == "monitor");
  CHECK(out.verbose);
  CHECK(out.dll_path.empty());
  REQUIRE(out.positional.size() == 3);
  CHECK(out.positional[0] == "--dll");
  CHECK(out.positional[1] == "not-a-flag");
  CHECK(out.positional[2] == "-v");
}

TEST_CASE("ParseOptions resets prior state on every call") {
  WideArgv first({L"--dll", L"old.dll", L"--verbose", L"--duration", L"99",
                  L"--type", L"3", L"monitor", L"left"});
  Options out;
  std::string error;
  REQUIRE(ParseOptions(first.argc(), first.argv(), out, error));
  CHECK(out.dll_path == "old.dll");
  CHECK(out.verbose);
  CHECK(out.duration_set);
  CHECK(out.collection_type_set);

  WideArgv second({L"status"});
  REQUIRE(ParseOptions(second.argc(), second.argv(), out, error));
  CHECK(out.command == "status");
  CHECK(out.dll_path.empty());
  CHECK(out.positional.empty());
  CheckDefaults(out);
}

TEST_CASE("ParseOptions rejects mutually exclusive option pairs") {
  MustReject({L"monitor", L"--no-provision", L"--force-provision"},
             "cannot specify both --no-provision and --force-provision");
  MustReject({L"monitor", L"--no-provision", L"--permission", L"restricted"},
             "cannot specify both --no-provision and --permission");
  MustReject({L"monitor", L"--no-hop", L"--force-hop"},
             "cannot specify both --no-hop and --force-hop");
}

TEST_CASE("ParseOptions validates --permission values") {
  MustReject({L"connect", L"--permission", L"invalid-perm"},
             "invalid value for --permission: invalid-perm");

  const Options full = MustParse({L"connect", L"--permission", L"full"});
  CHECK(full.permission == "full");

  const Options restr = MustParse({L"connect", L"--permission", L"restricted"});
  CHECK(restr.permission == "restricted");

  const Options abcd = MustParse({L"connect", L"--permission", L"abcd"});
  CHECK(abcd.permission == "abcd");

  const Options num = MustParse({L"connect", L"--permission", L"10000000"});
  CHECK(num.permission == "10000000");
}

TEST_CASE("EvaluateTrustPlan decision table covers all matrix branches") {
  using esptool::cli::EvaluateTrustPlan;
  using esptool::cli::ProvisioningContext;
  using esptool::cli::TrustPlan;

  // Branch 1: Explicit --no-provision
  {
    Options opt;
    opt.command = "monitor";
    opt.no_provision = true;
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = false;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK(plan.effective_no_provision);
    CHECK_FALSE(plan.stamp_needed);
    CHECK_FALSE(plan.child_required);
  }

  // Branch 2: Explicit --force-provision on test-signing non-PPL
  {
    Options opt;
    opt.command = "monitor";
    opt.force_provision = true;
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = false;
    ctx.attribute_present = false;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK_FALSE(plan.effective_no_provision);
    CHECK(plan.stamp_needed);
    CHECK(plan.child_required);
  }

  // Branch 3: Explicit --permission restricted on test-signing non-PPL
  {
    Options opt;
    opt.command = "connect";
    opt.permission = "restricted";
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = false;
    ctx.attribute_present = false;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK_FALSE(plan.effective_no_provision);
    CHECK(plan.target_permission == 10000000);
    CHECK(plan.stamp_needed);
    CHECK(plan.child_required);
  }

  // Branch 4: Explicit --no-auto-provision disables auto-detection
  {
    Options opt;
    opt.command = "monitor";
    opt.no_auto_provision = true;
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = false;
    ctx.attribute_present = false;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK_FALSE(plan.effective_no_provision);
    CHECK(plan.stamp_needed);
    CHECK(plan.child_required);
  }

  // Branch 5: Default auto-detection on test-signing non-PPL sets
  // effective_no_provision
  {
    Options opt;
    opt.command = "monitor";
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = false;
    ctx.attribute_present = false;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK(plan.effective_no_provision);
    CHECK(plan.auto_no_provision_applied);
    CHECK_FALSE(plan.stamp_needed);
    CHECK_FALSE(plan.clean_needed);
    CHECK_FALSE(plan.child_required);
  }

  // Branch 6: Pre-existing attribute on test-signing non-PPL triggers
  // clean_needed & child_required
  {
    Options opt;
    opt.command = "monitor";
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = false;
    ctx.attribute_present = true;
    ctx.attribute_permission = 10000000;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK(plan.effective_no_provision);
    CHECK(plan.clean_needed);
    CHECK(plan.child_required);
  }

  // Branch 7: Production / AM-PPL requires attribute; if missing on token,
  // stamps via child
  {
    Options opt;
    opt.command = "monitor";
    ProvisioningContext ctx;
    ctx.test_signing = false;
    ctx.is_ppl = false;
    ctx.attribute_present = false;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK_FALSE(plan.effective_no_provision);
    CHECK(plan.stamp_needed);
    CHECK(plan.child_required);
  }

  // Branch 8: Production / AM-PPL with matching attribute already present runs
  // directly
  {
    Options opt;
    opt.command = "monitor";
    ProvisioningContext ctx;
    ctx.test_signing = true;
    ctx.is_ppl = true;
    ctx.attribute_present = true;
    ctx.attribute_permission = 1000000000;  // Full
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt, ctx, plan, err));
    CHECK_FALSE(plan.effective_no_provision);
    CHECK_FALSE(plan.stamp_needed);
    CHECK_FALSE(plan.child_required);
  }

  // Branch 9: Hop flag overrides: --no-hop suppresses hop, --force-hop demands
  // hop, --worker suppresses hop
  {
    Options opt_nohop;
    opt_nohop.command = "monitor";
    opt_nohop.no_hop = true;
    opt_nohop.force_provision = true;
    ProvisioningContext ctx;
    TrustPlan plan;
    std::string err;
    REQUIRE(EvaluateTrustPlan(opt_nohop, ctx, plan, err));
    CHECK_FALSE(plan.child_required);

    Options opt_forcehop;
    opt_forcehop.command = "monitor";
    opt_forcehop.force_hop = true;
    opt_forcehop.no_provision = true;
    REQUIRE(EvaluateTrustPlan(opt_forcehop, ctx, plan, err));
    CHECK(plan.child_required);

    Options opt_worker;
    opt_worker.command = "monitor";
    opt_worker.worker = true;
    opt_worker.force_provision = true;
    REQUIRE(EvaluateTrustPlan(opt_worker, ctx, plan, err));
    CHECK_FALSE(plan.child_required);
  }
}

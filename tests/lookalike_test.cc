// Lookalike verdicts: the generated attacks and controls of the engine's validation run (tests/vectors/
// lookalike_attacks.tsv; brand list tests/data/brands.tsv, shared mailboxes tests/data/shared_mailbox.txt, the
// owner "Alex Morgan" of Kestrel Works). Contact cases need the run's synthetic address book and are left to
// tools/eval.
#include <gtest/gtest.h>

#include "maillookalike/lookalike.h"
#include "test_data.h"

namespace ml = maillookalike;

namespace {

std::vector<ml::Brand> brands() {
  std::vector<ml::Brand> out;
  for (const std::string& line : testdata::lines(MAILLOOKALIKE_TEST_DATA "/brands.tsv")) {
    const auto f = testdata::split(line, '\t');
    if (f.size() != 5 || line[0] == '#') continue;
    ml::Brand b;
    b.id = f[0];
    b.names = testdata::split(f[1], '|');
    b.domains = testdata::split(f[2], '|');
    if (f[3] != "-") b.tokens = testdata::split(f[3], '|');
    b.generic_name = f[4] == "generic";
    out.push_back(std::move(b));
  }
  return out;
}

std::unique_ptr<ml::Engine> engine() {
  std::string err;
  auto e = ml::Engine::create(testdata::psl(), ml::Options{}, &err);
  if (!e) return nullptr;
  ml::Profile p;
  p.brands = brands();
  p.shared_mailbox_domains = testdata::lines(MAILLOOKALIKE_TEST_DATA "/shared_mailbox.txt");
  p.own_names = {"Alex Morgan"};
  p.own_addresses = {"alex.morgan@kestrelworks.com", "alex.morgan.home@gmail.com"};
  p.org_names = {"Kestrel Works"};
  e->set_profile(p);
  return e;
}

}  // namespace

TEST(Lookalike, AttackAndControlVerdicts) {
  auto eng = engine();
  ASSERT_TRUE(eng);
  size_t n = 0;
  for (const auto& f : testdata::rows(MAILLOOKALIKE_TEST_VECTORS "/lookalike_attacks.tsv")) {
    ASSERT_GE(f.size(), 3u);
    const std::string expected = f.size() > 3 ? f[3] : "";
    std::string got;
    auto add = [&](const char* kind, ml::Severity s, const std::string& target) {
      got += std::string(got.empty() ? "" : ",") + kind + ":" + ml::to_string(s) + ":" + target;
    };
    if (!f[2].empty()) {
      const ml::SenderReport r = eng->check_sender({f[1], f[2], ""});
      for (const auto& m : r.name.matches) add(ml::to_string(m.kind), m.severity, m.matched);
      for (const auto& m : r.from.matches) add(ml::to_string(m.kind), m.severity, m.matched_domain);
    } else {
      const ml::HostReport r = eng->check_host(f[1]);
      for (const auto& m : r.matches) add(ml::to_string(m.kind), m.severity, m.matched_domain);
    }
    EXPECT_EQ(got, expected) << f[0] << " " << f[1];
    ++n;
  }
  EXPECT_EQ(n, 96u);
}

TEST(Lookalike, RegistrableDomainIsThePsl) {
  auto eng = engine();
  ASSERT_TRUE(eng);
  EXPECT_EQ(eng->registrable_domain("Paypal.COM.evil.top"), "evil.top");
  EXPECT_EQ(eng->registrable_domain("a.b.github.io"), "b.github.io");
}

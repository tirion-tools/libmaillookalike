// Chromium 156.0.8078.88's IDN spoof-checker expectations (components/url_formatter/spoof_checks/
// idn_spoof_checker_unittest.cc, kIdnCases with the Linux build conditionals; BSD-3-Clause, Copyright The Chromium
// Authors): every case must give Chromium's display (Unicode when kSafe, the input otherwise). The top-domain list
// is the test list of the same revision (idn_test_domains.list).
#include <gtest/gtest.h>

#include "maillookalike/lookalike.h"
#include "test_data.h"

namespace ml = maillookalike;

TEST(Chromium, All487IdnCasesAgree) {
  std::string err;
  auto eng = ml::Engine::create(testdata::psl(), ml::Options{}, &err);
  ASSERT_TRUE(eng) << err;
  ml::Profile p;
  p.top_domains = testdata::lines(MAILLOOKALIKE_TEST_DATA "/chromium_idn_test_domains.list");
  eng->set_profile(p);
  size_t total = 0, agree = 0;
  for (const std::string& line : testdata::lines(MAILLOOKALIKE_TEST_DATA "/chromium_idn_cases.tsv")) {
    const auto f = testdata::split(line, '\t');
    ASSERT_EQ(f.size(), 4u) << line;
    const std::string& input = f[1];
    ++total;
    const std::string expected = f[3] == "kSafe" ? f[2] : input;
    const ml::HostReport r = eng->check_host(input);
    std::string got = r.ascii.empty() && r.display.empty() ? input : r.display;
    if (!input.empty() && input.back() == '.' && (got.empty() || got.back() != '.')) got += ".";
    if (input.empty()) got = "";
    EXPECT_EQ(got, expected) << "input " << input << " reason " << ml::to_string(r.idn);
    agree += got == expected ? 1 : 0;
  }
  EXPECT_EQ(total, 487u);
  EXPECT_EQ(agree, total);
}

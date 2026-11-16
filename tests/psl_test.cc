// Registrable domains through libpsl over the pinned list, and the shared vectors (tests/vectors/psl.tsv: host, then
// the registrable domain or empty, then 1 when has_known_tld). The vectors were produced by the reference engine's
// own suffix matcher over the same list, so a consumer keeping a second matcher can check it against this file.
#include <gtest/gtest.h>

#include "test_data.h"

TEST(Psl, KnownCases) {
  auto p = testdata::psl();
  ASSERT_TRUE(p);
  EXPECT_EQ(p->registrable("www.example.co.uk"), "example.co.uk");
  EXPECT_EQ(p->registrable("a.b.github.io"), "b.github.io");
  EXPECT_EQ(p->registrable("foo.xn--p1ai"), "foo.xn--p1ai");
  EXPECT_EQ(p->registrable("x.y.xn--55qx5d.cn"), "y.xn--55qx5d.cn");
  EXPECT_EQ(p->registrable("paypal.com.evil.top"), "evil.top");
  EXPECT_EQ(p->registrable("sub.unknown-tld-zz"), "sub.unknown-tld-zz");
  EXPECT_EQ(p->registrable("co.uk"), "");
  EXPECT_EQ(p->registrable("localhost"), "");
  EXPECT_EQ(p->registrable("a..b.com"), "");
  EXPECT_EQ(p->registrable(std::string(250, 'a') + ".com"), "");
  EXPECT_TRUE(p->listed("co.uk"));
  EXPECT_FALSE(p->listed("unknown-tld-zz"));
  EXPECT_TRUE(p->has_known_tld("paypal.com"));
  EXPECT_FALSE(p->has_known_tld("paypal.example"));
  EXPECT_TRUE(testdata::psl({"example"})->has_known_tld("paypal.example"));
}

TEST(Psl, RefusesATruncatedList) {
  std::string err;
  EXPECT_FALSE(maillookalike::Psl::load("com\nnet\n", {}, &err));
  EXPECT_FALSE(err.empty());
}

TEST(Psl, SharedVectors) {
  auto p = testdata::psl();
  size_t n = 0;
  for (const std::string& l : testdata::lines(MAILLOOKALIKE_TEST_VECTORS "/psl.tsv")) {
    if (l.empty() || l[0] == '#') continue;
    const auto f = testdata::split(l, '\t');
    ASSERT_EQ(f.size(), 3u) << l;
    EXPECT_EQ(p->registrable(f[0]), f[1]) << f[0];
    EXPECT_EQ(p->has_known_tld(f[0]), f[2] == "1") << f[0];
    ++n;
  }
  EXPECT_GT(n, 1000u);
}

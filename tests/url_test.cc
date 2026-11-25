// URL parsing against the reference engine's vectors (tests/vectors/urls.tsv) and a few direct cases.
#include <gtest/gtest.h>

#include "maillookalike/url.h"
#include "test_data.h"

namespace ml = maillookalike;

TEST(Url, SharedVectors) {
  size_t n = 0;
  for (const auto& f : testdata::rows(testdata::vectors("urls.tsv"))) {
    ASSERT_EQ(f.size(), 10u);
    const std::string raw = testdata::unescape(f[0]);
    const auto u = ml::Url::parse(raw);
    ++n;
    EXPECT_EQ(u.has_value(), f[1] == "1") << raw;
    if (!u || f[1] != "1") continue;
    EXPECT_EQ(u->scheme, testdata::unescape(f[2])) << raw;
    EXPECT_EQ(u->host, testdata::unescape(f[3])) << raw;
    EXPECT_EQ(u->path, testdata::unescape(f[4])) << raw;
    EXPECT_EQ(u->query, testdata::unescape(f[5])) << raw;
    EXPECT_EQ(u->canonical, testdata::unescape(f[6])) << raw;
    EXPECT_EQ(u->mailto_domain, testdata::unescape(f[7])) << raw;
    const uint32_t flags = (u->userinfo ? 1u : 0u) | (u->ip ? 2u : 0u) | (u->encoded_host ? 4u : 0u) |
                           (u->idn ? 8u : 0u) | (u->non_default_port ? 16u : 0u) | (u->bad_slashes ? 32u : 0u);
    EXPECT_EQ(flags, std::stoul(f[8])) << raw;
    std::vector<std::string> params;
    for (const auto& [k, v] : u->query_params()) {
      params.push_back(k);
      params.push_back(v);
    }
    // Scheme-specific parts only (mailto and opaque schemes have no query of their own).
    if (u->scheme == "http" || u->scheme == "https" || u->scheme == "ftp" || u->scheme == "ws" || u->scheme == "wss" ||
        u->scheme == "file") {
      EXPECT_EQ(params, testdata::unescape_list(f[9])) << raw;
    }
  }
  EXPECT_GT(n, 90u);
}

TEST(Url, Ipv4NumberForms) {
  EXPECT_EQ(ml::parse_ipv4("0xC0A80001"), "192.168.0.1");
  EXPECT_EQ(ml::parse_ipv4("3232235521"), "192.168.0.1");
  EXPECT_EQ(ml::parse_ipv4("0300.0250.0.1"), "192.168.0.1");
  EXPECT_EQ(ml::parse_ipv4("192.168.1"), "192.168.0.1");
  EXPECT_FALSE(ml::parse_ipv4("256.1.1.1"));
  EXPECT_FALSE(ml::parse_ipv4("1.2.3.4.5"));
  EXPECT_FALSE(ml::parse_ipv4("example.com"));
}

TEST(Url, PercentDecodeKeepsInvalidEscapes) {
  EXPECT_EQ(ml::percent_decode("%E2%82%AC"), "\xE2\x82\xAC");
  EXPECT_EQ(ml::percent_decode("%FF%41"), "%FFA");
  EXPECT_EQ(ml::percent_decode("%zz%4"), "%zz%4");
}

TEST(Url, PercentEncodedHostWithForbiddenCodePointFails) {
  // WHATWG host parsing: percent-decode, then fail on a forbidden domain code point (CR, LF, space, '%', ...).
  EXPECT_FALSE(ml::Url::parse("http://evil%0d%0a.example.com/"));
  EXPECT_FALSE(ml::Url::parse("http://a%0aexample.com/"));
  EXPECT_FALSE(ml::Url::parse("http://a%20b.com/"));
  EXPECT_FALSE(ml::Url::parse("http://a%2fb.com/"));
  EXPECT_FALSE(ml::Url::parse("http://a%zzb.com/"));
  const auto ok = ml::Url::parse("http://p%61ypal.com/");
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->host, "paypal.com");
  EXPECT_TRUE(ok->encoded_host);
}

// A host with a ZWJ/ZWNJ outside the context UTS #46 CheckJoiners allows (after a virama) is refused, as by the
// lookalike engine and browsers (WHATWG CheckJoiners); a joiner after a virama is fine. Before 0.1.7 the URL layer ran
// without CheckJoiners and accepted "pay\u200Dpal.com", which the engine then refused, so its checks never ran.
TEST(Url, JoinerOutOfContextIsABadHost) {
  for (const char* href : {"https://pay\u200Dpal.com/login", "https://pay\u200Cpal.com/", "https://www.\u200Dpaypal.com/"}) {
    ml::Url::Refusal why = ml::Url::Refusal::kNone;
    EXPECT_FALSE(ml::Url::parse(href, &why)) << href;
    EXPECT_EQ(why, ml::Url::Refusal::kBadHost) << href;
  }
  ml::Url::Refusal why = ml::Url::Refusal::kOther;
  const auto ok = ml::Url::parse("https://\u0915\u094D\u200D\u0937.example/", &why);
  ASSERT_TRUE(ok);
  EXPECT_EQ(why, ml::Url::Refusal::kNone);
  EXPECT_TRUE(ok->idn);
}

// An input over kMaxInput code units is refused whole, with the reason, never cut to its first kMaxInput units (a cut
// would leave the rest unchecked); kMaxInput units parse.
TEST(Url, OverlongInputIsRefusedAsTooLong) {
  const std::string head = "https://example.com/?q=";
  ml::Url::Refusal why = ml::Url::Refusal::kOther;
  EXPECT_TRUE(ml::Url::parse(head + std::string(ml::Url::kMaxInput - head.size(), 'a'), &why));
  EXPECT_EQ(why, ml::Url::Refusal::kNone);
  EXPECT_FALSE(ml::Url::parse(head + std::string(ml::Url::kMaxInput - head.size() + 1, 'a'), &why));
  EXPECT_EQ(why, ml::Url::Refusal::kTooLong);
  EXPECT_FALSE(ml::Url::parse(std::string(ml::Url::kMaxInput * 7, 'a'), &why));
  EXPECT_EQ(why, ml::Url::Refusal::kTooLong);
  EXPECT_FALSE(ml::Url::parse("no scheme here", &why));
  EXPECT_EQ(why, ml::Url::Refusal::kOther);
}

// The path and query in one spelling, so the URL a browser reports for a click (dot segments resolved, its own escaping)
// and the href a sanitizer or a message wrote compare equal (Graphein F1, 2026-11-20).
TEST(Url, PathAndQueryAreNormalisedTheWhatwgWay) {
  struct Case {
    const char* raw;
    const char* canonical;
  };
  const Case cases[] = {
      {"https://evil.example/x/../login", "https://evil.example/login"},
      {"https://evil.example/x/%2e%2E/login", "https://evil.example/login"},
      {"https://evil.example/x/.%2e/./login", "https://evil.example/login"},
      {"https://evil.example/../../login", "https://evil.example/login"},
      {"https://evil.example/a/b/..", "https://evil.example/a/"},
      {"https://evil.example/a/.", "https://evil.example/a/"},
      {"https://evil.example/a//b", "https://evil.example/a//b"},
      {"https://evil.example/%6Cogin", "https://evil.example/login"},
      {"https://evil.example/x%5C..%5Clogin", "https://evil.example/x%5C..%5Clogin"},
      {"https://evil.example\\x\\..\\login", "https://evil.example/login"},
      {"https://evil.example/a b/%7e?q=a b&r='x'%2f%7E", "https://evil.example/a%20b/~?q=a%20b&r=%27x%27%2F~"},
      {"https://evil.example/\xD0\xB0?\xD0\xB1", "https://evil.example/%D0%B0?%D0%B1"},
      {"https://evil.example/100%/{a}|^`", "https://evil.example/100%/%7Ba%7D%7C%5E%60"},
  };
  for (const Case& c : cases) {
    const auto u = ml::Url::parse(c.raw);
    ASSERT_TRUE(u) << c.raw;
    EXPECT_EQ(u->canonical, c.canonical) << c.raw;
  }
  EXPECT_EQ(ml::Url::parse("https://evil.example/x/../oauth2/%61uthorize")->path, "/oauth2/authorize");
}

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

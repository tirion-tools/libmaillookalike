// Link checks against the reference engine's results (tests/vectors/links.tsv: links of a synthetic phishing and ham
// corpus with the reference engine's verdicts) and the cases where two earlier copies of these rules disagreed.
#include <gtest/gtest.h>

#include "maillookalike/links.h"
#include "test_data.h"

namespace ml = maillookalike;

namespace {

struct Fixture {
  std::shared_ptr<const ml::Psl> psl = testdata::psl();
  std::shared_ptr<const ml::LinkLists> lists = testdata::lists();
  ml::LinkAssessment run(const std::string& href, std::vector<std::string> texts, uint32_t source = ml::kSourceHtml) {
    ml::LinkFacts f;
    f.href = href;
    f.texts = std::move(texts);
    f.source = source;
    return ml::assess(f, *psl, *lists);
  }
};

}  // namespace

TEST(Links, ListsCompile) {
  std::string err;
  ml::LinkListsData d;
  d.redirectors.push_back({"x", "(", "", {}, ""});
  EXPECT_FALSE(ml::LinkLists::compile(d, &err));
  EXPECT_FALSE(err.empty());
  EXPECT_TRUE(testdata::lists());
}

TEST(Links, SharedVectors) {
  Fixture fx;
  ASSERT_TRUE(fx.psl && fx.lists);
  size_t n = 0;
  for (const auto& f : testdata::rows(testdata::vectors("links.tsv"))) {
    ASSERT_EQ(f.size(), 14u);
    const std::string href = testdata::unescape(f[0]);
    ml::LinkFacts facts;
    facts.href = href;
    facts.texts = testdata::unescape_list(f[1]);
    facts.source = static_cast<uint32_t>(std::stoul(f[2]));
    // The reference compares texts only for HTML anchors.
    if ((facts.source & ml::kSourceHtml) == 0) facts.texts.clear();
    const ml::LinkAssessment a = ml::assess(facts, *fx.psl, *fx.lists);
    ++n;
    ASSERT_TRUE(a.url) << href;
    EXPECT_EQ(a.reg, testdata::unescape(f[3])) << href;
    EXPECT_EQ(a.inner_reg, testdata::unescape(f[4])) << href;
    EXPECT_EQ(a.flags, std::stoul(f[5])) << href;
    EXPECT_EQ(a.text_domain, testdata::unescape(f[6])) << href;
    EXPECT_EQ(a.text_mismatch, f[7] == "1") << href;
    EXPECT_EQ(a.redirector, f[8] == "1") << href;
    EXPECT_EQ(a.esp, testdata::unescape(f[9])) << href;
    EXPECT_EQ(a.shortener, f[10] == "1") << href;
    EXPECT_EQ(a.user_content, f[11] == "1") << href;
    EXPECT_EQ(a.device, f[12] == "1") << href;
    const auto oauth = testdata::unescape_list(f[13]);
    ASSERT_EQ(a.oauth.has_value(), !oauth.empty()) << href;
    if (a.oauth) {
      EXPECT_EQ(a.oauth->provider, oauth.at(0));
      EXPECT_EQ(a.oauth->client_id, oauth.at(1));
      EXPECT_EQ(a.oauth->scope, oauth.at(2));
    }
  }
  EXPECT_GT(n, 100u);
}

// Earlier the click-time path compared the text with the outer (redirector) domain: a SafeLinks link to paypal.com
// whose text says www.paypal.com is no mismatch against its destination.
TEST(Links, RedirectorTextMatchesTheDestination) {
  Fixture fx;
  const auto a = fx.run("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com%2F&data=x",
                        {"www.paypal.com"}, ml::kSourceClick);
  EXPECT_TRUE(a.redirector);
  EXPECT_EQ(a.inner_reg, "paypal.com");
  EXPECT_TRUE(a.text_mismatch);
  EXPECT_NE(a.flags & ml::kLinkTextMatchesInner, 0u);
}

// Earlier a second matcher accepted any two labels as a domain and lost the real one written further right.
TEST(Links, EmbeddedDomainNeedsAKnownTld) {
  Fixture fx;
  const auto a = fx.run("http://abc.qwz.paypal.com.evil.net/", {});
  EXPECT_NE(a.flags & ml::kLinkDomainInSubdomain, 0u);
  EXPECT_EQ(a.embedded_domain, "paypal.com");
  EXPECT_EQ(fx.run("http://www.mybank.com.evil.net/", {}).embedded_domain, "mybank.com");
}

TEST(Links, TextChecks) {
  Fixture fx;
  auto a = fx.run("https://evil.example.net/x", {"https://www.paypal.com/signin"});
  EXPECT_TRUE(a.text_mismatch);
  EXPECT_EQ(a.text_domain, "paypal.com");
  EXPECT_EQ(a.flags & ml::kLinkTextMatchesInner, 0u);
  a = fx.run("https://www.paypal.com/x", {"PayPal.com"});
  EXPECT_FALSE(a.text_mismatch);
  a = fx.run("https://evil.example.net/x", {"pay\xE2\x80\x8Bpal.com"});  // U+200B inside
  EXPECT_NE(a.flags & ml::kLinkTextInvisible, 0u);
  EXPECT_TRUE(a.text_mismatch);
  EXPECT_EQ(a.text_domain, "paypal.com");
  EXPECT_EQ(ml::url_shaped_host("Click here", *fx.psl), "");
  EXPECT_EQ(ml::url_shaped_host("  user@B\xC3\xBC" "cher.de:8080/x  ", *fx.psl), "xn--bcher-kva.de");
}

TEST(Links, StructuralFlags) {
  Fixture fx;
  EXPECT_NE(fx.run("http://0xC0A80001/", {}).flags & ml::kLinkIp, 0u);
  auto a = fx.run("http://paypal.com@evil.net/", {});
  EXPECT_NE(a.flags & ml::kLinkUserinfo, 0u);
  EXPECT_EQ(a.userinfo, "paypal.com");
  EXPECT_TRUE(fx.run("https://bit.ly/abc", {}).shortener);
  EXPECT_TRUE(fx.run("https://example.com/?user_code=ABCD", {}).device);
  EXPECT_FALSE(fx.run("not a url", {}).url);
}

// Up to 0.1.4 a registrable domain over 64 bytes came back as "" (reg, inner_reg, text_domain), so a client's
// domain-level checks skipped long phishing domains such as `<63 letters>.com` and `*.replit.dev` customers.
TEST(Links, LongRegistrableDomainsAreWhole) {
  Fixture fx;
  const std::string label(63, 'a');
  const std::string longcom = label + ".com";  // 67 bytes
  const std::string replit = "c0ffee00-1234-4abc-8def-0123456789ab-00-2k4yq1x9z7m3p.riker.replit.dev";
  ASSERT_GT(replit.size(), 64u);

  auto a = fx.run("https://login." + longcom + "/x", {});
  EXPECT_EQ(a.reg, longcom);
  a = fx.run("https://www." + replit + "/pay", {});
  EXPECT_EQ(a.reg, replit);  // `*.replit.dev`: one customer per registrable domain
  EXPECT_EQ(fx.run("mailto:billing@" + longcom, {}).reg, longcom);

  // The text names the long domain the link goes to: no mismatch; another long domain: a mismatch that names it.
  a = fx.run("https://" + longcom + "/", {longcom});
  EXPECT_FALSE(a.text_mismatch);
  EXPECT_EQ(a.text_domain, longcom);
  a = fx.run("https://evil.example.net/", {"https://" + replit + "/"});
  EXPECT_TRUE(a.text_mismatch);
  EXPECT_EQ(a.text_domain, replit);

  a = fx.run("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2F" + longcom + "%2F&data=x", {});
  EXPECT_TRUE(a.redirector);
  EXPECT_EQ(a.inner_reg, longcom);

  // The longest host DNS allows (253 bytes) still parses, and its registrable domain is whole.
  const std::string host = label + "." + label + "." + label + "." + std::string(57, 'b') + ".com";
  ASSERT_EQ(host.size(), 253u);
  a = fx.run("https://" + host + "/", {});
  ASSERT_TRUE(a.url);
  EXPECT_EQ(a.reg, std::string(57, 'b') + ".com");
  EXPECT_FALSE(fx.run("https://x" + host + "/", {}).url);  // 254 bytes
}

// Link deception checks from raw link facts: the href, the visible text samples and where the link came from. The
// same function serves a mail client's arrival-time decision (facts stored at sync) and its click-time dialog (facts
// of the clicked link), so the two cannot disagree. No network, no I/O.
//
// Thread safety: LinkLists and Psl are immutable; assess() is reentrant.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "maillookalike/psl.h"
#include "maillookalike/url.h"

namespace maillookalike {

// One rule of a shipped list: ECMAScript regexes matched anywhere in the ASCII host and the path (an empty path
// pattern matches every path).
struct HostPathRule {
  std::string kind;  // redirector kind or provider name
  std::string host_re;
  std::string path_re;
  std::vector<std::string> params;  // redirectors: query keys holding the target
  std::string decode;               // redirectors: "", "proofpoint-v2", "proofpoint-v3" or "bing"
};

struct LinkListsData {
  std::vector<HostPathRule> redirectors;
  std::vector<std::string> generic_params;  // query keys whose http(s) value is a redirect target
  std::vector<std::string> esp_trackers;    // host suffixes
  std::vector<std::string> shorteners;      // hosts or registrable domains
  std::vector<std::string> user_content_hosts;  // host suffixes
  std::vector<HostPathRule> oauth;          // authorisation endpoints (kind = provider)
  std::vector<HostPathRule> device;         // device-login endpoints
};

// Reads the list format of tools/lists_tsv.py: one row per line, tab-separated,
// `rule <section> <kind> <host_re> <path_re> <params,comma,separated> <decode>` for the sections redirectors,
// oauth_endpoints and device_login, `item <section> <value>` for generic_redirect_params, esp_trackers, shorteners and
// user_content_hosts. Unknown rows are skipped.
LinkListsData parse_link_lists(std::string_view tsv);

class LinkLists {
 public:
  // nullptr and *error when a regex does not compile.
  static std::shared_ptr<const LinkLists> compile(const LinkListsData& data, std::string* error);
  ~LinkLists();
  LinkLists(const LinkLists&) = delete;
  LinkLists& operator=(const LinkLists&) = delete;
  struct Impl;
  const Impl& impl() const { return *impl_; }

 private:
  LinkLists() = default;
  std::unique_ptr<Impl> impl_;
};

// Letters of hidden text, by the first matching reason in this order.
struct HiddenCounts {
  uint32_t hidden_attr = 0;
  uint32_t display_none = 0;
  uint32_t visibility_hidden = 0;
  uint32_t font_size_zero = 0;
  uint32_t opacity_zero = 0;
  uint32_t zero_height = 0;
  uint64_t total() const {
    return uint64_t{hidden_attr} + display_none + visibility_hidden + font_size_zero + opacity_zero + zero_height;
  }
};

// Where a link came from (bits).
enum LinkSource : uint32_t {  // NOLINT(performance-enum-size): stored as uint32
  kSourceHtml = 1u << 0,      // an HTML anchor
  kSourcePlain = 1u << 1,     // a URL in plain text
  kSourceClick = 1u << 2,     // a clicked link outside any stored inventory
  kSourceQr = 1u << 3,        // decoded from a QR code
  kSourceDocument = 1u << 4,  // a link inside a previewed document
};

struct LinkFacts {
  std::string href;                // as written or canonical; parsed again here
  uint32_t source = 0;             // LinkSource bits
  uint32_t position = 0;           // 0-based order of first appearance
  std::vector<std::string> texts;  // raw visible text samples (bidi/invisible characters kept); empty when none
  HiddenCounts hidden_text;        // hidden letters inside the anchor
  bool anchor_hidden = false;      // the anchor itself is in a hidden subtree
};

// Structural flags (the bit values are stable).
enum LinkFlag : uint32_t {  // NOLINT(performance-enum-size): stored as uint32
  kLinkUserinfo = 1u << 0,
  kLinkIp = 1u << 1,
  kLinkEncodedHost = 1u << 2,
  kLinkIdn = 1u << 3,
  kLinkPort = 1u << 4,
  kLinkSlashes = 1u << 5,
  kLinkManySubdomains = 1u << 6,
  kLinkDomainInSubdomain = 1u << 7,
  kLinkInnerUserinfo = 1u << 8,
  kLinkInnerIp = 1u << 9,
  kLinkInnerIdn = 1u << 10,
  kLinkTextInvisible = 1u << 11,
  kLinkTextMatchesInner = 1u << 12,
  kLinkFromHtml = 1u << 13,
  kLinkFromPlain = 1u << 14,
};

struct OAuthLink {
  std::string provider;
  std::string client_id;  // <= 256 bytes
  std::string scope;      // <= 256 bytes
};

struct LinkAssessment {
  std::optional<Url> url;      // nullopt when the href does not parse (no other field is set)
  std::string reg;             // registrable domain of the host ("" for IP literals, suffix-only hosts)
  std::string inner_reg;       // registrable domain (or IP) of the unwrapped redirect target
  std::string text_domain;     // registrable domain a URL-shaped text names
  bool text_mismatch = false;  // that text domain differs from reg
  uint32_t flags = 0;          // LinkFlag bits
  bool redirector = false;     // a known redirector or a generic redirect parameter
  std::string esp;             // the ESP tracker suffix the host matched
  bool shortener = false;
  bool user_content = false;
  bool device = false;  // device-login endpoint, or a user_code parameter
  std::optional<OAuthLink> oauth;
  std::string embedded_domain;  // the registrable-looking domain written in the subdomain part, when flagged
  std::string userinfo;         // the userinfo text (the fake host a "trusted.com@evil" link shows)
};

LinkAssessment assess(const LinkFacts& facts, const Psl& psl, const LinkLists& lists);

// The host a text names when the whole (cleaned) text is URL-shaped ("https://www.paypal.com/x", "paypal.com"), with
// a known TLD; "" otherwise.
std::string url_shaped_host(std::string_view text, const Psl& psl);

// True when the text holds a bidi control or an invisible format character.
bool has_invisible(std::string_view text);

}  // namespace maillookalike

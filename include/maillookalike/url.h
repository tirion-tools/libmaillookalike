// URL parsing for the link checks: WHATWG-style host handling for special schemes (backslash as slash, userinfo
// stripped, percent-decoded host, UTS #46 IDNA, IPv4 number forms) and path handling (dot segments resolved, escapes of
// unreserved characters decoded). Not a full WHATWG implementation: it yields the canonical form, the host and the
// structural facts the checks need; the path and query are in one spelling, so a browser's serialisation of a URL and
// the href it came from have the same canonical form. Inputs are untrusted UTF-8.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace maillookalike {

struct Url {
  static constexpr size_t kMaxInput = 8192;      // code units after trimming; longer input is refused
  static constexpr size_t kMaxCanonical = 2048;  // bytes of canonical(); whole code points

  std::string scheme;         // lower case, without ':'
  std::string host;           // ASCII (A-labels), lower case; dotted quad for IPv4; "[...]" for IPv6
  std::string unicode_host;   // UTS #46 ToUnicode of host, NFKC, lower case (analysis only)
  std::string userinfo_text;  // the userinfo before '@' (empty when none)
  std::string path = "/";     // '\' turned into '/', dot segments resolved, fragment dropped; normalised escapes:
                              // unreserved characters decoded, other escapes upper-case hex, and controls, space,
                              // non-ASCII and " ' < > \ ^ ` { | } escaped
  std::string query;          // without '?'; escapes normalised as in path
  std::string canonical;      // scheme://host[:port]path[?query]; "mailto:addr"; "scheme:rest" for others
  std::string mailto_domain;  // ACE domain of the first mailto address (empty when none)
  bool userinfo = false;
  bool ip = false;               // IPv4 (any WHATWG number form) or an IPv6 literal
  bool encoded_host = false;     // the host held '%'
  bool idn = false;              // non-ASCII host input or an xn-- label
  bool non_default_port = false;
  bool bad_slashes = false;      // backslashes or not exactly two slashes after a special scheme

  // Why parse() refused an input.
  enum class Refusal : uint8_t {
    kNone,
    kTooLong,  // over kMaxInput code units after trimming: refused whole, never cut (a part past a cut is unchecked)
    kBadHost,  // a host UTS #46 refuses (host_forms)
    kOther,    // empty, no scheme
  };

  // nullopt for empty, oversized, scheme-less input or a host IDNA refuses; `why` (optional) says which. "www." gets
  // "http://".
  static std::optional<Url> parse(std::string_view utf8, Refusal* why = nullptr);

  // Decoded query parameters ('+' as space, keys lower-cased), split on '&' and ';'; at most 64.
  std::vector<std::pair<std::string, std::string>> query_params() const;
};

// Host to its ASCII and Unicode forms; nullopt when UTS #46 refuses it or it is empty or over 253 bytes. UTS #46 runs
// with the library's one option set, the lookalike engine's too: non-transitional both ways, CheckBidi and
// CheckJoiners (WHATWG URL's), so a host with a ZWJ/ZWNJ out of its allowed context is refused everywhere.
struct HostForms {
  std::string ascii;
  std::string unicode;
  bool idn = false;
};
std::optional<HostForms> host_forms(std::string_view host);

// The WHATWG IPv4 parser (1-4 parts, decimal, 0x hex, 0-prefixed octal): a dotted quad, or nullopt.
std::optional<std::string> parse_ipv4(std::string_view host);

// %XX decoding of UTF-8 (invalid escapes or invalid UTF-8 leave the input unchanged).
std::string percent_decode(std::string_view s);

}  // namespace maillookalike

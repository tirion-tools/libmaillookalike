#include "maillookalike/url.h"

#include <unicode/locid.h>
#include <unicode/normalizer2.h>
#include <unicode/uidna.h>
#include <unicode/unistr.h>

#include <algorithm>
#include <cstdint>
#include <mutex>

#include "text.h"

namespace maillookalike {

using detail::append_utf8;
using detail::ascii_lower;
using detail::clip_utf8;
using detail::next_cp;

namespace {

int hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// UTF-16 code units of a UTF-8 string (the unit the engine's length limits count).
size_t utf16_units(std::string_view s) {
  size_t n = 0;
  for (size_t i = 0; i < s.size();) n += next_cp(s, i) > 0xFFFF ? 2 : 1;
  return n;
}

const UIDNA* idna() {
  static UIDNA* h = [] {
    UErrorCode st = U_ZERO_ERROR;
    UIDNA* p = uidna_openUTS46(UIDNA_CHECK_BIDI | UIDNA_NONTRANSITIONAL_TO_ASCII | UIDNA_NONTRANSITIONAL_TO_UNICODE, &st);
    return U_SUCCESS(st) ? p : nullptr;
  }();
  return h;
}

bool is_space(char32_t c) {
  // char.IsWhiteSpace for the trim of a host: ASCII and Unicode white space.
  return c == ' ' || (c >= 0x09 && c <= 0x0D) || c == 0x85 || c == 0xA0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200A) ||
         c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000;
}

std::string replace_all(std::string s, std::string_view from, std::string_view to) {
  for (size_t p = 0; (p = s.find(from, p)) != std::string::npos; p += to.size()) s.replace(p, from.size(), to);
  return s;
}

// WHATWG "forbidden domain code point": C0 controls, space, # % / : < > ? @ [ \ ] ^ |, U+007F. A percent-decoded
// host that contains one is a host-parsing failure.
bool has_forbidden_domain_code_point(std::string_view h) {
  return std::any_of(h.begin(), h.end(), [](char ch) {
    const auto c = static_cast<unsigned char>(ch);
    return c <= 0x20 || c == 0x7F || std::string_view("#%/:<>?@[\\]^|").find(ch) != std::string_view::npos;
  });
}

}  // namespace

std::string percent_decode(std::string_view s) {
  if (s.find('%') == std::string_view::npos) return std::string(s);
  auto escaped = [&](size_t j) { return j + 2 < s.size() && s[j] == '%' && hex(s[j + 1]) >= 0 && hex(s[j + 2]) >= 0; };
  std::string out;
  out.reserve(s.size());
  size_t i = 0;
  while (i < s.size()) {
    if (!escaped(i)) {
      out += s[i++];
      continue;
    }
    // A run of escapes: decode it, keep the valid UTF-8 sequences, re-emit invalid bytes escaped.
    std::string bytes;
    std::vector<size_t> starts;
    size_t j = i;
    for (; escaped(j); j += 3) {
      starts.push_back(j);
      bytes += static_cast<char>(hex(s[j + 1]) * 16 + hex(s[j + 2]));
    }
    for (size_t k = 0; k < bytes.size();) {
      size_t m = k;
      const char32_t c = next_cp(bytes, m);
      if (c == 0xFFFD && bytes.compare(k, 3, "\xEF\xBF\xBD") != 0) {
        out.append(s.substr(starts[k], 3));
        ++k;
        continue;
      }
      out.append(bytes, k, m - k);
      k = m;
    }
    i = j;
  }
  return out;
}

std::optional<HostForms> host_forms(std::string_view raw) {
  // Trim white space, then trailing dots.
  size_t b = 0, e = raw.size();
  while (b < e) {
    size_t k = b;
    if (!is_space(next_cp(raw, k))) break;
    b = k;
  }
  std::string_view h = raw.substr(b, e - b);
  while (!h.empty()) {
    // Trailing white space (ASCII and the common Unicode spaces).
    if (h.back() == ' ' || (h.back() >= 0x09 && h.back() <= 0x0D)) {
      h.remove_suffix(1);
      continue;
    }
    break;
  }
  while (!h.empty() && h.back() == '.') h.remove_suffix(1);
  const size_t units = utf16_units(h);
  if (units == 0 || units > 253 || idna() == nullptr) return std::nullopt;
  char buf[1024];
  UErrorCode st = U_ZERO_ERROR;
  UIDNAInfo info = UIDNA_INFO_INITIALIZER;
  int32_t n = uidna_nameToASCII_UTF8(idna(), h.data(), static_cast<int32_t>(h.size()), buf, sizeof buf, &info, &st);
  // "--" in the third and fourth positions is accepted, as by the reference (.NET IdnMapping, which ignores
  // UIDNA_ERROR_HYPHEN_3_4); leading and trailing hyphens are not.
  if (U_FAILURE(st) || (info.errors & ~uint32_t{UIDNA_ERROR_HYPHEN_3_4}) != 0 || n <= 0 || n >= static_cast<int32_t>(sizeof buf))
    return std::nullopt;
  HostForms r;
  r.ascii = ascii_lower(std::string_view(buf, static_cast<size_t>(n)));
  st = U_ZERO_ERROR;
  info = UIDNA_INFO_INITIALIZER;
  char ubuf[2048];
  n = uidna_nameToUnicodeUTF8(idna(), r.ascii.data(), static_cast<int32_t>(r.ascii.size()), ubuf, sizeof ubuf, &info, &st);
  std::string uni = U_FAILURE(st) || info.errors != 0 || n < 0 || n >= static_cast<int32_t>(sizeof ubuf)
                        ? r.ascii
                        : std::string(ubuf, static_cast<size_t>(n));
  st = U_ZERO_ERROR;
  const icu::Normalizer2* nfkc = icu::Normalizer2::getNFKCInstance(st);
  icu::UnicodeString us = icu::UnicodeString::fromUTF8(uni);
  if (U_SUCCESS(st)) us = nfkc->normalize(us, st);
  us.toLower(icu::Locale::getRoot());
  r.unicode.clear();
  us.toUTF8String(r.unicode);
  for (size_t p = 0; p < r.ascii.size();) {
    if (r.ascii.compare(p, 4, "xn--") == 0) r.idn = true;
    const size_t dot = r.ascii.find('.', p);
    if (dot == std::string::npos) break;
    p = dot + 1;
  }
  return r;
}

std::optional<std::string> parse_ipv4(std::string_view host) {
  while (!host.empty() && host.back() == '.') host.remove_suffix(1);
  if (host.empty() || host.size() > 64) return std::nullopt;
  std::vector<uint64_t> nums;
  size_t p = 0;
  while (true) {
    const size_t dot = host.find('.', p);
    const std::string_view part = host.substr(p, dot == std::string_view::npos ? std::string_view::npos : dot - p);
    if (part.empty() || nums.size() == 4) return std::nullopt;
    uint64_t v = 0;
    if (part.size() >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X')) {
      if (part.size() > 2 + 16) return std::nullopt;
      for (char c : part.substr(2)) {
        const int d = hex(c);
        if (d < 0) return std::nullopt;
        v = (v << 4) | static_cast<uint64_t>(d);
      }
    } else if (part.size() > 1 && part[0] == '0') {
      for (char c : part.substr(1)) {
        if (c < '0' || c > '7' || v > (UINT64_MAX >> 3)) return std::nullopt;
        v = (v << 3) | static_cast<uint64_t>(c - '0');
      }
    } else {
      for (char c : part) {
        if (c < '0' || c > '9') return std::nullopt;
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
      }
    }
    nums.push_back(v);
    if (dot == std::string_view::npos) break;
    p = dot + 1;
  }
  for (size_t i = 0; i + 1 < nums.size(); ++i)
    if (nums[i] > 255) return std::nullopt;
  const uint64_t last = nums.back();
  if (last >= (uint64_t{1} << (8 * (5 - nums.size())))) return std::nullopt;
  uint64_t ip = last;
  for (size_t i = 0; i + 1 < nums.size(); ++i) ip += nums[i] << (8 * (3 - i));
  return std::to_string((ip >> 24) & 255) + "." + std::to_string((ip >> 16) & 255) + "." +
         std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}

std::optional<Url> Url::parse(std::string_view raw) {
  if (raw.size() > kMaxInput * 2 * 3) return std::nullopt;
  // Trim space, NUL..BEL, BS and FF at both ends, then drop tab, LF and CR everywhere.
  auto trimmed = [](char c) { return c == ' ' || (c >= 0 && c <= 0x08) || c == '\f'; };
  size_t b = 0, e = raw.size();
  while (b < e && trimmed(raw[b])) ++b;
  while (e > b && trimmed(raw[e - 1])) --e;
  std::string s;
  s.reserve(e - b);
  for (size_t i = b; i < e; ++i)
    if (raw[i] != '\t' && raw[i] != '\n' && raw[i] != '\r') s += raw[i];
  if (s.empty() || utf16_units(s) > kMaxInput) return std::nullopt;
  if (s.size() >= 4 && ascii_lower(s.substr(0, 4)) == "www.") s = "http://" + s;
  // Scheme: a letter, then up to 31 of [A-Za-z0-9+.-], then ':'.
  size_t k = 0;
  auto alpha = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); };
  if (!alpha(s[0])) return std::nullopt;
  k = 1;
  while (k < s.size() && k <= 31 &&
         (alpha(s[k]) || (s[k] >= '0' && s[k] <= '9') || s[k] == '+' || s[k] == '.' || s[k] == '-'))
    ++k;
  if (k >= s.size() || s[k] != ':') return std::nullopt;
  Url u;
  u.scheme = ascii_lower(s.substr(0, k));
  std::string rest = s.substr(k + 1);
  if (u.scheme == "mailto") {
    std::string addr = rest.substr(0, rest.find('?'));
    addr = percent_decode(addr.substr(0, addr.find(',')));
    const size_t at = addr.rfind('@');
    if (at != std::string::npos && at > 0)
      if (auto h = host_forms(std::string_view(addr).substr(at + 1))) u.mailto_domain = h->ascii;
    u.canonical = clip_utf8("mailto:" + addr, kMaxCanonical);
    return u;
  }
  if (u.scheme != "http" && u.scheme != "https" && u.scheme != "ftp" && u.scheme != "ws" && u.scheme != "wss" &&
      u.scheme != "file") {
    // The first 200 UTF-16 code units of the rest.
    size_t end = 0, units = 0;
    for (size_t i = 0; i < rest.size();) {
      size_t j = i;
      const char32_t c = next_cp(rest, j);
      const size_t w = c > 0xFFFF ? 2 : 1;
      if (units + w > 200) break;
      units += w;
      end = i = j;
    }
    u.canonical = u.scheme + ":" + rest.substr(0, end);
    return u;
  }
  size_t slashes = 0;
  while (slashes < rest.size() && (rest[slashes] == '/' || rest[slashes] == '\\')) ++slashes;
  if (slashes != 2 || (!rest.empty() && rest[0] == '\\') || (rest.size() > 1 && rest[1] == '\\')) u.bad_slashes = true;
  rest = rest.substr(slashes);
  const size_t end = rest.find_first_of("/\\?#");
  std::string authority = end == std::string::npos ? rest : rest.substr(0, end);
  std::string tail = end == std::string::npos ? std::string() : rest.substr(end);
  const size_t atp = authority.rfind('@');
  if (atp != std::string::npos) {
    u.userinfo = true;
    u.userinfo_text = authority.substr(0, atp);
    authority = authority.substr(atp + 1);
  }
  std::string host_part = authority, port;
  if (!authority.empty() && authority[0] == '[') {
    const size_t rb = authority.find(']');
    host_part = rb != std::string::npos && rb > 0 ? authority.substr(0, rb + 1) : authority;
    if (rb != std::string::npos && rb > 0 && rb + 1 < authority.size() && authority[rb + 1] == ':')
      port = authority.substr(rb + 2);
    u.ip = true;
    u.host = ascii_lower(host_part);
    u.unicode_host = u.host;
  } else {
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
      port = authority.substr(colon + 1);
      host_part = authority.substr(0, colon);
    }
    if (host_part.find('%') != std::string::npos) {
      u.encoded_host = true;
      host_part = percent_decode(host_part);
      if (has_forbidden_domain_code_point(host_part)) return std::nullopt;
    }
    host_part = replace_all(host_part, "\xE3\x80\x82", ".");  // U+3002
    host_part = replace_all(host_part, "\xEF\xBC\x8E", ".");  // U+FF0E
    host_part = replace_all(host_part, "\xEF\xBD\xA1", ".");  // U+FF61
    if (std::any_of(host_part.begin(), host_part.end(), [](char c) { return static_cast<unsigned char>(c) > 0x7F; }))
      u.idn = true;
    if (auto v4 = parse_ipv4(host_part)) {
      u.ip = true;
      u.host = *v4;
      u.unicode_host = u.host;
    } else {
      auto h = host_forms(host_part);
      if (!h) return std::nullopt;
      u.host = h->ascii;
      u.unicode_host = h->unicode;
      u.idn = u.idn || h->idn;
    }
  }
  if (!port.empty() && port != (u.scheme == "https" ? "443" : "80")) u.non_default_port = true;
  std::replace(tail.begin(), tail.end(), '\\', '/');
  if (const size_t hash = tail.find('#'); hash != std::string::npos) tail.resize(hash);
  const size_t q = tail.find('?');
  u.path = q == std::string::npos ? tail : tail.substr(0, q);
  if (u.path.empty()) u.path = "/";
  u.query = q == std::string::npos ? std::string() : tail.substr(q + 1);
  u.canonical = clip_utf8(u.scheme + "://" + u.host + (u.non_default_port ? ":" + port : std::string()) + u.path +
                              (u.query.empty() ? std::string() : "?" + u.query),
                          kMaxCanonical);
  return u;
}

std::vector<std::pair<std::string, std::string>> Url::query_params() const {
  std::vector<std::pair<std::string, std::string>> r;
  if (query.empty()) return r;
  size_t p = 0;
  while (r.size() < 64) {
    const size_t sep = query.find_first_of("&;", p);
    std::string kv = query.substr(p, sep == std::string::npos ? std::string::npos : sep - p);
    std::replace(kv.begin(), kv.end(), '+', ' ');
    const size_t eq = kv.find('=');
    std::string key = eq == std::string::npos ? kv : kv.substr(0, eq);
    std::string val = eq == std::string::npos ? std::string() : kv.substr(eq + 1);
    // Keys: ToLowerInvariant after decoding.
    icu::UnicodeString ku = icu::UnicodeString::fromUTF8(percent_decode(key));
    ku.toLower(icu::Locale::getRoot());
    std::string kl;
    ku.toUTF8String(kl);
    r.emplace_back(std::move(kl), percent_decode(val));
    if (sep == std::string::npos) break;
    p = sep + 1;
  }
  return r;
}

}  // namespace maillookalike

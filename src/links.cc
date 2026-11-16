#include "maillookalike/links.h"

#include <algorithm>
#include <regex>
#include <unordered_set>

#include "text.h"

namespace maillookalike {

using detail::append_utf8;
using detail::clean_text;
using detail::clip_utf8;
using detail::next_cp;

namespace {

constexpr size_t kMaxDomain = 64;  // longer domains are dropped whole (a cut domain would name another one)
constexpr int kMaxUnwrap = 3;

struct Rule {
  std::string kind;
  std::regex host;
  std::optional<std::regex> path;
  std::vector<std::string> params;
  std::string decode;
};

bool host_is(std::string_view host, std::string_view suffix) {
  return host == suffix || (host.size() > suffix.size() && host.substr(host.size() - suffix.size()) == suffix &&
                            host[host.size() - suffix.size() - 1] == '.');
}

std::string whole(std::string s) { return s.size() > kMaxDomain ? std::string() : s; }

bool match(const std::regex& re, const std::string& s) {
  try {
    return std::regex_search(s, re);
  } catch (const std::regex_error&) {
    return false;  // complexity or stack limits: no match
  }
}

std::u32string to_u32(std::string_view s) {
  std::u32string r;
  for (size_t i = 0; i < s.size();) r += next_cp(s, i);
  return r;
}

std::string from_u32(std::u32string_view s) {
  std::string r;
  for (char32_t c : s) append_utf8(r, c);
  return r;
}

// Base64 (standard alphabet, padded); nullopt on invalid input.
std::optional<std::string> base64_decode(std::string_view in) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  if (in.size() % 4 != 0) return std::nullopt;
  std::string out;
  for (size_t i = 0; i < in.size(); i += 4) {
    int v[4];
    int pad = 0;
    for (int k = 0; k < 4; ++k) {
      const char c = in[i + static_cast<size_t>(k)];
      if (c == '=') {
        if (i + 4 != in.size() || k < 2) return std::nullopt;
        v[k] = 0;
        ++pad;
      } else {
        if (pad) return std::nullopt;
        v[k] = val(c);
        if (v[k] < 0) return std::nullopt;
      }
    }
    const uint32_t n = (uint32_t(v[0]) << 18) | (uint32_t(v[1]) << 12) | (uint32_t(v[2]) << 6) | uint32_t(v[3]);
    out += static_cast<char>((n >> 16) & 0xFF);
    if (pad < 2) out += static_cast<char>((n >> 8) & 0xFF);
    if (pad < 1) out += static_cast<char>(n & 0xFF);
  }
  return out;
}

// Invalid UTF-8 → U+FFFD (Encoding.UTF8.GetString).
std::string utf8_repair(std::string_view s) {
  std::string r;
  for (size_t i = 0; i < s.size();) append_utf8(r, next_cp(s, i));
  return r;
}

bool starts_with_ci(std::string_view s, std::string_view p) {
  if (s.size() < p.size()) return false;
  for (size_t i = 0; i < p.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(s[i])) != p[i]) return false;
  return true;
}

std::vector<std::string> split_labels(std::string_view s) {
  std::vector<std::string> r;
  size_t p = 0;
  while (true) {
    const size_t d = s.find('.', p);
    r.emplace_back(s.substr(p, d == std::string_view::npos ? std::string_view::npos : d - p));
    if (d == std::string_view::npos) break;
    p = d + 1;
  }
  return r;
}

bool tld_like(const std::string& l) {
  return l.size() >= 2 && l.size() <= 24 &&
         std::all_of(l.begin(), l.end(), [](char c) { return (c >= 'a' && c <= 'z') || c == '-' || (c >= '0' && c <= '9'); });
}

}  // namespace

struct LinkLists::Impl {
  std::vector<Rule> redirectors, oauth, device;
  std::unordered_set<std::string> generic_params, shorteners;
  std::vector<std::string> esp, user_content;
};

LinkLists::~LinkLists() = default;

std::shared_ptr<const LinkLists> LinkLists::compile(const LinkListsData& d, std::string* error) {
  std::shared_ptr<LinkLists> l(new LinkLists());
  l->impl_ = std::make_unique<Impl>();
  Impl& m = *l->impl_;
  auto rules = [&](const std::vector<HostPathRule>& in, std::vector<Rule>& out) {
    for (const HostPathRule& r : in) {
      Rule x;
      x.kind = r.kind;
      x.host = std::regex(r.host_re, std::regex::ECMAScript | std::regex::optimize);
      if (!r.path_re.empty()) x.path = std::regex(r.path_re, std::regex::ECMAScript | std::regex::optimize);
      x.params = r.params;
      x.decode = r.decode;
      out.push_back(std::move(x));
    }
  };
  try {
    rules(d.redirectors, m.redirectors);
    rules(d.oauth, m.oauth);
    rules(d.device, m.device);
  } catch (const std::regex_error& e) {
    if (error) *error = std::string("link list regex: ") + e.what();
    return nullptr;
  }
  m.generic_params.insert(d.generic_params.begin(), d.generic_params.end());
  m.shorteners.insert(d.shorteners.begin(), d.shorteners.end());
  m.esp = d.esp_trackers;
  m.user_content = d.user_content_hosts;
  return l;
}

bool has_invisible(std::string_view text) {
  for (size_t i = 0; i < text.size();) {
    const char32_t c = next_cp(text, i);
    if (detail::is_bidi(c) || detail::is_invisible(c)) return true;
  }
  return false;
}

std::string url_shaped_host(std::string_view text, const Psl& psl) {
  // ^\s*(?:https?://|www\.)?(?:[^\s@/]+@)?([A-Za-z0-9\u00C0-\uFFFF.-]+\.[A-Za-z\u00C0-\uFFFF]{2,63})(?::\d+)?
  // (?:[/?#]\S*)?\s*$ over the cleaned text; supplementary characters count as letters (UTF-16 surrogates do).
  static const std::wregex re(
      L"^\\s*(?:(?:https?://)|(?:www\\.))?(?:[^\\s@/]+@)?"
      L"([A-Za-z0-9\u00C0-\U0010FFFF.-]+\\.[A-Za-z\u00C0-\U0010FFFF]{2,63})(?::[0-9]+)?(?:[/?#]\\S*)?\\s*$",
      std::regex::ECMAScript);
  const std::string clean = clean_text(text, 256);
  const std::u32string u = to_u32(clean);
  const std::wstring w(u.begin(), u.end());
  std::wsmatch m;
  try {
    if (!std::regex_match(w, m, re)) return {};
  } catch (const std::regex_error&) {
    return {};
  }
  const std::wstring g = m[1].str();
  const std::u32string g32(g.begin(), g.end());
  auto h = host_forms(from_u32(g32));
  if (!h || !psl.has_known_tld(h->ascii)) return {};
  return h->ascii;
}

namespace {

struct Ctx {
  const Psl& psl;
  const LinkLists::Impl& lists;
};

std::string embedded(const Ctx& c, const std::vector<std::string>& labels) {
  for (size_t i = 0; i + 1 < labels.size(); ++i)
    for (size_t j = i + 2; j <= labels.size(); ++j) {
      std::string c2;
      for (size_t k = i; k < j; ++k) c2 += (k > i ? "." : "") + labels[k];
      if (!tld_like(labels[j - 1]) || !c.psl.has_known_tld(c2)) continue;
      if (c.psl.registrable(c2) == c2 && labels[i].size() >= 3) return c2;
    }
  return {};
}

void unwrap(const Ctx& c, const Url& u, LinkAssessment& r, uint32_t& flags, std::string& inner_reg, int depth) {
  if (depth >= kMaxUnwrap) return;
  std::optional<std::string> inner;
  std::string kind;
  for (const Rule& rd : c.lists.redirectors) {
    if (!match(rd.host, u.host)) continue;
    if (rd.path && !match(*rd.path, u.path)) continue;
    kind = rd.kind;
    if (rd.decode == "proofpoint-v3") {
      const std::string p = u.path + (u.query.empty() ? std::string() : "?" + u.query);
      const size_t a = p.find("__");
      const size_t b = a == std::string::npos ? std::string::npos : p.find("__", a + 2);
      if (a != std::string::npos && b != std::string::npos && b > a) inner = p.substr(a + 2, b - a - 2);
    } else {
      for (auto [k, v] : u.query_params()) {
        if (std::find(rd.params.begin(), rd.params.end(), k) == rd.params.end()) continue;
        std::string val = v;
        if (rd.decode == "proofpoint-v2") {
          std::replace(val.begin(), val.end(), '-', '%');
          std::replace(val.begin(), val.end(), '_', '/');
          val = percent_decode(val);
        }
        if (rd.decode == "bing" && val.rfind("a1", 0) == 0) {
          std::string b64 = val.substr(2);
          std::replace(b64.begin(), b64.end(), '-', '+');
          std::replace(b64.begin(), b64.end(), '_', '/');
          b64.append((4 - b64.size() % 4) % 4, '=');
          auto dec = base64_decode(b64);
          if (!dec) continue;
          val = utf8_repair(*dec);
        }
        inner = val;
        break;
      }
    }
    break;
  }
  if (!inner && !r.oauth) {
    for (auto [k, v] : u.query_params()) {
      if (c.lists.generic_params.count(k) == 0) continue;
      size_t b = 0;
      while (b < v.size()) {
        size_t n = b;
        const char32_t ch = next_cp(v, n);
        if (!(ch == ' ' || (ch >= 0x09 && ch <= 0x0D) || ch == 0x85 || ch == 0xA0 || ch == 0x1680 ||
              (ch >= 0x2000 && ch <= 0x200A) || ch == 0x2028 || ch == 0x2029 || ch == 0x202F || ch == 0x205F ||
              ch == 0x3000))
          break;
        b = n;
      }
      const std::string t = v.substr(b);
      if (starts_with_ci(t, "http://") || starts_with_ci(t, "https://")) {
        inner = t;
        if (kind.empty()) kind = "generic";
        break;
      }
    }
  }
  if (!kind.empty() && depth == 0) r.redirector = true;
  if (!inner) return;
  auto iu = Url::parse(*inner);
  if (!iu || (iu->scheme != "http" && iu->scheme != "https")) return;
  inner_reg = iu->ip ? iu->host : c.psl.registrable(iu->host);
  if (iu->userinfo && (flags & kLinkUserinfo) == 0) flags |= kLinkInnerUserinfo;
  if (iu->ip) flags |= kLinkInnerIp;
  if (iu->idn) flags |= kLinkInnerIdn;
  unwrap(c, *iu, r, flags, inner_reg, depth + 1);
}

void compare_text(const Ctx& c, LinkAssessment& r, const std::vector<std::string>& texts, const std::string& reg,
                  const std::string& inner_reg, uint32_t& flags) {
  for (const std::string& t : texts) {
    if (has_invisible(t)) flags |= kLinkTextInvisible;
    const std::string h = url_shaped_host(t, c.psl);
    if (h.empty()) continue;
    const std::string treg = c.psl.registrable(h);
    if (treg.empty()) continue;
    r.text_domain = whole(treg);
    if (reg.empty() || treg != reg) {
      r.text_mismatch = true;
      if (!inner_reg.empty() && inner_reg == treg) flags |= kLinkTextMatchesInner;
      return;
    }
  }
}

}  // namespace

LinkAssessment assess(const LinkFacts& f, const Psl& psl, const LinkLists& lists) {
  LinkAssessment r;
  r.url = Url::parse(f.href);
  if (!r.url) return r;
  const Url& u = *r.url;
  const Ctx c{psl, lists.impl()};
  uint32_t flags = 0;
  if (f.source & kSourceHtml) flags |= kLinkFromHtml;
  if (f.source & kSourcePlain) flags |= kLinkFromPlain;
  if (u.scheme == "mailto") {
    r.reg = whole(psl.registrable(u.mailto_domain));
    r.flags = flags;
    return r;
  }
  if (u.userinfo) {
    flags |= kLinkUserinfo;
    r.userinfo = u.userinfo_text;
  }
  if (u.ip) flags |= kLinkIp;
  if (u.encoded_host) flags |= kLinkEncodedHost;
  if (u.idn) flags |= kLinkIdn;
  if (u.non_default_port) flags |= kLinkPort;
  if (u.bad_slashes) flags |= kLinkSlashes;
  if (u.scheme != "http" && u.scheme != "https") {
    r.flags = flags;
    return r;
  }
  const std::string reg = u.ip ? std::string() : psl.registrable(u.host);
  if (!reg.empty()) {
    const std::string sub = u.host.size() > reg.size() ? u.host.substr(0, u.host.size() - reg.size() - 1) : "";
    const std::vector<std::string> labels = sub.empty() ? std::vector<std::string>() : split_labels(sub);
    if (labels.size() >= 4) flags |= kLinkManySubdomains;
    // "paypal.com.secure-login.evil.tld": a registrable domain inside the subdomain part.
    if (labels.size() >= 2) {
      r.embedded_domain = embedded(c, labels);
      if (!r.embedded_domain.empty()) flags |= kLinkDomainInSubdomain;
    }
  }
  r.reg = whole(reg);
  std::string inner_reg;
  unwrap(c, u, r, flags, inner_reg, 0);
  r.inner_reg = whole(inner_reg);
  for (const std::string& e : c.lists.esp)
    if (host_is(u.host, e)) {
      r.esp = e;
      break;
    }
  r.shortener = c.lists.shorteners.count(u.host) != 0 || (!reg.empty() && c.lists.shorteners.count(reg) != 0);
  for (const std::string& h : c.lists.user_content)
    if (host_is(u.host, h)) {
      r.user_content = true;
      break;
    }
  const std::string path_lower = detail::ascii_lower(u.path);
  const auto params = u.query_params();
  auto param = [&](std::string_view key) -> std::string {
    for (const auto& [k, v] : params)
      if (k == key) return v;
    return {};
  };
  for (const Rule& o : c.lists.oauth) {
    if (!match(o.host, u.host) || !o.path || !match(*o.path, path_lower)) continue;
    const std::string cid = param("client_id");
    if (cid.empty()) continue;
    r.oauth = OAuthLink{clip_utf8(o.kind, 64), clip_utf8(cid, 256), clip_utf8(param("scope"), 256)};
    break;
  }
  for (const Rule& d : c.lists.device)
    if (match(d.host, u.host) && d.path && match(*d.path, path_lower)) {
      r.device = true;
      break;
    }
  if (!r.device)
    for (const auto& kv : params)
      if (kv.first == "user_code") {
        r.device = true;
        break;
      }
  if (!f.texts.empty()) compare_text(c, r, f.texts, reg, inner_reg, flags);
  r.flags = flags;
  return r;
}

}  // namespace maillookalike

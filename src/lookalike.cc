// Lookalike engine (see lookalike.h). The Public Suffix List is a small matcher over the caller's pinned list text.
//
// The IDN display decision (SafeToDisplayAsUnicode, the whole-script confusable table, the dangerous-pattern
// regex, the allowed character set and the skeleton supplements) is a port of Chromium 156.0.8078.88
// components/url_formatter/spoof_checks/{idn_spoof_checker,skeleton_generator}.cc (BSD-3-Clause,
// Copyright The Chromium Authors), adapted to ICU's public C/C++ API.
#include "maillookalike/lookalike.h"

#include <unicode/locid.h>
#include <unicode/normalizer2.h>
#include <unicode/regex.h>
#include <unicode/schriter.h>
#include <unicode/translit.h>
#include <unicode/uchar.h>
#include <unicode/uidna.h>
#include <unicode/uniset.h>
#include <unicode/unistr.h>
#include <unicode/uscript.h>
#include <unicode/uspoof.h>

#include <algorithm>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace maillookalike {
namespace {

using icu::UnicodeSet;
using icu::UnicodeString;

constexpr size_t kMaxHostBytes = 253;
constexpr int32_t kMaxNameCodePoints = 256;

std::string to_utf8(const UnicodeString& s) {
  std::string out;
  s.toUTF8String(out);
  return out;
}

std::u32string to_u32(const UnicodeString& s) {
  std::u32string out;
  out.reserve(s.length());
  for (int32_t i = 0; i < s.length();) {
    UChar32 c = s.char32At(i);
    out.push_back(static_cast<char32_t>(c));
    i += U16_LENGTH(c);
  }
  return out;
}


std::string u32_to_utf8(const std::u32string& s) {
  std::string o;
  o.reserve(s.size());
  for (char32_t c : s) {
    if (c < 0x80) {
      o.push_back(static_cast<char>(c));
    } else if (c < 0x800) {
      o.push_back(static_cast<char>(0xC0 | (c >> 6)));
      o.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else if (c < 0x10000) {
      o.push_back(static_cast<char>(0xE0 | (c >> 12)));
      o.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
      o.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else {
      o.push_back(static_cast<char>(0xF0 | (c >> 18)));
      o.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
      o.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
      o.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
  }
  return o;
}

bool is_ascii(std::string_view s) {
  for (unsigned char c : s)
    if (c >= 0x80) return false;
  return true;
}

bool is_ascii(const UnicodeString& s) {
  for (int32_t i = 0; i < s.length(); ++i)
    if (s.charAt(i) >= 0x80) return false;
  return true;
}

std::string ascii_lower(std::string_view s) {
  std::string out(s);
  for (char& c : out)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return out;
}

std::vector<std::string> split(std::string_view s, char sep) {
  std::vector<std::string> out;
  size_t start = 0;
  while (true) {
    size_t p = s.find(sep, start);
    out.emplace_back(s.substr(start, p == std::string_view::npos ? std::string_view::npos : p - start));
    if (p == std::string_view::npos) break;
    start = p + 1;
  }
  return out;
}

std::string join(const std::vector<std::string>& v, size_t from, size_t to, char sep) {
  std::string out;
  for (size_t i = from; i < to; ++i) {
    if (i > from) out.push_back(sep);
    out += v[i];
  }
  return out;
}

// Keys fold the skeleton's "rn" (UTS #39 prototype of m) to m; expand_m restores the raw skeleton form.
std::u32string expand_m(const std::u32string& k) {
  std::u32string o;
  o.reserve(k.size() + 2);
  for (char32_t c : k) {
    if (c == U'm') o += U"rn";
    else o.push_back(c);
  }
  return o;
}
std::u32string fold_m(const std::u32string& k) {
  std::u32string o;
  o.reserve(k.size());
  for (size_t i = 0; i < k.size(); ++i) {
    if (k[i] == U'r' && i + 1 < k.size() && k[i + 1] == U'n') {
      o.push_back(U'm');
      ++i;
    } else {
      o.push_back(k[i]);
    }
  }
  return o;
}
// Polynomial hashes over keys (mod 2^64), so single-deletion and transposition neighbourhoods are probed
// without building strings. Collisions only add candidates; every candidate is verified with OSA distance.
constexpr uint64_t kHashBase = 0x100000001b3ULL;
uint64_t poly_hash(std::u32string_view s) {
  uint64_t h = 0;
  for (char32_t c : s) h = h * kHashBase + (static_cast<uint64_t>(c) + 1);
  return h;
}
// Appends the hash of s and of every single-character deletion of s.
void deletion_hashes(std::u32string_view s, std::vector<uint64_t>* out) {
  const size_t n = s.size();
  uint64_t pw[96];
  uint64_t pre[97];
  uint64_t suf[97];
  if (n > 95) return;  // labels are at most 63 characters; keys stay well below this
  pw[0] = 1;
  for (size_t i = 0; i < n; ++i) pw[i + 1] = pw[i] * kHashBase;
  pre[0] = 0;
  for (size_t i = 0; i < n; ++i) pre[i + 1] = pre[i] * kHashBase + (static_cast<uint64_t>(s[i]) + 1);
  suf[n] = 0;
  for (size_t i = n; i-- > 0;) suf[i] = (static_cast<uint64_t>(s[i]) + 1) * pw[n - 1 - i] + suf[i + 1];
  out->push_back(pre[n]);
  for (size_t j = 0; j < n; ++j) out->push_back(pre[j] * pw[n - 1 - j] + suf[j + 1]);
}
// Appends the hash of every adjacent transposition of s.
void transposition_hashes(std::u32string_view s, std::vector<uint64_t>* out) {
  const size_t n = s.size();
  if (n < 2 || n > 95) return;
  uint64_t pw[96];
  pw[0] = 1;
  for (size_t i = 0; i < n; ++i) pw[i + 1] = pw[i] * kHashBase;
  const uint64_t h = poly_hash(s);
  for (size_t j = 0; j + 1 < n; ++j) {
    const uint64_t a = static_cast<uint64_t>(s[j]) + 1;
    const uint64_t b = static_cast<uint64_t>(s[j + 1]) + 1;
    out->push_back(h + (b - a) * pw[n - 1 - j] + (a - b) * pw[n - 2 - j]);
  }
}
// Sorted (hash, value) pairs: 16 bytes per entry, binary-searched.
struct HashIndex {
  std::vector<std::pair<uint64_t, uint32_t>> v;
  void add(uint64_t h, uint32_t x) { v.emplace_back(h, x); }
  void clear() { v.clear(); }
  void finalize() {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    v.shrink_to_fit();
  }
  template <class F>
  void each(uint64_t h, F f) const {
    for (auto it = std::lower_bound(v.begin(), v.end(), std::make_pair(h, uint32_t{0})); it != v.end() && it->first == h;
         ++it)
      f(it->second);
  }
  size_t bytes() const { return v.capacity() * sizeof(v[0]); }
};

// Optimal string alignment distance (Damerau-Levenshtein restricted to adjacent transpositions), bounded.
unsigned osa_distance(const std::u32string& a, const std::u32string& b, unsigned bound) {
  const size_t n = a.size();
  const size_t m = b.size();
  if ((n > m ? n - m : m - n) > bound) return bound + 1;
  std::vector<unsigned> prev2(m + 1);
  std::vector<unsigned> prev(m + 1);
  std::vector<unsigned> cur(m + 1);
  for (size_t j = 0; j <= m; ++j) prev[j] = static_cast<unsigned>(j);
  for (size_t i = 1; i <= n; ++i) {
    cur[0] = static_cast<unsigned>(i);
    unsigned row_min = cur[0];
    for (size_t j = 1; j <= m; ++j) {
      unsigned cost = a[i - 1] == b[j - 1] ? 0 : 1;
      unsigned v = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
      if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) v = std::min(v, prev2[j - 2] + 1);
      cur[j] = v;
      row_min = std::min(row_min, v);
    }
    if (row_min > bound) return bound + 1;
    std::swap(prev2, prev);
    std::swap(prev, cur);
  }
  return prev[m];
}

// Transparent hash: lookups by std::u32string_view do not allocate (C++20 heterogeneous lookup).
struct U32Hash {
  using is_transparent = void;
  size_t operator()(std::u32string_view s) const noexcept { return std::hash<std::u32string_view>()(s); }
};
template <class V>
using U32Map = std::unordered_map<std::u32string, V, U32Hash, std::equal_to<>>;
using U32Set = std::unordered_set<std::u32string, U32Hash, std::equal_to<>>;

template <class M>
size_t map_bytes(const M& m) {
  using V = typename M::mapped_type::value_type;
  size_t b = m.bucket_count() * sizeof(void*);
  for (const auto& [k, v] : m)
    b += sizeof(k) + k.capacity() * sizeof(char32_t) + sizeof(v) + v.capacity() * sizeof(V) + 2 * sizeof(void*);
  return b;
}

struct WholeScriptConfusable {
  std::unique_ptr<UnicodeSet> all_letters;
  std::unique_ptr<UnicodeSet> latin_lookalikes;
  std::vector<std::string> allowed_tlds;
};

// Index entry for a protected registrable domain.
struct Entry {
  TargetKind target;
  std::string registrable;  // ACE
  std::string suffix;       // ACE public suffix
  std::string brand;        // brand id (Brand)
  bool swap_typo_ok;        // label may be compared for TLD swap / typo
  std::vector<std::u32string> label_keys;
  unsigned label_len = 0;  // visible code points of the registrable label
};

struct TokenRef {
  uint32_t entry;
  bool contact;  // contact/own label token (vs brand token)
};

struct PersonRef {
  NameMatchKind kind;  // ContactName or OwnName
  uint32_t person;     // index into persons_
};

struct Person {
  std::string name;
  std::unordered_set<std::string> addresses;
  std::unordered_set<std::string> registrables;
  std::vector<std::vector<std::u32string>> tokens;  // per name-key variant
};

struct BrandName {
  uint32_t brand = 0;  // index into brands_
  std::string text;
  std::vector<std::vector<std::u32string>> tokens;  // per key variant
  std::vector<std::u32string> concat;               // per key variant, tokens joined without spaces
  bool generic = false;
};

// Candidate index over a BrandName list: first token of each variant, and concatenations >= 5 characters.
struct NameIndex {
  U32Map<std::vector<uint32_t>> first;
  U32Map<std::vector<uint32_t>> concat;
  std::vector<bool> concat_lens;

  void build(const std::vector<BrandName>& names) {
    first.clear();
    concat.clear();
    size_t max_len = 0;
    auto add = [](std::vector<uint32_t>& v, uint32_t i) {
      if (v.empty() || v.back() != i) v.push_back(i);
    };
    for (uint32_t i = 0; i < names.size(); ++i) {
      for (size_t vi = 0; vi < names[i].tokens.size(); ++vi) {
        if (!names[i].tokens[vi].empty()) add(first[names[i].tokens[vi][0]], i);
        const auto& c = names[i].concat[vi];
        if (!names[i].generic && c.size() >= 5) {
          add(concat[c], i);
          max_len = std::max(max_len, c.size());
        }
      }
    }
    concat_lens.assign(max_len + 1, false);
    for (const auto& [k, v] : concat) concat_lens[k.size()] = true;
  }
};

// The Public Suffix List (ICANN and private sections, as libpsl PSL_TYPE_ANY): exact, wildcard and exception
// rules in lower-case ACE, plus the implicit "*" rule for registrable_domain().
class SuffixList {
 public:
  bool load(std::string_view text, UIDNA* idna) {
    size_t pos = 0;
    while (pos < text.size()) {
      size_t nl = text.find('\n', pos);
      if (nl == std::string_view::npos) nl = text.size();
      std::string_view line = text.substr(pos, nl - pos);
      pos = nl + 1;
      const size_t end = line.find_first_of(" \t\r");
      if (end != std::string_view::npos) line = line.substr(0, end);
      if (line.empty() || line.substr(0, 2) == "//") continue;
      std::string rule;
      bool exception = false;
      bool wildcard = false;
      if (line[0] == '!') {
        exception = true;
        line.remove_prefix(1);
      } else if (line.substr(0, 2) == "*.") {
        wildcard = true;
        line.remove_prefix(2);
      }
      if (!to_ace(line, idna, &rule)) continue;
      (exception ? exceptions_ : wildcard ? wildcards_ : exact_).insert(std::move(rule));
    }
    return exact_.size() > 1000;
  }
  // libpsl psl_is_public_suffix2(PSL_TYPE_ANY | PSL_TYPE_NO_STAR_RULE): listed by an explicit rule.
  bool listed(std::string_view suffix) const {
    const std::string s(suffix);
    if (exact_.count(s) != 0) return true;
    const size_t dot = s.find('.');
    return dot != std::string::npos && wildcards_.count(s.substr(dot + 1)) != 0 && exceptions_.count(s) == 0;
  }
  // libpsl psl_registrable_domain: the public suffix (longest rule, exceptions first, implicit "*") plus one
  // label; empty when the host is itself a public suffix.
  std::string registrable(std::string_view host) const {
    if (host.empty() || host.front() == '.' || host.back() == '.') return {};
    std::vector<size_t> starts{0};
    for (size_t i = 0; i < host.size(); ++i)
      if (host[i] == '.') starts.push_back(i + 1);
    const size_t n = starts.size();
    size_t suffix_labels = 1;  // the implicit "*" rule
    for (size_t i = 0; i < n; ++i) {
      const std::string s(host.substr(starts[i]));
      const size_t labels = n - i;
      if (exceptions_.count(s) != 0) {
        suffix_labels = labels - 1;
        break;  // an exception rule always prevails
      }
      if (labels > suffix_labels &&
          (exact_.count(s) != 0 || (i + 1 < n && wildcards_.count(std::string(host.substr(starts[i + 1]))) != 0)))
        suffix_labels = labels;
    }
    if (n <= suffix_labels) return {};
    return std::string(host.substr(starts[n - suffix_labels - 1]));
  }
  size_t bytes() const { return (exact_.size() + wildcards_.size() + exceptions_.size()) * 48; }

 private:
  static bool to_ace(std::string_view rule, UIDNA* idna, std::string* out) {
    bool ascii = true;
    for (char c : rule) ascii = ascii && static_cast<unsigned char>(c) < 0x80;
    if (ascii) {
      *out = ascii_lower(rule);
      return !out->empty();
    }
    char buf[256];
    UErrorCode st = U_ZERO_ERROR;
    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    const int32_t len = uidna_nameToASCII_UTF8(idna, rule.data(), int32_t(rule.size()), buf, sizeof buf, &info, &st);
    if (U_FAILURE(st) || info.errors != 0 || len <= 0 || len >= int32_t(sizeof buf)) return false;
    *out = ascii_lower(std::string_view(buf, size_t(len)));
    return true;
  }
  std::unordered_set<std::string> exact_, wildcards_, exceptions_;
};

const std::set<std::u32string>& service_words() {
  static const std::set<std::u32string> words = {
      U"support", U"team", U"billing", U"security", U"service", U"services", U"account", U"accounts",
      U"alert", U"alerts", U"notification", U"notifications", U"customer", U"care", U"no", U"reply",
      U"noreply", U"no-reply", U"online", U"help", U"helpdesk", U"payments", U"payment", U"bank",
      U"banking", U"official", U"center", U"centre", U"info", U"mail", U"admin", U"verification",
      U"the", U"inc", U"llc", U"ltd", U"via", U"desk", U"id", U"pay", U"store", U"shop", U"delivery"};
  return words;
}

class EngineImpl final : public Engine {
 public:
  explicit EngineImpl(const Options& o) : opt_(o) {}
  EngineImpl(const EngineImpl&) = delete;  // owns ICU handles
  EngineImpl& operator=(const EngineImpl&) = delete;
  ~EngineImpl() override {
    if (idna_) uidna_close(idna_);
    if (sc_) uspoof_close(sc_);
    if (sc_name_) uspoof_close(sc_name_);
  }

  bool init(std::string_view psl_text, std::string* error);
  void set_profile(const Profile& p) override;
  HostReport check_host(std::string_view host) const override;
  NameReport check_display_name(std::string_view display_name, std::string_view address,
                                std::string_view verified_domain) const override;
  SenderReport check_sender(const SenderInput& in) const override;
  std::string registrable_domain(std::string_view ace_host) const override;
  std::string skeleton(std::string_view utf8) const override;
  std::vector<std::string> domain_keys(std::string_view unicode) const override;
  size_t index_bytes() const override;

 private:
  // --- Unicode primitives ---
  UnicodeString skel(const UnicodeString& s) const;
  std::vector<std::u32string> dkeys(const UnicodeString& unicode) const;
  std::u32string key_of(const UnicodeString& t) const;
  std::vector<UnicodeString> chromium_variants(const UnicodeString& s) const;
  IdnReason safe_to_display(const UnicodeString& label, const std::string& tld, const UnicodeString& tld_u) const;
  bool ace_to_unicode_label(const std::string& ace, UnicodeString* out) const;
  std::string ace_to_unicode_name(const std::string& ace) const;
  bool to_ace(std::string_view host, std::string* out) const;
  std::string suffix_of(const std::string& registrable) const {
    size_t p = registrable.find('.');
    return p == std::string::npos ? std::string() : registrable.substr(p + 1);
  }
  std::string registrable_of_address(std::string_view address) const;

  // --- name keys ---
  struct NameKeys {
    std::string normalized;
    bool removed_invisible = false;
    std::vector<std::vector<std::u32string>> tokens;  // per variant
  };
  NameKeys name_keys(std::string_view text) const;
  bool mixed_script_token(const UnicodeString& tok) const;

  // --- index building ---
  uint32_t add_entry(TargetKind t, const std::string& registrable_ace, const std::string& brand, bool swap_typo_ok);
  void index_entry(uint32_t idx);
  void find_matches(const std::string& ascii_host, const std::string& registrable, HostReport* r) const;
  void add_match(HostReport* r, MatchKind k, uint32_t e, Severity s) const;
  // False when the only difference between two keys is in digits 2-9 (site2/site5, tv11/tv17): numbering
  // variants, not typosquats (0 and 1 are letters in key space: o, l).
  // True when `s` (part of a label key) is empty or consists only of hyphens, digits and lure words.
  bool lure_only(const std::u32string& s) const {
    size_t i = 0;
    while (i < s.size()) {
      if (s[i] == U'-' || (s[i] >= U'0' && s[i] <= U'9')) {
        ++i;
        continue;
      }
      size_t j = i;
      while (j < s.size() && s[j] != U'-' && (s[j] < U'0' || s[j] > U'9')) ++j;
      // Segment s[i, j) into lure words (DP over prefixes).
      const size_t n = j - i;
      std::vector<bool> ok(n + 1, false);
      ok[0] = true;
      for (size_t a = 0; a < n; ++a) {
        if (!ok[a]) continue;
        for (size_t len = 1; a + len <= n && len <= max_lure_len_; ++len)
          if (lure_.find(std::u32string_view(s).substr(i + a, len)) != lure_.end()) ok[a + len] = true;
      }
      if (!ok[n]) return false;
      i = j;
    }
    return true;
  }
  bool typo_edit_counts(const std::u32string& a, const std::u32string& b) const {
    if (!opt_.typo_ignore_digit_edits || a == b) return true;
    auto strip = [](const std::u32string& x) {
      std::u32string o;
      for (char32_t c : x)
        if (c < U'2' || c > U'9') o.push_back(c);
      return o;
    };
    return strip(a) != strip(b);
  }

  Options opt_;
  SuffixList psl_;
  UIDNA* idna_ = nullptr;
  USpoofChecker* sc_ = nullptr;       // Chromium-configured checker (IDN display)
  USpoofChecker* sc_name_ = nullptr;  // restriction-level checker for display names
  const icu::Normalizer2* nfkc_cf_ = nullptr;
  const icu::Normalizer2* nfkc_ = nullptr;
  mutable std::mutex translit_mu_;
  std::unique_ptr<icu::Transliterator> diacritic_remover_;
  std::unique_ptr<icu::Transliterator> extra_mapper_;
  UnicodeSet name_lgc_;
  UnicodeSet lgc_letters_n_ascii_, non_ascii_latin_, kana_exc_, comb_exc_, digits_, digit_lookalikes_, icelandic_;
  std::vector<WholeScriptConfusable> wsc_;
  std::unique_ptr<icu::RegexPattern> dangerous_;
  std::unique_ptr<icu::RegexPattern> domain_re_;  // domain-shaped tokens in display names
  std::map<char16_t, std::vector<UnicodeString>> multi_skeleton_;
  std::set<char16_t> multi_skeleton_with_diacritics_;

  // --- indexes (rebuilt by set_profile) ---
  std::vector<Entry> entries_;
  std::unordered_map<std::string, std::vector<uint32_t>> exact_;  // ACE registrable -> entries
  U32Map<std::vector<uint32_t>> full_key_;
  U32Map<std::vector<uint32_t>> label_key_;
  HashIndex deletes_idx_;  // protected label keys (folded and raw) and their single deletions -> entry
  HashIndex labelh_;       // protected label keys (folded and raw) -> entry, for transposition probes
  U32Map<std::vector<TokenRef>> tokens_;
  std::vector<std::pair<std::u32string, uint32_t>> brand_tokens_;                  // token key, entry
  HashIndex tokdel_;  // brand token keys (folded and raw) and their single deletions -> brand_tokens_
  U32Set brand_token_set_;
  U32Map<std::vector<std::string>> top_key_;  // IDN display only
  size_t max_token_len_ = 0;
  size_t min_token_len_ = 1;
  std::vector<bool> token_lens_;  // token key lengths present in tokens_
  std::vector<Person> persons_;
  U32Map<std::vector<PersonRef>> person_key_;
  U32Map<std::vector<PersonRef>> person_first_token_;
  std::vector<Brand> brands_;
  std::vector<std::unordered_set<std::string>> brand_registrables_;
  std::vector<BrandName> brand_names_;
  std::vector<BrandName> org_names_;
  NameIndex brand_name_index_, org_name_index_;
  std::unordered_set<std::string> own_registrables_;
  std::unordered_set<std::string> shared_;
  std::unordered_set<std::string> popular_;
  U32Set lure_;  // keys of lure words (brand-token severity)
  std::u32string ascii_key_[128];                     // skel(fold(skel(c))) per ASCII character (no folds)
  std::u32string ascii_name_v1_[128];                 // skel(fold(c)) per ASCII character (name variant 1)
  size_t max_lure_len_ = 0;
};

bool EngineImpl::init(std::string_view psl_text, std::string* error) {
  UErrorCode st = U_ZERO_ERROR;
  idna_ = uidna_openUTS46(UIDNA_CHECK_BIDI | UIDNA_CHECK_CONTEXTJ | UIDNA_NONTRANSITIONAL_TO_ASCII |
                              UIDNA_NONTRANSITIONAL_TO_UNICODE,
                          &st);
  if (U_FAILURE(st) || !psl_.load(psl_text, idna_)) {
    *error = "the public suffix list could not be loaded";
    return false;
  }
  nfkc_cf_ = icu::Normalizer2::getNFKCCasefoldInstance(st);
  nfkc_ = icu::Normalizer2::getNFKCInstance(st);

  // Chromium IDNSpoofChecker configuration.
  sc_ = uspoof_open(&st);
  uspoof_setRestrictionLevel(sc_, USPOOF_HIGHLY_RESTRICTIVE);
  {
    UnicodeSet allowed;
    allowed.addAll(*uspoof_getRecommendedUnicodeSet(&st));
    allowed.addAll(*uspoof_getInclusionUnicodeSet(&st));
    for (UChar32 c : {0x338, 0x58a, 0x2010, 0x2019, 0x2027, 0x30a0, 0x2bb, 0x2bc, 0x2ec, 0x138}) allowed.remove(c);
    allowed.remove(0x01CD, 0x01DC);
    allowed.remove(0x1C80, 0x1C8F);
    allowed.remove(0x1E00, 0x1E9B);
    allowed.remove(0x1F00, 0x1FFF);
    allowed.remove(0xA640, 0xA69F);
    allowed.remove(0xA720, 0xA7FF);
    uspoof_setAllowedUnicodeSet(sc_, &allowed, &st);
  }
  uspoof_setChecks(sc_, uspoof_getChecks(sc_, &st) | USPOOF_AUX_INFO, &st);

  sc_name_ = uspoof_open(&st);
  uspoof_setRestrictionLevel(sc_name_, USPOOF_HIGHLY_RESTRICTIVE);
  uspoof_setChecks(sc_name_, USPOOF_RESTRICTION_LEVEL | USPOOF_AUX_INFO, &st);

  non_ascii_latin_ = UnicodeSet(UNICODE_STRING_SIMPLE("[[:Latin:] - [a-zA-Z]]"), st);
  kana_exc_ = UnicodeSet(UNICODE_STRING_SIMPLE("[\\u3078-\\u307a\\u30d8-\\u30da\\u30fb-\\u30fe]"), st);
  comb_exc_ = UnicodeSet(UNICODE_STRING_SIMPLE("[\\u0300-\\u0339]"), st);
  digits_ = UnicodeSet(UNICODE_STRING_SIMPLE("[0-9]"), st);
  digit_lookalikes_ = UnicodeSet(UnicodeString::fromUTF8("[θ२২੨੨૨೩೭շзҙӡउওਤ੩૩౩ဒვპੜკ੫丩ㄐճ৪੪୫૭୨౨]"), st);
  icelandic_ = UnicodeSet(UNICODE_STRING_SIMPLE("[\\u00fe\\u00f0]"), st);
  name_lgc_ = UnicodeSet(UNICODE_STRING_SIMPLE("[[:Latin:][:Greek:][:Cyrillic:][:Zyyy:][:Zinh:]]"), st);
  lgc_letters_n_ascii_ = UnicodeSet(
      UNICODE_STRING_SIMPLE("[[:Latin:][:Greek:][:Cyrillic:][0-9\\u002e_\\u002d][\\u0300-\\u0339]]"), st);

  struct Wsc {
    const char* script;
    const char* lookalikes;
    std::vector<std::string> tlds;
  };
  const Wsc kWsc[] = {
      {"[[:Armn:]]", "[ագզէլհյոսւօՙ]", {"am"}},
      {"[[:Cyrl:]]", "[аысԁеԍһіюкјӏморԗԛѕтԝхуъьҽпгѵѡ]", {"bg", "by", "kz", "pyc", "ru", "su", "ua", "uz"}},
      {"[[:Ethi:]]", "[ሀሠሰስበነተከዐዕዘጠፐꬅ]", {"er", "et"}},
      {"[[:Geor:]]", "[იოყძხჽჿ]", {"ge"}},
      {"[[:Grek:]]", "[αικνρυωηοτ]", {"gr"}},
      {"[[:Hebr:]]", "[דוחיןסװײ׳ﬦ]", {"il"}},
      {"[[:Beng:]]", "[০৭]", {}},
      {"[[:Deva:]]", "[ऽ०ॱ]", {}},
      {"[[:Gujr:]]", "[ડટ૦૧]", {}},
      {"[[:Guru:]]", "[੦੧]", {}},
      {"[[:Knda:]]", "[ಽ೦೧]", {}},
      {"[[:Mlym:]]", "[ടഠധനറ൦]", {}},
      {"[[:Orya:]]", "[ଠ୦୮]", {}},
      {"[[:Taml:]]", "[டப௦]", {}},
      {"[[:Telu:]]", "[౦౧]", {}},
      {"[[:Mymr:]]", "[ခဂငထပဝ၀၂ၔၜ\u1090\u1091\u1095\u1096\u1097]", {"mm"}},
      {"[[:Thai:]]", "[ทนบพรหเแ๐ดลปฟม]", {"th"}},  // Chromium's Linux set
  };
  for (const auto& w : kWsc) {
    WholeScriptConfusable s;
    s.all_letters = std::make_unique<UnicodeSet>(UnicodeString::fromUTF8(w.script), st);
    s.latin_lookalikes = std::make_unique<UnicodeSet>(UnicodeString::fromUTF8(w.lookalikes), st);
    s.allowed_tlds = w.tlds;
    wsc_.push_back(std::move(s));
  }

  UParseError pe;
  dangerous_.reset(icu::RegexPattern::compile(
      UnicodeString(
          R"([^\p{scx=kana}\p{scx=hira}\p{scx=hani}])"
          R"([\u30ce\u30f3\u30bd\u30be\u4e36\u4e40\u4e41\u4e3f])"
          R"([^\p{scx=kana}\p{scx=hira}\p{scx=hani}]|)"
          R"([^\p{scx=kana}][\u30fd\u30fe]|^[\u30fd\u30fe]|)"
          R"(^[\p{scx=kana}]+[\u3078-\u307a][\p{scx=kana}]+$|)"
          R"(^[\p{scx=hira}]+[\u30d8-\u30da][\p{scx=hira}]+$|)"
          R"([^\p{scx=kana}\p{scx=hira}]\u30fc|^\u30fc|)"
          R"([^\p{scx=kana}\p{scx=hira}\p{scx=hani}]\u30fb|)"
          R"(\u30fb[^\p{scx=kana}\p{scx=hira}\p{scx=hani}]|)"
          R"(\u30fb$|)"
          R"([^\p{scx=kana}\p{scx=hira}\p{scx=hani}\p{scx=bopo}])"
          R"([\u4e00\u3127\u4e28\u4e5b\u4e03\u4e05\u5341\u3007\u3112)"
          R"(\u311a\u311f\u3128\u3129\u3108\u31ba\u31b3\u5dE5)"
          R"(\u31b2\u8ba0\u4e01\u4e36\u4e85\u4e8c\u4ea0\u5196\u5b80\u5ddb]|)"
          R"([\u4e00\u3127\u4e28\u4e5b\u4e03\u4e05\u5341\u3007\u3112)"
          R"(\u311a\u311f\u3128\u3129\u3108\u31ba\u31b3\u5de5)"
          R"(\u31b2\u8ba0\u4e01\u4e36\u4e85\u4e8c\u4ea0\u5196\u5b80\u5ddb])"
          R"([^\p{scx=kana}\p{scx=hira}\p{scx=hani}\p{scx=bopo}]|)"
          R"([^\p{scx=latn}\p{scx=grek}\p{scx=cyrl}][\u0300-\u0339]|)"
          R"(\u0131[\u0300-\u0339]|)"
          R"(\u3099|\u309A|)"
          R"([ijl]\u0307)",
          -1, US_INV),
      0, pe, st));

  domain_re_.reset(icu::RegexPattern::compile(
      UnicodeString::fromUTF8(R"((?:[\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,62}[\p{L}\p{N}])?\.)+)"
                              R"([\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,62}[\p{L}\p{N}])?)"),
      0, pe, st));
  diacritic_remover_.reset(icu::Transliterator::createFromRules(
      "DropAcc", UnicodeString::fromUTF8("::NFD; ::[:Nonspacing Mark:] Remove; ::NFC; ł > l; ø > o; đ > d;"),
      UTRANS_FORWARD, pe, st));
  extra_mapper_.reset(icu::Transliterator::createFromRules(
      "ExtraConf",
      UnicodeString::fromUTF8("[æӕ] > ae; [ϼҏ] > p; [ħнћңҥӈӊԋԧԩ] > h;"
                              "[ĸκкқҝҟҡӄԟ] > k; [ŋпԥกח] > n;"
                              "[ŧтҭԏ七丅丆丁] > t; [ƅьҍвß] > b;  [ωшщพฟພຟ] > w;"
                              "[мӎ] > m; [єҽҿၔ] > e; ґ > r; [ғӻ] > f;"
                              "[ҫင] > c; [ұ丫] > y; [χҳӽӿ乂] > x;"
                              "[ԃძ]  > d; [ԍဌ] > g; [ടรຣຮ] > s; ၂ > j;"
                              "[०০੦૦ଠ୦೦စ] > o;"
                              "[৭੧૧] > q;"
                              "[บບ] > u;"
                              "[θ] > 0;"
                              "[२২੨੨૨೩೭շ] > 2;"
                              "[зҙӡउওਤ੩૩౩ဒვპੜკ] > 3;"
                              "[੫丩ㄐ] > 4;"
                              "[ճ] > 6;"
                              "[৪੪୫] > 8;"
                              "[૭୨౨] > 9;"
                              "[—一―⸺⸻] > \\-;"),
      UTRANS_FORWARD, pe, st));
  multi_skeleton_[u'þ'] = {UNICODE_STRING_SIMPLE("b"), UNICODE_STRING_SIMPLE("p")};
  multi_skeleton_[u'œ'] = {UNICODE_STRING_SIMPLE("ce"), UNICODE_STRING_SIMPLE("oe")};
  multi_skeleton_[u'ł'] = {UNICODE_STRING_SIMPLE("l"), UNICODE_STRING_SIMPLE("t")};
  multi_skeleton_[u'ı'] = {UNICODE_STRING_SIMPLE("l"), UNICODE_STRING_SIMPLE("i")};
  if (U_FAILURE(st) || !dangerous_ || !domain_re_ || !diacritic_remover_ || !extra_mapper_) {
    *error = std::string("ICU initialisation failed: ") + u_errorName(st);
    return false;
  }
  for (int c = 0; c < 128; ++c) {
    UnicodeString k = skel(UnicodeString(static_cast<UChar>(c)));
    k.foldCase();
    ascii_key_[c] = to_u32(skel(k));
    UnicodeString f(static_cast<UChar>(c));
    f.foldCase();
    ascii_name_v1_[c] = to_u32(skel(f));
  }
  // Words phishing domains put next to a brand token (a fixed list).
  for (const char* w : {"secure", "security", "login", "logon", "signin", "sign", "verify", "verification",
                        "validate", "account", "accounts", "acct", "support", "help", "helpdesk", "billing",
                        "bill", "invoice", "invoices", "payment", "payments", "pay", "update", "updates", "service",
                        "services", "online", "auth", "authentication", "wallet", "id", "mail", "email", "webmail",
                        "alert", "alerts", "notice", "notification", "team", "customer", "care", "center", "centre",
                        "portal", "web", "app", "my", "official", "confirm", "confirmation", "unlock", "locked",
                        "recovery", "recover", "reset", "refund", "refunds", "claim", "prize", "gift", "bonus",
                        "reward", "rewards", "access", "docs", "doc", "document", "documents", "file", "files",
                        "share", "sharing", "drive", "delivery", "deliver", "track", "tracking", "parcel",
                        "package", "shipping", "express", "office", "cloud", "storage", "connect", "member",
                        "members", "client", "user", "users", "info", "inc", "corp", "group", "global", "us", "uk",
                        "eu", "home", "net", "site", "page", "link", "go", "get", "now", "new", "safe", "check",
                        "case", "dispute", "secured", "protect", "protection", "review", "status", "dept", "desk",
                        "hr", "it", "admin", "log", "in", "on", "the", "and", "of", "to"}) {
    std::u32string k = key_of(UnicodeString(w));
    lure_.insert(k);
    max_lure_len_ = std::max(max_lure_len_, k.size());
  }
  for (const auto& [c, alts] : multi_skeleton_) {
    UnicodeString cs(static_cast<UChar>(c));
    UnicodeString t = cs;
    diacritic_remover_->transliterate(t);
    if (t != cs) multi_skeleton_with_diacritics_.insert(c);
  }
  return true;
}

UnicodeString EngineImpl::skel(const UnicodeString& s) const {
  UErrorCode st = U_ZERO_ERROR;
  UnicodeString out;
  uspoof_getSkeletonUnicodeString(sc_, 0, s, out, &st);
  return out;
}

std::string EngineImpl::skeleton(std::string_view utf8) const {
  return to_utf8(skel(UnicodeString::fromUTF8(icu::StringPiece(utf8.data(), static_cast<int32_t>(utf8.size())))));
}

// Chromium SkeletonGenerator::GetSkeletons inputs: diacritic removal for LGC-only strings and supplemental
// variants for characters with several skeletons (þ, œ, ł, ı), at most 5 such characters / 128 variants.
std::vector<UnicodeString> EngineImpl::chromium_variants(const UnicodeString& s) const {
  auto supplemental = [&](const UnicodeString& in, std::set<UnicodeString>* out) {
    int interesting = 0;
    for (int32_t i = 0; i < in.length(); ++i) interesting += multi_skeleton_.count(in.charAt(i)) ? 1 : 0;
    if (interesting > 5) return;
    std::vector<UnicodeString> cur{UnicodeString()};
    for (int32_t i = 0; i < in.length(); ++i) {
      char16_t c = in.charAt(i);
      std::vector<UnicodeString> next;
      for (const auto& p : cur) {
        next.push_back(UnicodeString(p).append(c));
        auto it = multi_skeleton_.find(c);
        if (it != multi_skeleton_.end())
          for (const auto& alt : it->second) next.push_back(UnicodeString(p).append(alt));
      }
      cur.swap(next);
      if (cur.size() > 128) cur.resize(128);
    }
    out->insert(cur.begin(), cur.end());
  };
  std::set<UnicodeString> all;
  UnicodeString base = s;
  if (lgc_letters_n_ascii_.containsAll(s)) {
    std::lock_guard<std::mutex> lk(translit_mu_);
    diacritic_remover_->transliterate(base);
  }
  supplemental(base, &all);
  bool with_diacritics = false;
  for (int32_t i = 0; i < s.length(); ++i) with_diacritics |= multi_skeleton_with_diacritics_.count(s.charAt(i)) > 0;
  if (with_diacritics) supplemental(s, &all);
  return {all.begin(), all.end()};
}

// Comparison key: skeleton, case-folded, skeleton again (prototypes such as 'O' for '0' fold to the same key
// as their lower-case form), then the visual pair vv -> w that UTS #39 data does not contain, and rn -> m.
std::u32string EngineImpl::key_of(const UnicodeString& t) const {
  if (is_ascii(t)) {
    // Fast path: for ASCII input every step is per code point (NFD is the identity), so the key is the
    // concatenation of per-character keys precomputed from ICU at init, then the two folds.
    std::u32string k;
    k.reserve(static_cast<size_t>(t.length()) + 2);
    for (int32_t i = 0; i < t.length(); ++i) k += ascii_key_[t.charAt(i) & 0x7F];
    std::u32string o;
    o.reserve(k.size());
    for (size_t i = 0; i < k.size(); ++i) {
      if (i + 1 < k.size() && k[i] == U'v' && k[i + 1] == U'v') {
        o.push_back(U'w');
        ++i;
      } else {
        o.push_back(k[i]);
      }
    }
    return fold_m(o);
  }
  UnicodeString k = skel(t);
  k.foldCase();
  k = skel(k);
  k.findAndReplace(UNICODE_STRING_SIMPLE("vv"), UNICODE_STRING_SIMPLE("w"));
  // The skeleton spells m as "rn"; fold it back so edit distances count one edit for m, not two.
  k.findAndReplace(UNICODE_STRING_SIMPLE("rn"), UNICODE_STRING_SIMPLE("m"));
  return to_u32(k);
}

std::vector<std::u32string> EngineImpl::dkeys(const UnicodeString& unicode) const {
  UErrorCode st = U_ZERO_ERROR;
  std::vector<std::u32string> out;
  if (is_ascii(unicode)) {
    // NFKC_Casefold of ASCII is ASCII lower-casing.
    UnicodeString x;
    for (int32_t i = 0; i < unicode.length(); ++i) {
      UChar c = unicode.charAt(i);
      x.append(static_cast<UChar>(c >= u'A' && c <= u'Z' ? c - u'A' + u'a' : c));
    }
    out.push_back(key_of(x));
    return out;
  }
  UnicodeString x = nfkc_cf_->normalize(unicode, st);
  // Full case folding turns deviation characters into other letters (ß -> ss, ς -> σ) before Chromium's
  // supplemental mapping (ß -> b) can see them, so lower-cased NFKC is keyed as well.
  UnicodeString lower = nfkc_->normalize(unicode, st);
  lower.toLower(icu::Locale::getRoot());
  std::set<std::u32string> keys;
  for (const UnicodeString* in : {&x, &lower}) {
    if (in == &lower && lower == x) break;
    for (UnicodeString v : chromium_variants(*in)) {
      {
        std::lock_guard<std::mutex> lk(translit_mu_);
        extra_mapper_->transliterate(v);
      }
      keys.insert(key_of(v));
      if (v.indexOf(static_cast<UChar>(0x4CF)) >= 0) {
        UnicodeString alt = v;
        alt.findAndReplace(UnicodeString(static_cast<UChar>(0x4CF)), UNICODE_STRING_SIMPLE("l"));
        keys.insert(key_of(alt));
      }
    }
  }
  out.assign(keys.begin(), keys.end());
  return out;
}

std::vector<std::string> EngineImpl::domain_keys(std::string_view unicode) const {
  std::vector<std::string> out;
  for (const auto& k :
       dkeys(UnicodeString::fromUTF8(icu::StringPiece(unicode.data(), static_cast<int32_t>(unicode.size())))))
    out.push_back(u32_to_utf8(k));
  return out;
}

bool EngineImpl::to_ace(std::string_view host, std::string* out) const {
  if (host.empty() || host.size() > 1024) return false;
  if (host.back() == '.') host.remove_suffix(1);
  // Fast path: an ASCII LDH host maps to its lower-case form under UTS #46 (no STD3 rules, non-transitional)
  // unless a label is empty, too long, or has hyphens at the start, end or positions 3-4 (which covers
  // A-labels): those, and anything non-ASCII, go through ICU.
  {
    bool fast = host.size() <= kMaxHostBytes;
    size_t label_start = 0;
    for (size_t i = 0; fast && i <= host.size(); ++i) {
      if (i == host.size() || host[i] == '.') {
        size_t len = i - label_start;
        fast = len > 0 && len <= 63 && host[label_start] != '-' && host[i - 1] != '-' &&
               (len < 4 || host[label_start + 2] != '-' || host[label_start + 3] != '-');
        label_start = i + 1;
        continue;
      }
      const char c = host[i];
      fast = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
    }
    if (fast) {
      *out = ascii_lower(host);
      return true;
    }
  }
  char buf[512];
  UIDNAInfo info = UIDNA_INFO_INITIALIZER;
  UErrorCode st = U_ZERO_ERROR;
  int32_t n = uidna_nameToASCII_UTF8(idna_, host.data(), static_cast<int32_t>(host.size()), buf, sizeof buf,
                                      &info, &st);
  if (U_FAILURE(st) || info.errors != 0 || n <= 0 || static_cast<size_t>(n) > kMaxHostBytes) return false;
  out->assign(buf, static_cast<size_t>(n));
  return true;
}

bool EngineImpl::ace_to_unicode_label(const std::string& ace, UnicodeString* out) const {
  UnicodeString in = UnicodeString::fromUTF8(ace);
  UChar buf[256];
  UIDNAInfo info = UIDNA_INFO_INITIALIZER;
  UErrorCode st = U_ZERO_ERROR;
  int32_t n = uidna_labelToUnicode(idna_, in.getBuffer(), in.length(), buf, 256, &info, &st);
  if (U_FAILURE(st) || info.errors != 0) return false;
  *out = UnicodeString(buf, n);
  return true;
}

std::string EngineImpl::ace_to_unicode_name(const std::string& ace) const {
  std::vector<std::string> labels = split(ace, '.');
  std::string out;
  for (size_t i = 0; i < labels.size(); ++i) {
    if (i) out.push_back('.');
    UnicodeString u;
    if (labels[i].rfind("xn--", 0) == 0 && ace_to_unicode_label(labels[i], &u))
      out += to_utf8(u);
    else
      out += labels[i];
  }
  return out;
}

std::string EngineImpl::registrable_domain(std::string_view ace_host) const {
  std::string h = ascii_lower(ace_host);
  return psl_.registrable(h);
}

std::string EngineImpl::registrable_of_address(std::string_view address) const {
  size_t at = address.rfind('@');
  if (at == std::string_view::npos) return {};
  std::string ace;
  if (!to_ace(address.substr(at + 1), &ace)) return {};
  return registrable_domain(ace);
}

IdnReason EngineImpl::safe_to_display(const UnicodeString& label, const std::string& tld,
                                      const UnicodeString& tld_u) const {
  UErrorCode st = U_ZERO_ERROR;
  int32_t result = uspoof_check(sc_, label.getBuffer(), label.length(), nullptr, &st);
  if (U_FAILURE(st) || (result & USPOOF_ALL_CHECKS)) return IdnReason::IcuSpoofChecks;
  if (label.length() > 1 && tld != "is" && tld != "fo" && icelandic_.containsSome(label))
    return IdnReason::TldSpecificCharacters;
  if (label.length() > 1 && tld != "az" && label.indexOf(static_cast<UChar>(0x259)) != -1)
    return IdnReason::TldSpecificCharacters;
  for (int32_t from = 0;;) {
    int32_t idx = label.indexOf(static_cast<UChar>(0xB7), from);
    if (idx < 0) break;
    if (tld != "cat") return IdnReason::UnsafeMiddleDot;
    if (idx == 0 || idx == label.length() - 1) return IdnReason::UnsafeMiddleDot;
    if (label.charAt(idx - 1) != u'l' || label.charAt(idx + 1) != u'l') return IdnReason::UnsafeMiddleDot;
    from = idx + 1;
  }
  auto digit_lookalike = [&]() {
    bool has = false;
    for (int32_t i = 0; i < label.length();) {
      UChar32 c = label.char32At(i);
      i += U16_LENGTH(c);
      if (digits_.contains(c)) continue;
      if (digit_lookalikes_.contains(c)) {
        has = true;
        continue;
      }
      return false;
    }
    return has;
  };
  result &= USPOOF_RESTRICTION_LEVEL_MASK;
  if (result == USPOOF_ASCII) return IdnReason::Safe;
  if (result == USPOOF_SINGLE_SCRIPT_RESTRICTIVE && kana_exc_.containsNone(label) && comb_exc_.containsNone(label)) {
    static const char16_t* kAllowedWords[] = {u"секс",  u"как",   u"коса",    u"курс",     u"парк",  u"такий",
                                              u"укроп", u"сахарок", u"покраска", u"театр", u"астро", u"пхукет"};
    for (const auto& w : wsc_) {
      UnicodeSet in_script;
      for (int32_t i = 0; i < label.length();) {
        UChar32 c = label.char32At(i);
        i += U16_LENGTH(c);
        if (w.all_letters->contains(c)) in_script.add(c);
      }
      bool confusable = !in_script.isEmpty() && w.latin_lookalikes->containsAll(in_script);
      if (!confusable) continue;
      bool tld_ok = w.all_letters->containsSome(tld_u) ||
                    std::find(w.allowed_tlds.begin(), w.allowed_tlds.end(), tld) != w.allowed_tlds.end();
      bool word_ok = false;
      for (const char16_t* aw : kAllowedWords) word_ok |= label == UnicodeString(aw);
      if (!tld_ok && !word_ok) return IdnReason::WholeScriptConfusable;
    }
    if (digit_lookalike()) return IdnReason::DigitLookalikes;
    return IdnReason::Safe;
  }
  if (digit_lookalike()) return IdnReason::DigitLookalikes;
  if (non_ascii_latin_.containsSome(label) && !lgc_letters_n_ascii_.containsAll(label))
    return IdnReason::NonAsciiLatinMixed;
  std::unique_ptr<icu::RegexMatcher> m(dangerous_->matcher(label, st));
  if (U_SUCCESS(st) && m->find()) return IdnReason::DangerousPattern;
  return IdnReason::Safe;
}

uint32_t EngineImpl::add_entry(TargetKind t, const std::string& registrable_ace, const std::string& brand,
                               bool swap_typo_ok) {
  Entry e{t, registrable_ace, suffix_of(registrable_ace), brand, swap_typo_ok, {}, 0};
  entries_.push_back(std::move(e));
  uint32_t idx = static_cast<uint32_t>(entries_.size() - 1);
  exact_[registrable_ace].push_back(idx);
  return idx;
}

void EngineImpl::index_entry(uint32_t idx) {
  const Entry& e = entries_[idx];
  std::string uni = ace_to_unicode_name(e.registrable);
  for (const auto& k : dkeys(UnicodeString::fromUTF8(uni))) full_key_[k].push_back(idx);
  if (!e.swap_typo_ok) return;
  std::string label_u = split(uni, '.')[0];
  entries_[idx].label_len = static_cast<unsigned>(UnicodeString::fromUTF8(label_u).countChar32());
  for (const auto& k : dkeys(UnicodeString::fromUTF8(label_u))) {
    label_key_[k].push_back(idx);
    entries_[idx].label_keys.push_back(k);
    const std::u32string kr = expand_m(k);
    labelh_.add(poly_hash(k), idx);
    if (kr != k) labelh_.add(poly_hash(kr), idx);
    UnicodeString lu = UnicodeString::fromUTF8(label_u);
    if (static_cast<unsigned>(lu.countChar32()) >= opt_.typo_min_len) {
      std::vector<uint64_t> hs;
      deletion_hashes(k, &hs);
      if (kr != k) deletion_hashes(kr, &hs);
      for (uint64_t h : hs) deletes_idx_.add(h, idx);
    }
  }
}

void EngineImpl::set_profile(const Profile& p) {
  entries_.clear();
  exact_.clear();
  full_key_.clear();
  label_key_.clear();
  deletes_idx_.clear();
  labelh_.clear();
  tokens_.clear();
  tokdel_.clear();
  brand_tokens_.clear();
  brand_token_set_.clear();
  top_key_.clear();
  persons_.clear();
  person_key_.clear();
  person_first_token_.clear();
  brands_ = p.brands;
  brand_registrables_.clear();
  brand_names_.clear();
  org_names_.clear();
  own_registrables_.clear();
  shared_.clear();
  popular_.clear();
  max_token_len_ = 0;
  min_token_len_ = opt_.contact_token_min_len ? std::min(opt_.brand_token_min_len, opt_.contact_token_min_len)
                                              : opt_.brand_token_min_len;
  for (const auto& d : p.shared_mailbox_domains) shared_.insert(ascii_lower(d));

  auto registrable_of_domain = [&](const std::string& d) {
    std::string ace;
    if (!to_ace(d, &ace)) return std::string();
    return registrable_domain(ace);
  };

  // Own domains (from own addresses) and contact domains. Shared-mailbox domains are protected too: a
  // lookalike of gmail.com is still a lookalike.
  std::unordered_set<std::string> seen_contact;
  for (const auto& a : p.own_addresses) {
    std::string r = registrable_of_address(a);
    if (r.empty() || own_registrables_.count(r)) continue;
    own_registrables_.insert(r);
    index_entry(add_entry(TargetKind::Own, r, {}, true));
  }
  for (const Contact& contact : p.contacts) {
    for (const auto& a : contact.addresses) {
      std::string r = registrable_of_address(a);
      if (r.empty() || own_registrables_.count(r) || !seen_contact.insert(r).second) continue;
      index_entry(add_entry(TargetKind::Contact, r, {}, true));
    }
  }
  // Brands.
  for (const Brand& b : brands_) {
    std::unordered_set<std::u32string, U32Hash> token_keys;
    for (const auto& t : b.tokens) {
      for (const auto& k : dkeys(UnicodeString::fromUTF8(t))) token_keys.insert(k);
    }
    std::unordered_set<std::string> regs;
    int64_t first = -1;  // tokens refer to the brand's first (primary) domain entry
    for (const auto& d : b.domains) {
      std::string r = registrable_of_domain(d);
      if (r.empty() || !regs.insert(r).second) continue;
      bool ok = true;
      if (opt_.brand_swap_tokens_only) {
        ok = false;
        std::string label_u = split(ace_to_unicode_name(r), '.')[0];
        for (const auto& k : dkeys(UnicodeString::fromUTF8(label_u))) ok |= token_keys.count(k) > 0;
      }
      uint32_t idx = add_entry(TargetKind::Brand, r, b.id, ok);
      index_entry(idx);
      if (first < 0) first = idx;
    }
    brand_registrables_.push_back(regs);
    if (first < 0) continue;
    for (const auto& k : token_keys) {
      if (k.size() < opt_.brand_token_min_len) continue;
      tokens_[k].push_back({static_cast<uint32_t>(first), false});
      brand_token_set_.insert(k);
      max_token_len_ = std::max(max_token_len_, k.size());
      if (expand_m(k).size() >= opt_.typo_min_len) {
        brand_tokens_.emplace_back(k, static_cast<uint32_t>(first));
        uint32_t ti = static_cast<uint32_t>(brand_tokens_.size() - 1);
        std::vector<uint64_t> hs;
        deletion_hashes(k, &hs);
        if (expand_m(k) != k) deletion_hashes(expand_m(k), &hs);
        for (uint64_t h : hs) tokdel_.add(h, ti);
      }
    }
  }
  // Contact/own labels as tokens (optional).
  if (opt_.contact_token_min_len > 0) {
    for (uint32_t i = 0; i < entries_.size(); ++i) {
      if (entries_[i].target == TargetKind::Brand) continue;
      std::string label_u = split(ace_to_unicode_name(entries_[i].registrable), '.')[0];
      for (const auto& k : dkeys(UnicodeString::fromUTF8(label_u))) {
        if (k.size() < opt_.contact_token_min_len) continue;
        tokens_[k].push_back({i, true});
        max_token_len_ = std::max(max_token_len_, k.size());
      }
    }
  }
  deletes_idx_.finalize();
  labelh_.finalize();
  tokdel_.finalize();
  token_lens_.assign(max_token_len_ + 1, false);
  for (const auto& [k, refs] : tokens_) token_lens_[k.size()] = true;
  popular_.reserve(p.popular_domains.size());
  // Shipped pre-canonicalised (ACE, registrable) at package build time, so no IDNA/PSL work here.
  for (const auto& d : p.popular_domains) popular_.insert(ascii_lower(d));
  // Top domains for the IDN display decision (protected registrables are added implicitly via full_key_).
  for (const auto& d : p.top_domains) {
    std::string r = registrable_of_domain(d);
    if (r.empty()) continue;
    for (const auto& k : dkeys(UnicodeString::fromUTF8(ace_to_unicode_name(r)))) top_key_[k].push_back(r);
  }

  // Display names.
  auto add_person = [&](NameMatchKind kind, const std::string& name, const std::vector<std::string>& addrs) {
    NameKeys nk = name_keys(name);
    if (nk.tokens.empty() || nk.tokens[0].empty()) return;
    Person person;
    person.name = name;
    for (const auto& a : addrs) {
      person.addresses.insert(ascii_lower(a));
      std::string r = registrable_of_address(a);
      if (!r.empty()) person.registrables.insert(r);
    }
    person.tokens = nk.tokens;
    persons_.push_back(std::move(person));
    PersonRef ref{kind, static_cast<uint32_t>(persons_.size() - 1)};
    for (const auto& toks : nk.tokens) {
      std::u32string joined;
      std::u32string sorted_joined;
      std::vector<std::u32string> sorted = toks;
      std::sort(sorted.begin(), sorted.end());
      for (size_t i = 0; i < toks.size(); ++i) {
        if (i) joined.push_back(U' '), sorted_joined.push_back(U' ');
        joined += toks[i];
        sorted_joined += sorted[i];
      }
      if (toks.size() < opt_.contact_name_min_tokens) continue;
      auto add_unique = [&](std::vector<PersonRef>& v) {
        for (const auto& x : v)
          if (x.person == ref.person) return;
        v.push_back(ref);
      };
      add_unique(person_key_[joined]);
      add_unique(person_key_[sorted_joined]);
      add_unique(person_first_token_[toks[0]]);
    }
  };
  for (const auto& n : p.own_names) add_person(NameMatchKind::OwnName, n, p.own_addresses);
  for (const auto& c : p.contacts) add_person(NameMatchKind::ContactName, c.name, c.addresses);

  auto make_name = [&](uint32_t owner, const std::string& text, bool generic) {
    BrandName bn;
    bn.brand = owner;
    bn.text = text;
    bn.generic = generic;
    NameKeys nk = name_keys(text);
    for (const auto& toks : nk.tokens) {
      std::u32string c;
      for (const auto& t : toks) c += t;
      bn.tokens.push_back(toks);
      bn.concat.push_back(c);
    }
    return bn;
  };
  for (uint32_t bi = 0; bi < brands_.size(); ++bi)
    for (const auto& n : brands_[bi].names) brand_names_.push_back(make_name(bi, n, brands_[bi].generic_name));
  for (const auto& n : p.org_names) org_names_.push_back(make_name(0, n, false));
  brand_name_index_.build(brand_names_);
  org_name_index_.build(org_names_);
}

void EngineImpl::add_match(HostReport* r, MatchKind k, uint32_t e, Severity s) const {
  const Entry& en = entries_[e];
  for (auto& m : r->matches) {
    if (m.matched_domain == en.registrable && m.target == en.target) {
      // Keep the strongest/most specific kind for a protected domain.
      if (static_cast<int>(s) > static_cast<int>(m.severity) ||
          (s == m.severity && static_cast<int>(k) < static_cast<int>(m.kind))) {
        m.kind = k;
        m.severity = s;
      }
      return;
    }
  }
  r->matches.push_back({k, en.target, s, en.registrable, en.brand});
}

void EngineImpl::find_matches(const std::string& ascii_host, const std::string& registrable, HostReport* r) const {
  const std::string reg_u = ace_to_unicode_name(registrable);
  const std::string suffix = suffix_of(registrable);
  const std::string label_u = split(reg_u, '.')[0];
  const UnicodeString label_us = UnicodeString::fromUTF8(label_u);
  const bool reg_ascii = is_ascii(reg_u);

  // Homoglyph / visual pair: whole registrable skeleton.
  for (const auto& k : dkeys(UnicodeString::fromUTF8(reg_u))) {
    auto it = full_key_.find(k);
    if (it == full_key_.end()) continue;
    for (uint32_t e : it->second)
      if (entries_[e].registrable != registrable)
        add_match(r, reg_ascii ? MatchKind::VisualPair : MatchKind::Homoglyph, e, Severity::Danger);
  }

  const std::vector<std::u32string> lkeys = dkeys(label_us);
  for (const auto& k : lkeys) {
    // TLD swap.
    auto it = label_key_.find(k);
    if (it != label_key_.end()) {
      for (uint32_t e : it->second) {
        if (entries_[e].suffix == suffix) continue;
        // A label that only matches after skeleton folding (pаypal.net, paypa1.org) is a homoglyph/visual
        // lookalike on another suffix: danger. The identical label on another suffix is a TLD swap, which
        // legitimate owners do constantly (amazon.dev, discord.gg): its severity is configurable.
        const std::string plabel = split(ace_to_unicode_name(entries_[e].registrable), '.')[0];
        if (plabel != label_u) {
          if (k.size() >= opt_.swap_min_len)
            add_match(r, is_ascii(label_u) ? MatchKind::VisualPair : MatchKind::Homoglyph, e, Severity::Danger);
        } else if (k.size() >= opt_.swap_min_len) {
          Severity s = entries_[e].target == TargetKind::Brand ? opt_.tld_swap_brand : opt_.tld_swap_contact;
          add_match(r, MatchKind::TldSwap, e, s);
        }
      }
    }
    // Typo: symmetric deletes + adjacent transpositions, verified with OSA distance == 1, on the folded key
    // (m) and on the raw skeleton (rn) so that both ammazon -> amazon and wetrnsfer -> wetransfer are one edit.
    // DL-1 is applied when the protected label is at least typo_min_len long (the deletes index holds only
    // those); the candidate may be one shorter (adobe -> adoe).
    // Lengths are visible characters (the folded key spells rn as m, the raw key m as rn).
    if (static_cast<unsigned>(label_us.countChar32()) + (opt_.typo_shorter_candidate ? 1 : 0) >= opt_.typo_min_len) {
      const std::u32string kr = expand_m(k);
      std::unordered_set<uint32_t> cand;
      std::vector<uint64_t> hs;
      for (const std::u32string* form : {&k, &kr}) {
        if (form == &kr && kr == k) break;
        hs.clear();
        deletion_hashes(*form, &hs);
        for (uint64_t h : hs) deletes_idx_.each(h, [&](uint32_t e) { cand.insert(e); });
        hs.clear();
        transposition_hashes(*form, &hs);
        for (uint64_t h : hs) labelh_.each(h, [&](uint32_t e) { cand.insert(e); });
      }
      for (uint32_t e : cand) {
        const Entry& en = entries_[e];
        if (en.registrable == registrable || (opt_.typo_same_suffix && en.suffix != suffix)) continue;
        bool hit = false;
        for (const auto& ek : en.label_keys)
          hit |= (osa_distance(k, ek, 1) == 1 || osa_distance(kr, expand_m(ek), 1) == 1) && typo_edit_counts(k, ek);
        if (!hit) continue;
        Severity s = Severity::Danger;
        if (en.target == TargetKind::Contact && en.label_len < opt_.typo_contact_danger_min_len)
          s = Severity::Caution;
        add_match(r, MatchKind::Typo, e, s);
      }
    }
    // Tokens inside the label.
    if (!tokens_.empty()) {
      auto boundary = [&](size_t pos) {
        return pos == 0 || pos >= k.size() || k[pos] == U'-' || k[pos - 1] == U'-' ||
               (k[pos] >= U'0' && k[pos] <= U'9') || (k[pos - 1] >= U'0' && k[pos - 1] <= U'9');
      };
      // Brand token severity: danger when everything else in the label is lure vocabulary, digits or hyphens
      // (paypal-secure, microsoft365-billing, secure-docusign, microsoftsupport); a token next to other words is
      // a caution (lufthansa-cargo, nintendoworldreport, amazonaws-us-gov are brand-owned or fan sites).
      auto token_severity = [&](size_t from, size_t to) {
        if (!opt_.brand_token_needs_lure) return opt_.brand_token;
        return lure_only(k.substr(0, from)) && lure_only(k.substr(to)) ? opt_.brand_token : Severity::Caution;
      };
      const std::u32string_view kv(k);
      for (size_t i = 0; i < k.size(); ++i) {
        for (size_t len = min_token_len_; i + len <= k.size() && len <= max_token_len_; ++len) {
          if (i == 0 && len == k.size()) continue;  // whole label: TLD swap / homoglyph territory
          if (!token_lens_[len]) continue;
          auto t = tokens_.find(kv.substr(i, len));
          if (t == tokens_.end()) continue;
          bool bounded = boundary(i) && boundary(i + len);
          for (const TokenRef& ref : t->second) {
            const Entry& en = entries_[ref.entry];
            if (en.registrable == registrable) continue;
            if (ref.contact) {
              if (bounded) add_match(r, MatchKind::BrandToken, ref.entry, opt_.contact_token);
            } else if (bounded || len >= opt_.brand_token_anywhere_len) {
              add_match(r, MatchKind::BrandToken, ref.entry, token_severity(i, i + len));
            }
          }
        }
      }
      // Typo'd brand token as a run of 1-3 hyphen/digit-separated parts of the label (paypa1-secure,
      // micros0ft-365, t-obile-verify, credit-agriole-secure); the whole label counts too (venmo.net is a TLD
      // swap, vemno.net a typo of the token on another suffix).
      std::vector<std::pair<size_t, size_t>> parts;  // [start, end)
      size_t start = 0;
      for (size_t i = 0; i <= k.size(); ++i) {
        bool sep = i == k.size() || k[i] == U'-' || (k[i] >= U'0' && k[i] <= U'9');
        if (!sep) continue;
        if (i > start) parts.emplace_back(start, i);
        start = i + 1;
      }
      for (size_t a = 0; a < parts.size(); ++a) {
        for (size_t b = a; b < parts.size() && b < a + 3; ++b) {
          size_t from = parts[a].first;
          size_t to = parts[b].second;
          if (to - from > max_token_len_ + 1) continue;
          std::u32string part = k.substr(from, to - from);
          const std::u32string part_raw = expand_m(part);
          if (part.size() < opt_.token_typo_min_len) continue;
          const bool whole_label = from == 0 && to == k.size();
          std::vector<uint64_t> hs;
          deletion_hashes(part, &hs);
          if (part_raw != part) deletion_hashes(part_raw, &hs);
          std::vector<uint32_t> tis;
          for (uint64_t h : hs) tokdel_.each(h, [&](uint32_t ti) { tis.push_back(ti); });
          std::sort(tis.begin(), tis.end());
          tis.erase(std::unique(tis.begin(), tis.end()), tis.end());
          for (uint32_t ti : tis) {
            const auto& [tk, e] = brand_tokens_[ti];
            if (entries_[e].registrable == registrable || !typo_edit_counts(part, tk)) continue;
            unsigned d1 = std::min(osa_distance(part, tk, 1), osa_distance(part_raw, expand_m(tk), 1));
            // The whole label equal to a token is the TLD-swap rule's business, not a token match.
            if (d1 == 0 && whole_label) continue;
            if (d1 > 1) continue;
            Severity sev = token_severity(from, to);
            // A typo'd short token alone is often another real word or brand (norden/nordea, revolt/revolut,
            // laposta/laposte): danger needs lure vocabulary around it, or a long token (mlcrosoft).
            if (d1 == 1 && whole_label && expand_m(tk).size() < opt_.token_typo_danger_min_len) sev = Severity::Caution;
            add_match(r, MatchKind::BrandToken, e, sev);
          }
        }
      }
    }
  }

  // Subdomain abuse.
  std::vector<std::string> labels = split(ascii_host, '.');
  size_t reg_labels = split(registrable, '.').size();
  if (labels.size() > reg_labels) {
    size_t nsub = labels.size() - reg_labels;
    std::vector<std::string> ul;
    ul.reserve(ul.size() + nsub);
    for (size_t i = 0; i < nsub; ++i) ul.push_back(ace_to_unicode_name(labels[i]));
    for (size_t i = 0; i < nsub; ++i) {
      for (size_t len = 2; len <= 4 && i + len <= nsub; ++len) {
        std::string run = join(ul, i, i + len, '.');
        for (const auto& k : dkeys(UnicodeString::fromUTF8(run))) {
          auto it = full_key_.find(k);
          if (it == full_key_.end()) continue;
          for (uint32_t e : it->second)
            if (entries_[e].registrable != registrable) add_match(r, MatchKind::SubdomainAbuse, e, Severity::Danger);
        }
      }
      for (const auto& k : dkeys(UnicodeString::fromUTF8(ul[i]))) {
        if (!brand_token_set_.count(k)) continue;
        for (const TokenRef& ref : tokens_.at(k))
          if (!ref.contact && entries_[ref.entry].registrable != registrable)
            add_match(r, MatchKind::SubdomainLabel, ref.entry, opt_.subdomain_label);
      }
    }
  }
}

HostReport EngineImpl::check_host(std::string_view host_in) const {
  HostReport r;
  std::string ace;
  if (!to_ace(host_in, &ace)) {
    r.display = std::string(host_in.substr(0, std::min<size_t>(host_in.size(), kMaxHostBytes)));
    r.idn = IdnReason::InvalidIdna;
    return r;
  }
  r.ascii = ace;
  r.unicode = ace_to_unicode_name(ace);
  r.registrable = registrable_domain(ace);

  // Per-label display decision (Chromium IDNToUnicodeWithAdjustments).
  std::vector<std::string> labels = split(ace, '.');
  std::string tld = labels.back();
  UnicodeString tld_u;
  if (tld.rfind("xn--", 0) != 0 || !ace_to_unicode_label(tld, &tld_u)) tld_u = UnicodeString::fromUTF8(tld);
  bool has_idn = false;
  bool all_safe = true;
  std::vector<std::string> shown;
  std::set<std::string> scripts;
  for (const auto& l : labels) {
    if (l.rfind("xn--", 0) != 0 || l.back() == '-') {
      shown.push_back(l);
      continue;
    }
    UnicodeString u;
    if (!ace_to_unicode_label(l, &u)) {
      shown.push_back(l);
      all_safe = false;
      if (r.idn == IdnReason::Ascii || r.idn == IdnReason::Safe) r.idn = IdnReason::InvalidIdna;
      continue;
    }
    has_idn = true;
    for (int32_t i = 0; i < u.length();) {
      UChar32 c = u.char32At(i);
      i += U16_LENGTH(c);
      UErrorCode st = U_ZERO_ERROR;
      UScriptCode sc = uscript_getScript(c, &st);
      if (sc != USCRIPT_COMMON && sc != USCRIPT_INHERITED && c >= 0x80) scripts.insert(uscript_getName(sc));
    }
    UErrorCode st = U_ZERO_ERROR;
    int32_t lvl = uspoof_check(sc_name_, u.getBuffer(), u.length(), nullptr, &st) & USPOOF_RESTRICTION_LEVEL_MASK;
    if (lvl > USPOOF_HIGHLY_RESTRICTIVE) r.mixed_script = true;
    IdnReason why = safe_to_display(u, tld, tld_u);
    if (why == IdnReason::Safe) {
      shown.push_back(to_utf8(u));
      if (r.idn == IdnReason::Ascii) r.idn = IdnReason::Safe;
    } else {
      shown.push_back(l);
      all_safe = false;
      if (r.idn == IdnReason::Ascii || r.idn == IdnReason::Safe) r.idn = why;
    }
  }
  r.scripts.assign(scripts.begin(), scripts.end());
  r.display = join(shown, 0, shown.size(), '.');
  r.show_unicode = has_idn && all_safe;

  // Skeleton of the registrable domain against protected and top domains (Chromium GetSimilarTopDomain).
  if (has_idn && !r.registrable.empty()) {
    std::string reg_u = ace_to_unicode_name(r.registrable);
    for (const auto& k : dkeys(UnicodeString::fromUTF8(reg_u))) {
      auto it = full_key_.find(k);
      if (it != full_key_.end())
        for (uint32_t e : it->second)
          if (entries_[e].registrable != r.registrable && r.similar_to.empty()) r.similar_to = entries_[e].registrable;
      auto tt = top_key_.find(k);
      if (tt != top_key_.end())
        for (const auto& d : tt->second)
          if (d != r.registrable && r.similar_to.empty()) r.similar_to = d;
    }
    if (!r.similar_to.empty()) {
      r.display = ace;
      r.show_unicode = false;
      r.idn = IdnReason::SimilarToProtected;
    }
  }
  if (!r.registrable.empty()) {
    size_t n = split(r.registrable, '.').size();
    std::vector<std::string> dl = split(r.display, '.');
    r.registrable_display = join(dl, dl.size() >= n ? dl.size() - n : 0, dl.size(), '.');
  }
  r.valid = !r.registrable.empty();
  if (!r.valid) return r;
  r.known_self = exact_.count(r.registrable) > 0;
  r.popular = popular_.count(r.registrable) > 0;
  if (!r.known_self && !r.popular) find_matches(ace, r.registrable, &r);
  return r;
}

EngineImpl::NameKeys EngineImpl::name_keys(std::string_view text) const {
  NameKeys nk;
  UnicodeString in = UnicodeString::fromUTF8(icu::StringPiece(text.data(), static_cast<int32_t>(text.size())));
  UnicodeString cleaned;
  int32_t cps = 0;
  for (int32_t i = 0; i < in.length() && cps < kMaxNameCodePoints;) {
    UChar32 c = in.char32At(i);
    i += U16_LENGTH(c);
    ++cps;
    if (u_hasBinaryProperty(c, UCHAR_DEFAULT_IGNORABLE_CODE_POINT) || u_hasBinaryProperty(c, UCHAR_BIDI_CONTROL) ||
        (u_iscntrl(c) && c != 0x20)) {
      nk.removed_invisible = true;
      continue;
    }
    cleaned.append(c);
  }
  UErrorCode st = U_ZERO_ERROR;
  UnicodeString n = nfkc_->normalize(cleaned, st);
  nk.normalized = to_utf8(n);
  // Two variants: skeleton of the case-folded text, and skeleton of the case-sensitive skeleton (catches
  // upper-case-only confusables such as I for l before folding). Both get Chromium's diacritic removal
  // (Latin/Greek/Cyrillic text only) and supplemental mappings (Cyrillic м/т/п/н/к ... -> m/t/n/h/k).
  UnicodeString v1;
  UnicodeString v2;
  if (is_ascii(n)) {
    // ASCII: diacritic removal and the supplemental mapper are no-ops and every step is per character, so
    // both variants come from per-character tables precomputed with ICU.
    for (int32_t i = 0; i < n.length(); ++i) {
      const UChar c = n.charAt(i) & 0x7F;
      for (char32_t x : ascii_name_v1_[c]) v1.append(static_cast<UChar32>(x));
      for (char32_t x : ascii_key_[c]) v2.append(static_cast<UChar32>(x));
    }
  } else {
    UnicodeString base = n;
    std::lock_guard<std::mutex> lk(translit_mu_);
    if (name_lgc_.containsAll(n)) diacritic_remover_->transliterate(base);
    v1 = base;
    v1.foldCase();
    extra_mapper_->transliterate(v1);
    v1 = skel(v1);
    v2 = skel(base);
    v2.foldCase();
    extra_mapper_->transliterate(v2);
    v2 = skel(v2);
  }
  for (UnicodeString* v : {&v1, &v2}) {
    v->findAndReplace(UNICODE_STRING_SIMPLE("vv"), UNICODE_STRING_SIMPLE("w"));
    v->findAndReplace(UNICODE_STRING_SIMPLE("rn"), UNICODE_STRING_SIMPLE("m"));
  }
  for (const UnicodeString* v : {&v1, &v2}) {
    std::vector<std::u32string> toks;
    std::u32string cur;
    for (int32_t i = 0; i < v->length();) {
      UChar32 c = v->char32At(i);
      i += U16_LENGTH(c);
      if (u_isalnum(c) || u_getIntPropertyValue(c, UCHAR_GENERAL_CATEGORY_MASK) & U_GC_M_MASK) {
        cur.push_back(static_cast<char32_t>(c));
      } else if (!cur.empty()) {
        toks.push_back(cur);
        cur.clear();
      }
    }
    if (!cur.empty()) toks.push_back(cur);
    nk.tokens.push_back(std::move(toks));
  }
  return nk;
}

bool EngineImpl::mixed_script_token(const UnicodeString& tok) const {
  UErrorCode st = U_ZERO_ERROR;
  int32_t lvl = uspoof_check(sc_name_, tok.getBuffer(), tok.length(), nullptr, &st) & USPOOF_RESTRICTION_LEVEL_MASK;
  return U_SUCCESS(st) && lvl > USPOOF_HIGHLY_RESTRICTIVE;
}

NameReport EngineImpl::check_display_name(std::string_view display_name, std::string_view address,
                                          std::string_view verified_domain) const {
  NameReport rep;
  NameKeys nk = name_keys(display_name);
  rep.normalized = nk.normalized;
  rep.removed_invisible = nk.removed_invisible;
  {
    UnicodeString n = UnicodeString::fromUTF8(nk.normalized);
    UnicodeString tok;
    for (int32_t i = 0; i <= n.length();) {
      UChar32 c = i < n.length() ? n.char32At(i) : 0x20;
      i += i < n.length() ? U16_LENGTH(c) : 1;
      if (u_isUWhiteSpace(c)) {
        if (!tok.isEmpty() && !is_ascii(tok) && mixed_script_token(tok)) rep.mixed_script = true;
        tok.remove();
      } else {
        tok.append(c);
      }
    }
  }
  const std::string addr = ascii_lower(address);
  const std::string sender_reg = registrable_of_address(addr);
  std::string verified_reg;
  if (!verified_domain.empty()) {
    std::string ace;
    if (to_ace(verified_domain, &ace)) verified_reg = registrable_domain(ace);
  }
  const bool sender_shared = shared_.count(sender_reg) > 0;
  auto add = [&](NameMatchKind k, Severity s, const std::string& matched, bool confusable) {
    for (auto& m : rep.matches)
      if (m.kind == k && m.matched == matched) {
        if (static_cast<int>(s) > static_cast<int>(m.severity)) m.severity = s;
        m.confusable &= confusable;
        return;
      }
    rep.matches.push_back({k, s, matched, confusable});
  };
  auto person_backed = [&](const Person& p) {
    if (p.addresses.count(addr)) return true;
    // Same organisation domain, authenticated, not a shared mailbox provider.
    return !sender_reg.empty() && !sender_shared && p.registrables.count(sender_reg) && verified_reg == sender_reg;
  };
  UnicodeString folded_raw = UnicodeString::fromUTF8(nk.normalized);
  folded_raw.foldCase();

  // People: exact key (or sorted tokens) -> danger; containment of the full name among other words -> caution.
  // If any person whose name matches is backed by this sender (address book holds several people with the
  // same name, or one person with several addresses), the name belongs to the sender and nothing fires.
  std::map<uint32_t, NameMatchKind> exact_people;
  std::map<uint32_t, NameMatchKind> contained_people;
  for (size_t vi = 0; vi < nk.tokens.size(); ++vi) {
    const auto& toks = nk.tokens[vi];
    if (toks.empty()) continue;
    std::u32string joined;
    std::u32string sorted_joined;
    std::vector<std::u32string> sorted = toks;
    std::sort(sorted.begin(), sorted.end());
    for (size_t i = 0; i < toks.size(); ++i) {
      if (i) joined.push_back(U' '), sorted_joined.push_back(U' ');
      joined += toks[i];
      sorted_joined += sorted[i];
    }
    for (const auto* key : {&joined, &sorted_joined}) {
      auto it = person_key_.find(*key);
      if (it == person_key_.end()) continue;
      for (const PersonRef& ref : it->second) exact_people.emplace(ref.person, ref.kind);
    }
    for (size_t i = 0; i < toks.size(); ++i) {
      auto it = person_first_token_.find(toks[i]);
      if (it == person_first_token_.end()) continue;
      for (const PersonRef& ref : it->second) {
        const auto& ptoks = persons_[ref.person].tokens[vi];
        if (ptoks.size() < opt_.contact_name_min_tokens || i + ptoks.size() > toks.size()) continue;
        if (std::equal(ptoks.begin(), ptoks.end(), toks.begin() + std::ptrdiff_t(i))) contained_people.emplace(ref.person, ref.kind);
      }
    }
  }
  bool name_backed = false;
  for (const auto& [pi, kind] : exact_people) name_backed |= person_backed(persons_[pi]);
  for (const auto& [pi, kind] : contained_people) name_backed |= person_backed(persons_[pi]);
  if (!name_backed) {
    for (const auto& [pi, kind] : exact_people) {
      UnicodeString pf = UnicodeString::fromUTF8(persons_[pi].name);
      pf.foldCase();
      add(kind, Severity::Danger, persons_[pi].name, !(pf == folded_raw));
    }
    for (const auto& [pi, kind] : contained_people)
      if (!exact_people.count(pi)) add(kind, Severity::Caution, persons_[pi].name, true);
  }

  // Brands and organisation names.
  auto match_names = [&](const std::vector<BrandName>& names, const NameIndex& index, NameMatchKind kind,
                         const std::function<bool(const BrandName&)>& backed) {
    // Candidates: names whose first token occurs in the display name, or whose concatenation (>= 5) occurs
    // in the display name's concatenation; checked in list order so results are deterministic.
    std::set<uint32_t> cand;
    for (const auto& variant : nk.tokens) {
      std::u32string all;
      for (const auto& t : variant) {
        auto it = index.first.find(t);
        if (it != index.first.end()) cand.insert(it->second.begin(), it->second.end());
        all += t;
      }
      const std::u32string_view av(all);
      for (size_t i = 0; i < av.size(); ++i)
        for (size_t len = 5; i + len <= av.size() && len < index.concat_lens.size(); ++len) {
          if (!index.concat_lens[len]) continue;
          auto it = index.concat.find(av.substr(i, len));
          if (it != index.concat.end()) cand.insert(it->second.begin(), it->second.end());
        }
    }
    for (uint32_t ni : cand) {
      const BrandName& bn = names[ni];
      for (size_t vi = 0; vi < nk.tokens.size() && vi < bn.tokens.size(); ++vi) {
        const auto& toks = nk.tokens[vi];
        const auto& btoks = bn.tokens[vi];
        if (btoks.empty() || toks.empty()) continue;
        bool hit = false;
        if (bn.generic) {
          // Whole name, optionally with service words only ("Chase", "Chase Alerts"; not "Chase Miller").
          size_t pos = toks.size();
          for (size_t i = 0; i + btoks.size() <= toks.size(); ++i)
            if (std::equal(btoks.begin(), btoks.end(), toks.begin() + std::ptrdiff_t(i))) {
              pos = i;
              break;
            }
          if (pos != toks.size()) {
            hit = true;
            for (size_t i = 0; i < toks.size(); ++i)
              if ((i < pos || i >= pos + btoks.size()) && !service_words().count(toks[i])) hit = false;
          }
        } else {
          for (size_t i = 0; i + btoks.size() <= toks.size() && !hit; ++i)
            hit = std::equal(btoks.begin(), btoks.end(), toks.begin() + std::ptrdiff_t(i));
          if (!hit && bn.concat[vi].size() >= 5) {
            std::u32string all;
            for (const auto& t : toks) all += t;
            hit = all.find(bn.concat[vi]) != std::u32string::npos;
          }
        }
        if (!hit) continue;
        if (backed(bn)) break;
        UnicodeString bf = UnicodeString::fromUTF8(bn.text);
        bf.foldCase();
        add(kind, Severity::Danger, kind == NameMatchKind::BrandName ? brands_[bn.brand].id : bn.text,
            folded_raw.indexOf(bf) < 0);
        break;
      }
    }
  };
  match_names(brand_names_, brand_name_index_, NameMatchKind::BrandName,
              [&](const BrandName& bn) { return brand_registrables_[bn.brand].count(sender_reg) > 0; });
  match_names(org_names_, org_name_index_, NameMatchKind::OrgName,
              [&](const BrandName&) { return own_registrables_.count(sender_reg) > 0; });

  // Addresses and domain-shaped tokens inside the display name (P3).
  {
    UErrorCode st2 = U_ZERO_ERROR;
    UnicodeString hay = UnicodeString::fromUTF8(nk.normalized);
    std::unique_ptr<icu::RegexMatcher> m(domain_re_->matcher(hay, st2));
    while (U_SUCCESS(st2) && m->find()) {
      const int32_t at = m->start(st2);
      const bool email = at > 0 && hay.charAt(at - 1) == u'@';
      std::string cand = to_utf8(m->group(st2));
      std::string ace;
      if (!to_ace(cand, &ace)) continue;
      std::string reg = registrable_domain(ace);
      if (reg.empty()) continue;
      std::string suf = suffix_of(reg);
      if (suf.empty() || !psl_.listed(suf)) continue;
      if (reg == sender_reg) continue;
      // An address in the name that is not the sender's is danger (P3). A bare domain-shaped token is only a
      // caution: newsletters name their site ("CNET News.com") while sending from an ESP domain, and initials
      // ("R.Hughes") parse as domains under new gTLDs, so single-character labels are ignored.
      if (email) {
        add(NameMatchKind::EmbeddedAddress, Severity::Danger, reg, false);
      } else if (reg.find('.') >= 2) {
        add(NameMatchKind::EmbeddedAddress, opt_.embedded_domain, reg, false);
      }
    }
  }
  return rep;
}

SenderReport EngineImpl::check_sender(const SenderInput& in) const {
  SenderReport r;
  size_t at = in.address.rfind('@');
  if (at != std::string_view::npos) r.from = check_host(in.address.substr(at + 1));
  r.name = check_display_name(in.display_name, in.address, in.verified_domain);
  r.severity = std::max(r.from.severity(), r.name.severity());
  return r;
}

size_t EngineImpl::index_bytes() const {
  size_t b = entries_.capacity() * sizeof(Entry);
  b += popular_.bucket_count() * sizeof(void*);
  for (const auto& d : popular_) b += sizeof(std::string) + (d.size() > 15 ? d.capacity() + 1 : 0) + 2 * sizeof(void*);
  for (const auto& e : entries_) b += e.registrable.capacity() + e.suffix.capacity() + e.brand.capacity();
  b += exact_.bucket_count() * sizeof(void*);
  for (const auto& [k, v] : exact_) b += sizeof(std::string) + k.capacity() + sizeof(std::decay_t<decltype(v)>) + v.capacity() * 4 + 2 * sizeof(void*);
  b += deletes_idx_.bytes() + labelh_.bytes() + tokdel_.bytes();
  b += map_bytes(full_key_) + map_bytes(label_key_) + map_bytes(tokens_) +
       map_bytes(person_key_) + map_bytes(person_first_token_) +
       brand_tokens_.capacity() * sizeof(brand_tokens_[0]);
  for (const auto& p : persons_) {
    b += sizeof(p) + p.name.capacity();
    for (const auto& a : p.addresses) b += a.capacity() + 3 * sizeof(void*);
    for (const auto& a : p.registrables) b += a.capacity() + 3 * sizeof(void*);
  }
  return b;
}

}  // namespace

Severity HostReport::severity() const {
  Severity s = Severity::None;
  for (const auto& m : matches) s = std::max(s, m.severity);
  return s;
}

Severity NameReport::severity() const {
  Severity s = Severity::None;
  for (const auto& m : matches) s = std::max(s, m.severity);
  return s;
}

std::unique_ptr<Engine> Engine::create(std::string_view psl_text, const Options& options, std::string* error) {
  auto e = std::make_unique<EngineImpl>(options);
  if (!e->init(psl_text, error)) return nullptr;
  return e;
}

const char* to_string(MatchKind k) {
  switch (k) {
    case MatchKind::Homoglyph: return "homoglyph";
    case MatchKind::VisualPair: return "visual_pair";
    case MatchKind::Typo: return "typo";
    case MatchKind::TldSwap: return "tld_swap";
    case MatchKind::BrandToken: return "token";
    case MatchKind::SubdomainAbuse: return "subdomain_abuse";
    case MatchKind::SubdomainLabel: return "subdomain_label";
  }
  return "?";
}
const char* to_string(TargetKind k) {
  switch (k) {
    case TargetKind::Own: return "own";
    case TargetKind::Contact: return "contact";
    case TargetKind::Brand: return "brand";
  }
  return "?";
}
const char* to_string(Severity s) {
  switch (s) {
    case Severity::None: return "none";
    case Severity::Caution: return "caution";
    case Severity::Danger: return "danger";
  }
  return "?";
}
const char* to_string(IdnReason r) {
  switch (r) {
    case IdnReason::Ascii: return "ascii";
    case IdnReason::Safe: return "safe";
    case IdnReason::InvalidIdna: return "invalid_idna";
    case IdnReason::IcuSpoofChecks: return "icu_spoof_checks";
    case IdnReason::TldSpecificCharacters: return "tld_specific_characters";
    case IdnReason::UnsafeMiddleDot: return "unsafe_middle_dot";
    case IdnReason::WholeScriptConfusable: return "whole_script_confusable";
    case IdnReason::DigitLookalikes: return "digit_lookalikes";
    case IdnReason::NonAsciiLatinMixed: return "non_ascii_latin_mixed";
    case IdnReason::DangerousPattern: return "dangerous_pattern";
    case IdnReason::SimilarToProtected: return "similar_to_protected";
  }
  return "?";
}
const char* to_string(NameMatchKind k) {
  switch (k) {
    case NameMatchKind::ContactName: return "contact_name";
    case NameMatchKind::OwnName: return "own_name";
    case NameMatchKind::OrgName: return "org_name";
    case NameMatchKind::BrandName: return "brand_name";
    case NameMatchKind::EmbeddedAddress: return "embedded_address";
  }
  return "?";
}

}  // namespace maillookalike

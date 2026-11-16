// Lookalike engine for mail senders and link hosts: IDN display decision, registrable-domain lookalikes, display-name
// impersonation.
//
// Pure, local, no I/O after construction. Inputs are bounded strings that come from a mail
// client's message record (sender display name, address, authenticated domain, link hosts); outputs are
// enumerations plus the matched protected domain/name for the one-sentence reason.
//
// Thread safety: an Engine is immutable after set_profile(); check_* are const and may run concurrently
// (ICU USpoofChecker/Normalizer2/UIDNA are thread-safe for const use; Transliterator and RegexMatcher are
// created per call or guarded internally).
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace maillookalike {

enum class Severity : uint8_t { None = 0, Caution = 1, Danger = 2 };

enum class MatchKind : uint8_t {
  Homoglyph,        // same UTS #39 skeleton as a protected registrable domain; differs outside ASCII
  VisualPair,       // same skeleton, ASCII-only difference (rn/m, vv/w, 1/l/I, 0/o)
  Typo,             // Damerau-Levenshtein 1 on the registrable label (label >= typo_min_len)
  TldSwap,          // same label skeleton, different public suffix
  BrandToken,       // protected token inside another registrable label
  SubdomainAbuse,   // protected registrable domain spelled out in the subdomain part
  SubdomainLabel,   // protected brand token used as a whole subdomain label
};

enum class TargetKind : uint8_t { Own, Contact, Brand };

struct DomainMatch {
  MatchKind kind;
  TargetKind target;
  Severity severity;
  std::string matched_domain;  // protected registrable domain (ACE)
  std::string brand;           // brand id when target == Brand
};

// Why a host is (not) shown in Unicode. Mirrors Chromium's IDNSpoofCheckerResult plus the skeleton test.
enum class IdnReason : uint8_t {
  Ascii,                     // no IDN label
  Safe,                      // all IDN labels pass; shown in Unicode
  InvalidIdna,               // UTS #46 rejected the label
  IcuSpoofChecks,            // uspoof: restriction level above highly restrictive, invisible, mixed numbers, char limit
  TldSpecificCharacters,     // þ/ð outside .is/.fo, ə outside .az
  UnsafeMiddleDot,
  WholeScriptConfusable,     // e.g. all-Cyrillic label made only of Latin lookalikes under an ASCII TLD
  DigitLookalikes,
  NonAsciiLatinMixed,
  DangerousPattern,
  SimilarToProtected,        // skeleton of the registrable domain equals a protected/top domain's
};

struct HostReport {
  bool valid = false;               // UTS #46 accepted the host and it has a registrable domain
  std::string ascii;                // canonical ACE host
  std::string unicode;              // UTS #46 ToUnicode (analysis only; never shown unless show_unicode)
  std::string display;              // what chrome shows (per-label Unicode/Punycode decision)
  std::string registrable;          // ACE eTLD+1
  std::string registrable_display;  // registrable part of `display`
  bool show_unicode = false;        // every IDN label is shown decoded
  IdnReason idn = IdnReason::Ascii;
  std::string similar_to;           // protected domain when idn == SimilarToProtected
  std::vector<std::string> scripts; // scripts present in non-ASCII labels ("Cyrillic", ...)
  bool mixed_script = false;        // some label is above UTS #39 "highly restrictive"
  bool known_self = false;          // registrable is itself an own/contact/brand domain: matches suppressed
  bool popular = false;             // registrable is on the shipped popular-domain list: matches suppressed
  std::vector<DomainMatch> matches; // lookalike matches (empty when known_self or popular)
  Severity severity() const;
};

enum class NameMatchKind : uint8_t { ContactName, OwnName, OrgName, BrandName, EmbeddedAddress };

struct NameMatch {
  NameMatchKind kind;
  Severity severity;
  std::string matched;     // contact/own/org/brand name, or the embedded address/domain
  bool confusable = false; // matched only after skeleton folding (text differs from the protected name)
};

struct NameReport {
  std::string normalized;          // display name after invisible/bidi removal + NFKC (what chrome may show)
  bool removed_invisible = false;  // bidi controls / default-ignorables were present
  bool mixed_script = false;       // a token is above "highly restrictive"
  std::vector<NameMatch> matches;  // only matches NOT backed by identity
  Severity severity() const;
};

struct Contact {
  std::string name;
  std::vector<std::string> addresses;
};

struct Brand {
  std::string id;
  std::vector<std::string> names;    // display names
  std::vector<std::string> domains;  // registrable domains owned
  std::vector<std::string> tokens;   // distinctive tokens searched inside other domains
  bool generic_name = false;         // name is an ordinary word/surname: whole-name match only
};

struct Profile {
  std::vector<std::string> own_names;
  std::vector<std::string> own_addresses;
  std::vector<std::string> org_names;
  std::vector<Contact> contacts;
  std::vector<Brand> brands;
  std::vector<std::string> shared_mailbox_domains;  // freemail: identity needs the exact address
  std::vector<std::string> top_domains;             // optional shipped top list: IDN display decision only
  std::vector<std::string> popular_domains;         // shipped popular registrable domains (ACE): never lookalikes
};

struct Options {
  // Thresholds (values chosen on measured false-positive and detection rates; see README).
  unsigned typo_min_len = 5;              // DL-1 only on protected labels at least this long (code points)
  bool typo_shorter_candidate = false;    // candidate label may be typo_min_len - 1 long (adobe -> adoe)
  unsigned swap_min_len = 4;              // TLD swap only for protected labels at least this long
  bool typo_ignore_digit_edits = true;    // an edit confined to digits 2-9 is not a typo (site2 vs site5)
  unsigned typo_contact_danger_min_len = 7;  // typos of contact labels shorter than this are caution
  unsigned token_typo_min_len = 6;        // typo'd brand token parts must be at least this long (cloud ≠ icloud)
  unsigned token_typo_danger_min_len = 8; // a typo'd token as the whole label is danger only if the token is this long
  bool brand_token_needs_lure = true;     // brand token is danger only next to lure words; else caution
  bool typo_same_suffix = true;           // DL-1 only against the same public suffix
  unsigned brand_token_min_len = 5;       // brand token search
  unsigned brand_token_anywhere_len = 8;  // tokens this long match anywhere; shorter need a label boundary
  unsigned contact_token_min_len = 0;     // 0 = contact/own labels are not searched as tokens
  bool brand_swap_tokens_only = true;     // TLD swap / typo against brand labels only when the label is a brand token
  Severity tld_swap_brand = Severity::Caution;    // same label, other suffix (a confusable label is danger)
  Severity tld_swap_contact = Severity::Caution;
  Severity brand_token = Severity::Danger;
  Severity contact_token = Severity::Caution;
  Severity subdomain_label = Severity::Caution;
  Severity embedded_domain = Severity::Caution;  // bare domain in the display name ≠ sender (an address is danger)
  unsigned contact_name_min_tokens = 2;   // single-token contact names never raise danger
};

struct SenderInput {
  std::string_view display_name;
  std::string_view address;          // addr-spec from From
  std::string_view verified_domain;  // DMARC-aligned (or trusted ARH) domain; empty when not verified
};

struct SenderReport {
  HostReport from;
  NameReport name;
  Severity severity = Severity::None;
};

class Engine {
 public:
  // psl_text: the pinned public_suffix_list.dat (ICANN + private sections), the list the caller's other components use.
  static std::unique_ptr<Engine> create(std::string_view psl_text, const Options& options, std::string* error);
  virtual ~Engine() = default;

  // Rebuilds every index; O(contacts + brands). Call again when contacts change.
  virtual void set_profile(const Profile& profile) = 0;

  virtual HostReport check_host(std::string_view host) const = 0;
  virtual NameReport check_display_name(std::string_view display_name, std::string_view address,
                                        std::string_view verified_domain) const = 0;
  virtual SenderReport check_sender(const SenderInput& in) const = 0;

  // Primitives exposed for tests and tools.
  virtual std::string registrable_domain(std::string_view ace_host) const = 0;
  virtual std::string skeleton(std::string_view utf8) const = 0;      // ICU uspoof_getSkeleton, type 0
  virtual std::vector<std::string> domain_keys(std::string_view unicode) const = 0;  // comparison keys
  virtual size_t index_bytes() const = 0;                              // approximate heap held by indexes
};

const char* to_string(MatchKind);
const char* to_string(TargetKind);
const char* to_string(Severity);
const char* to_string(IdnReason);
const char* to_string(NameMatchKind);

}  // namespace maillookalike

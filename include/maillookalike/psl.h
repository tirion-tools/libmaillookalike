// The Public Suffix List through libpsl, loaded from the caller's pinned public_suffix_list.dat (ICANN and private
// sections; no built-in or system list is used). Hosts are ASCII (A-labels), lower case, without a trailing dot.
//
// Thread safety: immutable after load(); every member is const and may run concurrently.
#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

struct psl_ctx_st;

namespace maillookalike {

class Psl {
 public:
  // psl_text: the list text. fixture_tlds: extra top-level labels has_known_tld() accepts (test fixtures that use
  // RFC 2606 names); empty in production. Returns nullptr and sets *error when the list does not load.
  static std::shared_ptr<const Psl> load(std::string_view psl_text, std::vector<std::string> fixture_tlds,
                                         std::string* error);
  ~Psl();
  Psl(const Psl&) = delete;
  Psl& operator=(const Psl&) = delete;

  // The registrable domain (public suffix by the longest rule, exceptions first, the implicit "*" rule, plus one
  // label), or "" when the host is empty, longer than 253 bytes, has an empty label or is itself a public suffix.
  std::string registrable(std::string_view host) const;
  // True when an explicit rule lists the suffix (the implicit "*" rule does not count).
  bool listed(std::string_view suffix) const;
  // True when the last label of the host is a listed top-level suffix or a fixture TLD ("domain-shaped").
  bool has_known_tld(std::string_view host) const;

 private:
  Psl() = default;
  psl_ctx_st* ctx_ = nullptr;
  std::vector<std::string> fixture_tlds_;
};

}  // namespace maillookalike

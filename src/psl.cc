#include "maillookalike/psl.h"

#include <libpsl.h>

#include <algorithm>
#include <cstdio>

namespace maillookalike {

std::shared_ptr<const Psl> Psl::load(std::string_view psl_text, std::vector<std::string> fixture_tlds,
                                     std::string* error) {
  std::string buf(psl_text);
  std::shared_ptr<Psl> p(new Psl());
  p->fixture_tlds_ = std::move(fixture_tlds);
  if (!buf.empty()) {
#ifdef _WIN32
    // No fmemopen in the Windows CRT: libpsl reads the list from an anonymous temporary file instead.
    FILE* f = std::tmpfile();
    if (f != nullptr && (std::fwrite(buf.data(), 1, buf.size(), f) != buf.size() || std::fseek(f, 0, SEEK_SET) != 0)) {
      std::fclose(f);
      f = nullptr;
    }
#else
    FILE* f = fmemopen(buf.data(), buf.size(), "r");
#endif
    if (f != nullptr) {
      p->ctx_ = psl_load_fp(f);
      std::fclose(f);
    }
  }
  // A real list has thousands of rules; a truncated or wrong file is refused rather than used.
  if (p->ctx_ == nullptr || psl_suffix_count(p->ctx_) < 1000) {
    if (error) *error = "the public suffix list could not be loaded";
    return nullptr;
  }
  return p;
}

Psl::~Psl() {
  if (ctx_) psl_free(ctx_);
}

std::string Psl::registrable(std::string_view host) const {
  if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.' ||
      host.find("..") != std::string_view::npos)
    return {};
  const std::string h(host);
  const char* r = psl_registrable_domain(ctx_, h.c_str());
  return r ? std::string(r) : std::string();
}

bool Psl::listed(std::string_view suffix) const {
  if (suffix.empty()) return false;
  const std::string s(suffix);
  return psl_is_public_suffix2(ctx_, s.c_str(), PSL_TYPE_ANY | PSL_TYPE_NO_STAR_RULE) != 0;
}

bool Psl::has_known_tld(std::string_view host) const {
  const size_t dot = host.rfind('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 == host.size()) return false;
  const std::string_view tld = host.substr(dot + 1);
  if (listed(tld)) return true;
  return std::find(fixture_tlds_.begin(), fixture_tlds_.end(), tld) != fixture_tlds_.end();
}

}  // namespace maillookalike

// Fixture loading for the tests: the pinned PSL copy, the link lists (tests/data/lists.tsv) and line splitting.
#pragma once

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "maillookalike/links.h"
#include "maillookalike/psl.h"

namespace testdata {

inline std::string read(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  std::stringstream s;
  s << f.rdbuf();
  return s.str();
}

inline std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> r;
  size_t p = 0;
  while (true) {
    const size_t q = s.find(sep, p);
    r.push_back(s.substr(p, q == std::string::npos ? std::string::npos : q - p));
    if (q == std::string::npos) break;
    p = q + 1;
  }
  return r;
}

inline std::vector<std::string> lines(const std::string& path) {
  std::vector<std::string> r = split(read(path), '\n');
  if (!r.empty() && r.back().empty()) r.pop_back();
  return r;
}

// Unescapes a vector field (tools/vectors_tsv.py) into its list elements: "\|" separates, "\\", "\t", "\n", "\r".
inline std::vector<std::string> unescape_list(const std::string& f) {
  std::vector<std::string> r;
  if (f.empty()) return r;
  r.emplace_back();
  for (size_t i = 0; i < f.size(); ++i) {
    if (f[i] != '\\' || i + 1 == f.size()) {
      r.back() += f[i];
      continue;
    }
    const char c = f[++i];
    if (c == '|') r.emplace_back();
    else r.back() += c == 't' ? '\t' : c == 'n' ? '\n' : c == 'r' ? '\r' : c;
  }
  return r;
}
inline std::string unescape(const std::string& f) {
  std::vector<std::string> l = unescape_list(f);
  return l.empty() ? std::string() : l.front();
}

// Rows of a vector file: comment lines dropped, fields split on tabs.
inline std::vector<std::vector<std::string>> rows(const std::string& path) {
  std::vector<std::vector<std::string>> r;
  for (const std::string& l : lines(path))
    if (!l.empty() && l[0] != '#') r.push_back(split(l, '\t'));
  return r;
}

inline std::shared_ptr<const maillookalike::Psl> psl(std::vector<std::string> fixture_tlds = {}) {
  std::string err;
  return maillookalike::Psl::load(read(MAILLOOKALIKE_TEST_DATA "/public_suffix_list.dat"), std::move(fixture_tlds), &err);
}

inline std::shared_ptr<const maillookalike::LinkLists> lists() {
  maillookalike::LinkListsData d;
  for (const std::string& l : lines(MAILLOOKALIKE_TEST_DATA "/lists.tsv")) {
    const std::vector<std::string> f = split(l, '\t');
    if (f[0] == "rule") {
      maillookalike::HostPathRule r{f[2], f[3], f[4], f[5].empty() ? std::vector<std::string>() : split(f[5], ','), f[6]};
      (f[1] == "redirectors" ? d.redirectors : f[1] == "oauth_endpoints" ? d.oauth : d.device).push_back(std::move(r));
    } else if (f[1] == "generic_redirect_params") {
      d.generic_params.push_back(f[2]);
    } else if (f[1] == "esp_trackers") {
      d.esp_trackers.push_back(f[2]);
    } else if (f[1] == "shorteners") {
      d.shorteners.push_back(f[2]);
    } else {
      d.user_content_hosts.push_back(f[2]);
    }
  }
  std::string err;
  return maillookalike::LinkLists::compile(d, &err);
}

}  // namespace testdata

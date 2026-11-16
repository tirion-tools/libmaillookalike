// libFuzzer: URL parsing and the link checks on untrusted input. Input: href, then optional NUL-separated texts.
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

#include "maillookalike/links.h"

namespace {
std::string read(const char* path) {
  std::ifstream f(path, std::ios::binary);
  std::stringstream s;
  s << f.rdbuf();
  return s.str();
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static const auto psl = maillookalike::Psl::load(read(MAILLOOKALIKE_TEST_DATA "/public_suffix_list.dat"), {}, nullptr);
  static const auto lists = [] {
    maillookalike::LinkListsData d;
    d.redirectors.push_back({"safelinks", "\\.safelinks\\.protection\\.outlook\\.com$", "", {"url"}, ""});
    d.redirectors.push_back({"proofpoint-v2", "^urldefense\\.proofpoint\\.com$", "^/v2/url$", {"u"}, "proofpoint-v2"});
    d.redirectors.push_back({"proofpoint-v3", "^urldefense\\.com$", "^/v3/__", {}, "proofpoint-v3"});
    d.redirectors.push_back({"bing", "^www\\.bing\\.com$", "^/ck/a$", {"u"}, "bing"});
    d.generic_params = {"url", "redirect", "u", "target"};
    d.oauth.push_back({"microsoft", "^login\\.microsoftonline\\.com$", "^/[^/]+/oauth2/(v2\\.0/)?authorize", {}, ""});
    d.device.push_back({"microsoft", "^(www\\.)?microsoft\\.com$", "^/devicelogin", {}, ""});
    return maillookalike::LinkLists::compile(d, nullptr);
  }();
  const std::string in(reinterpret_cast<const char*>(data), size);
  maillookalike::LinkFacts f;
  size_t p = in.find('\0');
  f.href = in.substr(0, p);
  while (p != std::string::npos) {
    const size_t q = in.find('\0', p + 1);
    f.texts.push_back(in.substr(p + 1, q == std::string::npos ? std::string::npos : q - p - 1));
    p = q;
  }
  f.source = maillookalike::kSourceHtml;
  (void)maillookalike::assess(f, *psl, *lists);
  return 0;
}

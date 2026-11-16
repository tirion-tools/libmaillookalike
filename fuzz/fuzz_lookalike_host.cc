// libFuzzer: the lookalike engine on an untrusted host, display name and address (input split at the first two NULs).
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

#include "maillookalike/lookalike.h"

namespace {
std::string read(const char* path) {
  std::ifstream f(path, std::ios::binary);
  std::stringstream s;
  s << f.rdbuf();
  return s.str();
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static const auto eng = [] {
    auto e = maillookalike::Engine::create(
        maillookalike::Psl::load(read(MAILLOOKALIKE_TEST_DATA "/public_suffix_list.dat"), {}, nullptr),
        maillookalike::Options{}, nullptr);
    maillookalike::Profile p;
    p.brands.push_back({"paypal", {"PayPal"}, {"paypal.com"}, {"paypal"}, false});
    p.brands.push_back({"microsoft", {"Microsoft"}, {"microsoft.com"}, {"sharepoint", "outlook"}, false});
    p.contacts.push_back({"Ryan Evans", {"ryan.evans@proton.me"}});
    p.own_names = {"Alex Morgan"};
    p.own_addresses = {"alex.morgan@kestrelworks.com"};
    e->set_profile(p);
    return e;
  }();
  const std::string in(reinterpret_cast<const char*>(data), size);
  const size_t a = in.find('\0');
  const size_t b = a == std::string::npos ? std::string::npos : in.find('\0', a + 1);
  const std::string host = in.substr(0, a);
  (void)eng->check_host(host);
  if (a != std::string::npos) {
    const std::string name = in.substr(a + 1, b == std::string::npos ? std::string::npos : b - a - 1);
    const std::string addr = b == std::string::npos ? std::string() : in.substr(b + 1);
    (void)eng->check_sender({name, addr, ""});
  }
  return 0;
}

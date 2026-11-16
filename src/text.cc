#include "text.h"

#include <unicode/normalizer2.h>
#include <unicode/uchar.h>
#include <unicode/unistr.h>

namespace maillookalike::detail {

char32_t next_cp(std::string_view s, size_t& i) {
  const auto b0 = static_cast<unsigned char>(s[i]);
  if (b0 < 0x80) {
    ++i;
    return b0;
  }
  size_t n = 0;
  char32_t c = 0;
  if ((b0 & 0xE0) == 0xC0) {
    n = 1;
    c = b0 & 0x1F;
  } else if ((b0 & 0xF0) == 0xE0) {
    n = 2;
    c = b0 & 0x0F;
  } else if ((b0 & 0xF8) == 0xF0) {
    n = 3;
    c = b0 & 0x07;
  } else {
    ++i;
    return 0xFFFD;
  }
  if (i + n >= s.size()) {
    ++i;
    return 0xFFFD;
  }
  for (size_t k = 1; k <= n; ++k) {
    const auto b = static_cast<unsigned char>(s[i + k]);
    if ((b & 0xC0) != 0x80) {
      ++i;
      return 0xFFFD;
    }
    c = (c << 6) | (b & 0x3F);
  }
  const char32_t min = n == 1 ? 0x80 : n == 2 ? 0x800 : 0x10000;
  if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) {
    ++i;
    return 0xFFFD;
  }
  i += n + 1;
  return c;
}

void append_utf8(std::string& out, char32_t c) {
  if (c < 0x80) {
    out += static_cast<char>(c);
  } else if (c < 0x800) {
    out += static_cast<char>(0xC0 | (c >> 6));
    out += static_cast<char>(0x80 | (c & 0x3F));
  } else if (c < 0x10000) {
    out += static_cast<char>(0xE0 | (c >> 12));
    out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (c & 0x3F));
  } else {
    out += static_cast<char>(0xF0 | (c >> 18));
    out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (c & 0x3F));
  }
}

std::string ascii_lower(std::string_view s) {
  std::string r(s);
  for (char& c : r)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return r;
}

bool is_bidi(char32_t c) {
  return (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F || c == 0x061C;
}

bool is_invisible(char32_t c) {
  return c == 0x200B || c == 0x200C || c == 0x200D || (c >= 0x2060 && c <= 0x2064) || c == 0xFEFF || c == 0x00AD ||
         c == 0x034F || c == 0x180E || c == 0x115F || c == 0x1160 || c == 0x3164 || c == 0xFFA0 || c == 0x17B4 ||
         c == 0x17B5 || (c >= 0x206A && c <= 0x206F) || (c >= 0xFFF9 && c <= 0xFFFB) ||
         (c >= 0xE0000 && c <= 0xE007F) || (c >= 0x1D173 && c <= 0x1D17A);
}

std::string clean_text(std::string_view s, size_t max) {
  std::string out;
  size_t units = 0;
  bool space = false;
  for (size_t i = 0; i < s.size();) {
    const char32_t c = next_cp(s, i);
    if (is_bidi(c) || is_invisible(c)) continue;
    if (c < 0x20 || (c >= 0x7F && c <= 0x9F) || u_isUWhiteSpace(static_cast<UChar32>(c)) || c == 0xA0) {
      space = !out.empty();
      continue;
    }
    if (units >= max * 2) continue;
    if (space) {
      out += ' ';
      ++units;
      space = false;
    }
    append_utf8(out, c);
    units += c > 0xFFFF ? 2 : 1;
  }
  UErrorCode st = U_ZERO_ERROR;
  const icu::Normalizer2* nfkc = icu::Normalizer2::getNFKCInstance(st);
  if (U_SUCCESS(st)) {
    icu::UnicodeString n = nfkc->normalize(icu::UnicodeString::fromUTF8(out), st);
    if (U_SUCCESS(st)) {
      if (static_cast<size_t>(n.length()) > max) {
        int32_t cut = static_cast<int32_t>(max);
        if (U16_IS_LEAD(n.charAt(cut - 1))) --cut;
        n.truncate(cut);
      }
      out.clear();
      n.toUTF8String(out);
    }
  }
  return out;
}

std::string clip_utf8(std::string_view s, size_t max_bytes) {
  if (s.size() <= max_bytes) return std::string(s);
  size_t end = 0;
  for (size_t i = 0; i < s.size();) {
    size_t j = i;
    next_cp(s, j);
    if (j > max_bytes) break;
    end = i = j;
  }
  return std::string(s.substr(0, end));
}

}  // namespace maillookalike::detail

// UTF-8 helpers shared by the URL parser and the link checks (internal).
#pragma once

#include <string>
#include <string_view>

namespace maillookalike::detail {

// Decodes one code point at s[i] (advancing i); invalid bytes give U+FFFD and advance by one.
char32_t next_cp(std::string_view s, size_t& i);
void append_utf8(std::string& out, char32_t c);
std::string ascii_lower(std::string_view s);
bool is_bidi(char32_t c);
bool is_invisible(char32_t c);
// Removes bidi/invisible characters and C0/C1 controls, collapses white space (and U+00A0) to one space, NFKC;
// at most max UTF-16 code units, as the engine's text normaliser.
std::string clean_text(std::string_view s, size_t max = 256);
// The longest prefix of s of at most max_bytes bytes, whole code points.
std::string clip_utf8(std::string_view s, size_t max_bytes);

}  // namespace maillookalike::detail

// The library's one UTS #46 configuration (internal): every host it reads, in the URL parser and in the lookalike
// engine, goes through this handle, so a host one layer refuses is refused by the other too and never reaches only
// half of the checks.
#pragma once

#include <unicode/uidna.h>

namespace maillookalike::detail {

// Non-transitional ToASCII and ToUnicode with CheckBidi and CheckJoiners (UIDNA_CHECK_CONTEXTJ: WHATWG URL's
// CheckJoiners, which browsers apply), opened once; thread-safe (ICU's UIDNA is immutable). nullptr when ICU cannot
// open it.
const UIDNA* uts46();

// True when a uts46() conversion's errors are acceptable: none, or only "--" in the third and fourth positions, as by
// the reference (.NET IdnMapping, which ignores UIDNA_ERROR_HYPHEN_3_4); leading and trailing hyphens are not.
bool uts46_ok(const UIDNAInfo& info);

}  // namespace maillookalike::detail

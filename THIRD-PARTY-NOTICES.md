# Third-party notices

The code in this repository is MIT-licensed (`LICENSE`, Copyright (c) 2026 Tirion) unless this file says otherwise.

## Bundled third-party code and data

### Chromium IDN spoof checker (BSD-3-Clause)

- **What:**
  - parts of `src/lookalike.cc`: the IDN display decision (`SafeToDisplayAsUnicode`, the whole-script confusable
    table, the dangerous-pattern regex, the allowed character set) and the skeleton supplements, ported to ICU's
    public API;
  - `tests/data/chromium_idn_cases.tsv` and `tests/data/chromium_idn_test_domains.list`, the test cases and test
    top-domain list of `idn_spoof_checker_unittest.cc`.
- **Source:** Chromium 156.0.8078.88, `components/url_formatter/spoof_checks/` (`idn_spoof_checker.cc`,
  `skeleton_generator.cc`, `idn_spoof_checker_unittest.cc` and its test data).
- **Licence:** BSD-3-Clause, Copyright The Chromium Authors. Text below.

### Public Suffix List (MPL-2.0)

- **What:** `tests/data/public_suffix_list.dat`, unmodified. Test data only; the library loads the caller's list.
- **Source:** https://github.com/publicsuffix/list at commit `aa004f90b4cbe1c54ea96375622eca83d76059f0`.
- **Licence:** Mozilla Public License 2.0 (the file's own header). Text in `LICENSES/MPL-2.0.txt`.

Everything else in `tests/` and `fuzz/` is synthetic. `tests/data/brands.tsv` and `shared_mailbox.txt` are test
fixtures written for this repository; the domains in them belong to their owners and are named only to test
impersonation checks.

## Dependencies (not bundled)

Linked at build time; nothing from them is redistributed in this repository:

- [ICU](https://icu.unicode.org/) (Unicode-3.0).
- [libpsl](https://github.com/rockdaboot/libpsl) (MIT).
- Tests: [GoogleTest](https://github.com/google/googletest) (BSD-3-Clause).

## Chromium licence text

```
Copyright 2015 The Chromium Authors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

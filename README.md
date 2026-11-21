# libmaillookalike

Lookalike and link-deception checks for mail clients (C++20, Linux). No network and no I/O after construction:
inputs are bounded strings taken from a message, outputs are enumerations plus the domain or name a warning would
cite.

## Builds on

- **ICU** (78.2 in the gate): UTS #46 IDNA, UTS #39 `uspoof` skeletons and restriction levels, `Normalizer2`,
  `Transliterator`, script data.
- **libpsl** (0.21.2 in the gate) over the caller's pinned `public_suffix_list.dat`, loaded with `psl_load_fp`. No
  built-in or system list is used, so every component of a client can share one list file.
- **Chromium's IDN spoof checker** (`components/url_formatter/spoof_checks`, 156.0.8078.88, BSD-3-Clause): the
  display decision (`SafeToDisplayAsUnicode`, the whole-script confusable table, the dangerous-pattern rule, the
  skeleton supplements) is a port onto ICU's public API.

## What it adds

- `lookalike.h`: lookalike detection for sender and link hosts against the user's own domains, contacts, brands and
  a top-domain list (homoglyph, visual pair, typo, brand token, subdomain abuse, TLD swap), and display-name
  impersonation (contact, own, organisation and brand names, embedded addresses), with a popular-domain exemption.
- `links.h`: link deception from **raw link facts** (the href, the visible text samples, where the link came from):
  structural flags (userinfo, IP in any WHATWG number form, encoded or IDN host, port, slashes, many subdomains, a
  registrable domain written in the subdomain part), redirector unwrapping (Google, SafeLinks, Proofpoint v2/v3,
  Bing, generic redirect parameters; three levels), URL-shaped text that names another domain (including the
  redirect target), invisible or bidi characters in link text, shorteners, user-content hosts, OAuth consent and
  device-login endpoints. A client calls the same `assess()` with the facts it stored at sync and with the facts of
  a clicked link, so its arrival-time decision and its click-time dialog cannot disagree.
- `url.h`: the URL parsing those checks need (canonical form, host, structural facts). Not a full WHATWG parser, but
  the path follows WHATWG (dot segments resolved, `\` as `/`) and path and query are in one spelling (escapes of
  unreserved characters decoded, every other escape in upper-case hex, unsafe bytes escaped), so a browser's
  serialisation of a clicked URL and the href it came from have the same canonical form. The reference engine's
  vectors (`tests/vectors/urls.tsv`) differ from the engine there in three rows (since 0.1.3).
- `psl.h`: registrable domains, listed suffixes and "known TLD" through libpsl.

Lists (redirectors, shorteners, endpoints, hosts) are data from the caller: `LinkListsData`, or the TSV of
`parse_link_lists()` produced by `tools/lists_tsv.py`. Policy (what is trusted, what a finding means, how warnings
are worded) stays with the client.

## Security model

All string inputs are untrusted: lengths are bounded (URLs 8192 UTF-16 units, canonical form 2048 bytes, domains 64
bytes, at most 64 query parameters and three redirect levels), invalid UTF-8 is replaced, and list regexes run
with `std::regex` on bounded inputs (a regex error counts as no match). The list data and the PSL are trusted (they
ship with the client). Objects are immutable after construction and safe to share between threads.

## Tests and gate

`tools/container.sh tools/gate.sh` runs, in a pinned Ubuntu 26.04 image:

- **format**: no tabs, trailing blanks or CRs outside the data files;
- **build**: GCC 15 with warnings as errors and the GoogleTest suites:
  - `chromium_test`: all 487 cases of Chromium 156's `idn_spoof_checker_unittest.cc` (`tests/data`);
  - `lookalike_test`: the attack and control verdicts of the engine's validation run (`tests/vectors/lookalike_attacks.tsv`);
  - `psl_test`, `url_test`, `links_test`: the shared vectors in `tests/vectors/` (`psl.tsv`, `urls.tsv`, `links.tsv`),
    produced by the reference implementation these checks were ported from, plus the cases where two earlier copies
    of the rules disagreed;
- **asan**: clang 21 with AddressSanitizer and UndefinedBehaviorSanitizer;
- **fuzz**: libFuzzer on `fuzz_url_links` and `fuzz_lookalike_host`, 60 s each.

The vector files are TSV with escaped fields (`tools/vectors_tsv.py`); a consumer that keeps a second
implementation of any of these rules (for example a suffix matcher in another language) can test it against them.

## Data

`tests/data/public_suffix_list.dat` is a copy of the Public Suffix List (MPL-2.0) at
publicsuffix/list@aa004f90b4cbe1c54ea96375622eca83d76059f0. `tests/data/chromium_idn_*` come from Chromium
156.0.8078.88 (BSD-3-Clause, Copyright The Chromium Authors). `tests/data/brands.tsv` and `shared_mailbox.txt`
are test fixtures, not a shipped brand list.

## Contributing

This repository is not accepting contributions at this time: issues and pull requests are not accepted. Report
security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT (see `LICENSE`), except the data files named above and the parts of `src/lookalike.cc` ported from Chromium
(BSD-3-Clause). `THIRD-PARTY-NOTICES.md` lists them with their licence texts.

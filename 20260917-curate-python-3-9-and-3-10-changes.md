# Curate the Python 3.9 and 3.10 changes

## Overview

The registry analysis window now opens at Python 3.8. It was curated for
changes landing in 3.11 and later, and carries a handful of events between 3.8
and 3.10, so a project on 3.8 sees what breaks it on the way to 3.12 and 3.13
and almost nothing about 3.9 and 3.10. This plan closes that gap.

It is a curation plan, not an execution plan. `pyahead registry validate` can
prove a rule is well-formed; nothing in the suite can prove a rule is *true*.
Truth comes from reading CPython's record, which is why every candidate below
carries its source and why the judgement — which entries are statically
representable, and how — happens here, before any YAML is written. A wrong
rule is worse than a missing one: a false positive in a migration tool is what
makes people stop trusting it, and Gate C exists for that reason.

Work is done in batches of five rules, each batch reviewed as rules rather
than as YAML.

## Where the candidates come from

The *Deprecated* and *Removed* sections of "What's New in Python 3.9" and
"What's New in Python 3.10", read from the raw HTML rather than through a
summariser. That distinction mattered: a summarised fetch of the 3.10 page
silently dropped `formatter`, the `collections` ABC aliases and the `asyncio`
loop parameter — three of the most consequential entries.

- https://docs.python.org/3/whatsnew/3.9.html#deprecated (18 items)
- https://docs.python.org/3/whatsnew/3.9.html#removed (22 items)
- https://docs.python.org/3/whatsnew/3.10.html#deprecated (34 items)
- https://docs.python.org/3/whatsnew/3.10.html#removed (11 items)

Each candidate must be re-read at its source before its rule is written. The
tables record what the section says; the rule records what the author
verified.

## What PyAhead can represent

From `docs/registry-authoring.md`: module imports, qualified references,
qualified calls, call shapes (a positional or keyword argument on a named
callable), literal dynamic imports, and built-in patterns. PyAhead does not
infer receiver types, so **a method on an instance is not representable**
unless the receiver is a module-qualified name: `asyncio.Task.current_task` is,
`some_thread.isAlive()` is not.

## Already in the registry

Verified by subject name; a rule may also cover a candidate through an alias,
so each "not in registry" entry below must be checked against existing rule
files before being written.

`distutils` (CPY0023), `imp` (CPY0024), `lib2to3` (CPY0027), `smtpd`
(CPY0016), `asyncore` (CPY0004), `cgi` (CPY0001), `typing.io` (CPY0079),
`threading.currentThread` (CPY0125), `pathlib.Path.link_to` (CPY0071),
`ssl.wrap_socket` (CPY0026), `ssl.match_hostname` (CPY0067),
`ssl.PROTOCOL_TLS` (CPY0123), `ssl.OP_NO_TLSv1` (CPY0121), `pkgutil.ImpImporter`
(CPY0025), `shlex.split` (CPY0075).

## Candidates, ranked

### Tier 1 — removals a 3.8 codebase will hit, statically representable

| # | subject | deprecated | removed | matcher | note |
| --- | --- | --- | --- | --- | --- |
| 1 | `collections.Mapping` and the other ABC aliases: `MutableMapping`, `Sequence`, `MutableSequence`, `Iterable`, `Iterator`, `Callable`, `Set`, `MutableSet`, `Hashable`, `Sized`, `Container`, `Generator`, `Collection`, `Awaitable`, `Coroutine`, `AsyncIterable`, `AsyncIterator`, `AsyncGenerator`, `Reversible`, `ByteString`, `MappingView`, `KeysView`, `ItemsView`, `ValuesView` | 3.3 | 3.10 | qualified reference | The single most common breakage in pre-3.3-style code. **Decide: one rule with many subjects, or one per alias.** Remediation: `collections.abc`. |
| 2 | `parser` | 3.9 | 3.10 | module import | Old parser removed with the PEG switch (PEP 617). |
| 3 | `symbol` | 3.9 | 3.10 | module import | Deprecated with `parser`; **verify the 3.10 removal** — the 3.10 Removed section names `parser` explicitly and `symbol` only by association. |
| 4 | `formatter` | 3.4 | 3.10 | module import | |
| 5 | `asyncio` high-level API `loop=` parameter: `sleep`, `wait`, `wait_for`, `as_completed`, `shield`, `gather`, `open_connection`, `start_server`, `create_subprocess_exec`, `create_subprocess_shell`, `Queue`, `Lock`, `Event`, `Condition`, `Semaphore`, `BoundedSemaphore` | 3.8 | 3.10 | call shape, keyword `loop` | One rule per callable, or one rule with a callable list. **Verify the exact set against the 3.10 asyncio section**; the list above is from memory of the change, not the page. |
| 6 | `base64.encodestring`, `base64.decodestring` | 3.1 | 3.9 | qualified reference | Remediation: `encodebytes` / `decodebytes`. |
| 7 | `fractions.gcd` | 3.5 | 3.9 | qualified reference | Remediation: `math.gcd`. |
| 8 | `sys.getcheckinterval`, `sys.setcheckinterval` | 3.2 | 3.9 | qualified reference | Remediation: `getswitchinterval` / `setswitchinterval`. |
| 9 | `asyncio.Task.current_task`, `asyncio.Task.all_tasks` | 3.7 | 3.9 | qualified reference | Remediation: `asyncio.current_task` / `asyncio.all_tasks`. |
| 10 | `plistlib.readPlist`, `writePlist`, `readPlistFromBytes`, `writePlistToBytes`, `plistlib.Data` | 3.4 | 3.9 | qualified reference | Remediation: `load`/`loads`/`dump`/`dumps`. |
| 11 | `dummy_threading`, `_dummy_thread` | 3.7 | 3.9 | module import | Remediation: `threading`. |
| 12 | `aifc.openfp`, `sunau.openfp`, `wave.openfp` | 3.7 | 3.9 | qualified reference | `aifc` and `sunau` are themselves removed in 3.13 (PEP 594); check those rules before adding these. |
| 13 | `sys.callstats` | 3.7 | 3.9 | qualified reference | Undocumented; low frequency. |

### Tier 2 — deprecations in 3.9/3.10 whose removal is inside the window

These add an earlier *deprecated* event for something a project may already be
warned about, or a removal in 3.11/3.12 that a 3.8 baseline would otherwise
miss.

| # | subject | deprecated | removed | matcher | note |
| --- | --- | --- | --- | --- | --- |
| 14 | `binhex` module; `binascii.b2a_hqx`, `a2b_hqx`, `rlecode_hqx`, `rledecode_hqx` | 3.9 | 3.11 | module import / qualified reference | Not in registry at all. |
| 15 | `ast.Index`, `ast.ExtSlice`, `ast.Suite`, `ast.Param`, `ast.AugLoad`, `ast.AugStore` | 3.9 | **verify** | qualified reference | Removal version is not stated on the 3.9 page; check the `ast` docs and the 3.14 What's New. |
| 16 | `random.shuffle(random=)` | 3.9 | 3.11 | call shape, keyword `random` | |
| 17 | `sqlite3.OptimizedUnicode`, `sqlite3.enable_shared_cache` | 3.10 | 3.12 | qualified reference | |
| 18 | `importlib.find_loader`, `importlib.util.set_package_wrapper`, `set_loader_wrapper`, `module_for_loader`, `pkgutil.ImpLoader` | 3.10 | 3.12 | qualified reference | `imp` and `pkgutil.ImpImporter` already exist; check whether these are aliases of them. |
| 19 | `threading.activeCount` | 3.10 | 3.12 | qualified reference | `currentThread` exists as CPY0125; check whether it already carries this. The method forms (`notifyAll`, `isSet`, `setName`, `getName`, `isDaemon`, `setDaemon`) are on instances and are **not representable**. |
| 20 | `typing.re` | 3.8 | 3.13 | qualified reference | Check whether CPY0079 (`typing.io`) already covers it. |
| 21 | `json.loads(encoding=)` | 3.1 | 3.9 | call shape, keyword `encoding` | Ignored since 3.1; low frequency. |
| 22 | `bz2.BZ2File(buffering=)` | 3.0 | 3.9 | call shape, keyword `buffering` | Low frequency. |
| 23 | `cgi.log` | 3.10 | 3.12 | qualified reference | Subsumed by the `cgi` removal in 3.13 (CPY0001); probably not worth a rule. |

### Out of scope — not statically representable

Recorded so nobody re-derives them. Each is a method on an instance PyAhead
cannot type, a runtime value, or syntax.

`array.array.tostring`/`fromstring`; `threading.Thread.isAlive`;
`xml.etree.ElementTree.Element.getchildren`/`getiterator`;
`html.parser.HTMLParser.unescape`; `typing.NamedTuple._field_types`;
`symtable.SymbolTable.has_exec`; `nntplib.NNTP.xpath`/`xgtitle`;
`zipimport.zipimporter.load_module`; the `importlib.abc` finder and loader
methods; `math.factorial` with a float; `random.randrange` with a non-integer;
`random` non-hashable seeds; `NotImplemented` in a boolean context;
`asyncio.wait` given coroutines; `gzip.GzipFile` without a mode; numeric
literals followed by keywords; the `complex` dunder removals; every C API item.

## Decisions before the first batch

1. **One rule per alias, or one rule with many subjects**, for the
   `collections` ABCs (#1) and the `asyncio` loop parameter (#5). The
   registry's existing convention decides this; check `CPY0121`–`CPY0124`,
   which cover several `ssl` constants.
2. **Whether Gate C's precision evidence is restated or re-run.** It was
   measured at baseline 3.11. Adding rules whose events fall in 3.9 and 3.10
   changes the finding population for a 3.8 baseline. Either re-run the corpus
   at 3.8 or restate the evidence's scope explicitly.
3. **Whether #5 is worth its complexity.** The `loop` parameter is the highest
   value item for real asyncio code and the hardest to represent well. Decide
   before batch 2, not during it.

## Development Approach

- Five rules per batch. Each batch: rule YAML with source key and timeline,
  positive and negative fixtures per `docs/registry-authoring.md`, coverage
  manifest entries, then `pyahead registry validate`, `pyahead registry
  coverage`, and the full gate.
- Every rule cites the What's New anchor it was read from. If the page and
  the module documentation disagree, stop and record the disagreement rather
  than picking one.
- No rule for anything in the out-of-scope list, however tempting the
  heuristic.
- The registry label bumps once at the end, not per batch.

## Implementation Steps

### Task 0: Decisions — made 17 September 2026

- [x] #1 — **one rule per removed object; one rule per removed change.** The
      deciding fact: a finding's headline is its rule's *subject*, and
      `CPY0093` already reports `utcnow` for a line using `utcfromtimestamp`.
      So the 25 `collections` aliases are 25 rules, while the `asyncio` loop
      parameter is one rule with a module subject and 18 matchers, because
      "asyncio" is true of every match. (`CPY0093`'s headline is a wart worth
      fixing separately.)
- [x] #2 — **restate now, re-run once.** Dated scope notes added to
      `docs/evidence/gate-c.md` and `docs/evidence/pypi-top-1000.md`; the
      top-1000 protocol runs again after Task 3, when there is a full set to
      measure.
- [x] #3 — **in.** The call-shape matcher expresses `required_keywords: [loop]`
      directly and treats `**kwargs` as unknown. The 18 signatures were read
      from the 3.10 documentation's "Removed the loop parameter" notes, which
      also settled that `Future` and `Task` kept it.

**Batching changed while doing Task 1.** A rule cannot be loaded without a
coverage manifest claiming it, and a manifest must disposition every entry on
its page — so batches follow source pages, not tiers. `symbol` therefore moves
to the 3.9 Deprecated page, where its census entry lives.

### Task 1: the "What's New in 3.10 — Removed" page — done

- [x] `parser` (#2) — CPY0138
- [x] `formatter` (#4) — CPY0139, deprecation verified at the 3.4 page
- [x] the `asyncio` loop parameter (#5) — CPY0140, 18 matchers
- [x] the 25 `collections` ABC aliases (#1) — CPY0141–CPY0165
- [x] census `python-3.10-removed`: 9 keys, every bullet dispositioned
- [x] fixtures generated under intent assertions; one caught a real problem —
      `collections.abc.ByteString`, the supposed replacement for #1's last
      alias, is itself deprecated in 3.12 (CPY0044); CPY0165's remediation
      says so
- [x] gate: 2059 tests, 161 rules, 14 manifests, 0 unclassified

`symbol` (#3) verified removed in 3.10 — its documentation page exists at
3.9 and returns 404 at 3.10 — but its census entry is on the 3.9 Deprecated
page, so it is written with Task 3.

### Task 2: the "What's New in 3.9 — Removed" page — done

- [x] `base64.encodestring`/`decodestring` (#6) — CPY0178, CPY0179
- [x] `fractions.gcd` (#7) — CPY0180
- [x] `sys.getcheckinterval`/`setcheckinterval` (#8) — CPY0167, CPY0168
- [x] `asyncio.Task.current_task`/`all_tasks` (#9) — CPY0183, CPY0184
- [x] `plistlib` old API (#10) — CPY0172–CPY0176, plus CPY0177 for the
      `use_builtin_types` keyword, which the 3.8 docs show was keyword-only on
      exactly `load` and `loads`
- [x] `dummy_threading`/`_dummy_thread` (#11) — CPY0169, CPY0170; moved here
      from Task 3 because their census entry is on this page
- [x] `wave.openfp` (#12) — CPY0171. **`aifc.openfp` and `sunau.openfp` have
      no rule**: any use of them already reports the module removals at 3.13
      (CPY0002, CPY0019), and a rule's fixture may hold only its own findings.
      The entry is `partial` and states the cost — a horizon below 3.13 does
      not hear the aliases went in 3.9.
- [x] `sys.callstats` (#13) — CPY0166
- [x] `json.loads(encoding=)` (#21) — CPY0182; `bz2.BZ2File(buffering=)`
      (#22) — CPY0181, `partial`: keyword form only, positional not claimed
- [x] census `python-3.9-removed`: 22 keys; 7 instance-method entries
      recorded as not statically detectable, 2 C API, 2 not applicable
- [x] gate: 2078 tests, 180 rules, 15 manifests, 0 unclassified

### Task 3: the two Deprecated pages, 3.9 and 3.10 — done

- [x] `symbol` (#3) — CPY0185. Its 3.9 documentation has no deprecation note,
      so the removal was verified against interpreters (importable at 3.9,
      `ModuleNotFoundError` at 3.10) and cited to the 3.10 changelog entry
- [x] `binhex` and the four `binascii` hqx functions (#14) — CPY0186–CPY0190.
      The 3.11 Removed page spells one "rldecode_hqx"; the rule does not
- [x] `ast.Index`, `ExtSlice` (#15) — CPY0191, CPY0192, deprecated only: both
      still importable at 3.14.6, removal unscheduled. `Suite`, `Param`,
      `AugLoad`, `AugStore` are `not-applicable` on the page's own word that
      Python 3 never generated or accepted them
- [x] `random.shuffle(random=)` (#16) — CPY0193, keyword and positional forms;
      the 3.11 Removed page does not mention it, the `random` module page does
- [x] `sqlite3` (#17), `importlib` (#18), `threading` (#19), `typing.re`
      (#20) — all already carried by CPY0070, CPY0024/0025/0074/0084, CPY0125,
      CPY0079; recorded as `duplicate` of those rules
- [x] census both pages: 19 and 36 keys, 0 unclassified
- [x] gate: 2087 tests, 189 rules, 17 manifests

### Task 4: leftovers — nothing left

Every candidate in the tables above is now either a rule, a recorded
duplicate of an existing rule, or dispositioned as out of scope with the
reason. #21–#23 were absorbed by Task 2 and Task 3.

### Task 5: Close — in progress

- [x] registry label: already `2026.09.17`, set when the window opened; the
      three batches share it
- [x] `docs/usage.md` states coverage by censused page and names the 3.11
      "What's New" sections as the gap
- [x] the validation harness scans each package at the registry's own floor.
      It hardcoded 3.11, which would have scanned every package there and
      exercised none of the new rules; it now reads the window from the
      registry. Python 3.8 installed for the (3.8, 3.9) adjudication pairs
- [x] the precision sweep ran twice. The first pass scanned 494 of 999:
      at a 3.8–3.10 reference, 467 packages could not install their
      dependency tree from a one-artifact wheelhouse acquired under 3.11. The
      runner now falls back upward to the lowest floor a package installs at
      and records every rejected candidate; the second pass scanned 796
- [x] aggregated and triaged: 1439 findings, 98.49% agreement, 82.6%
      adjudicated, 18 refuted. **Eleven refutations were CPY0169 and CPY0170**
      — every adjudicable finding those two rules produced — all `except
      ImportError` fallbacks that never run on Python 3. Both retired, IDs
      reserved, census entry says why. The other seven are the September
      record's open rows, unchanged
- [x] evidence record: `docs/evidence/pypi-top-1000-2026-09-17.md`, prepared
      and awaiting the owner's approval
- [ ] release — a minor bump, since inferred policy changed; then re-pin the
      site and add 3.8, 3.9 and 3.10 to its baseline menu

## Post-Completion (operator, not automatable)

1. **Decide the version.** Opening the window already changes inferred policy
   for projects declaring `requires-python` below 3.11; these rules change
   their findings further. That is a minor bump under semantic versioning, not
   a patch.
2. **Approve or reject the evidence record.** The sweep measured the new
   rules; the record recommends release and an agent cannot approve it.
3. **Decide on import-fallback reachability.** Fifteen of the sweep's
   eighteen refutations are an import inside `except ImportError:` after a
   primary import that always succeeds on 3.x. The September record called
   extending the reachability grammar to this a roadmap decision; two sweeps
   have now made the same case. It is the single largest remaining source of
   false positives.
4. **Census the 3.11 "What's New" sections.** The one release between 3.8
   and 3.14 whose pages have no manifest; `docs/usage.md` names it as the gap.
5. **Consider a multi-interpreter wheelhouse.** 120 of 250 not-adjudicable
   findings are CPython-tagged wheels that cannot be installed under the
   older interpreter a probe needs.

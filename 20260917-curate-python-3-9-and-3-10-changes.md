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

### Task 0: Decisions

- [ ] decide #1 — rule granularity for many-subject entries
- [ ] decide #2 — Gate C evidence: re-run at 3.8 or restate scope
- [ ] decide #3 — whether the `asyncio` loop parameter is in or out

### Task 1: Batch 1 — the 3.10 module removals and the ABC aliases

- [ ] `parser` (#2) and `symbol` (#3), the latter only after verifying its 3.10
      removal at source
- [ ] `formatter` (#4)
- [ ] the `collections` ABC aliases (#1), in the granularity decided in Task 0
- [ ] fixtures, coverage, gate

### Task 2: Batch 2 — the 3.9 function removals

- [ ] `base64.encodestring`/`decodestring` (#6)
- [ ] `fractions.gcd` (#7)
- [ ] `sys.getcheckinterval`/`setcheckinterval` (#8)
- [ ] `asyncio.Task.current_task`/`all_tasks` (#9)
- [ ] `plistlib` old API (#10)
- [ ] fixtures, coverage, gate

### Task 3: Batch 3 — modules and the rest of Tier 1

- [ ] `dummy_threading`/`_dummy_thread` (#11)
- [ ] `aifc`/`sunau`/`wave.openfp` (#12), after checking the PEP 594 rules
- [ ] `sys.callstats` (#13)
- [ ] `binhex` and the `binascii` hqx functions (#14)
- [ ] the `asyncio` loop parameter (#5), if Task 0 said yes
- [ ] fixtures, coverage, gate

### Task 4: Batch 4 — Tier 2 with existing-rule checks

- [ ] #15 through #20, each first checked against the existing rule it may
      already belong to; skip #21–#23 unless a reason appears
- [ ] fixtures, coverage, gate

### Task 5: Close

- [ ] bump the registry label
- [ ] act on decision #2: re-run or restate Gate C
- [ ] update the coverage sentence in `docs/usage.md`, which currently says
      3.8–3.10 is sparse
- [ ] release; then re-pin the site and add 3.8, 3.9 and 3.10 to its baseline
      menu, which cannot happen before the release because the site installs
      the published package

## Post-Completion (operator, not automatable)

1. **Decide the version.** Opening the window already changes inferred policy
   for projects declaring `requires-python` below 3.11; these rules change
   their findings further. That is a minor bump under semantic versioning, not
   a patch.
2. **Watch the false-positive rate** on the first real 3.8 projects scanned.
   Nothing in this plan measures precision on the new rules; the corpus does.

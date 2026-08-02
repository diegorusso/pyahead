# Registry authoring

PyAhead registry files are reviewed data, not executable plugins. They are
loaded with PyYAML's safe loader, checked against a closed schema, and converted
to immutable domain models. Duplicate mapping keys, unknown fields, arbitrary
Python callable paths, unresolved sources, and inconsistent timelines fail
validation.

The generated structural schemas are
[`schema/registry-index-v1.json`](schema/registry-index-v1.json) and
[`schema/registry-rule-v1.json`](schema/registry-rule-v1.json). Runtime
validation also enforces cross-file and ordered-timeline invariants that JSON
Schema cannot express concisely. Regenerate the checked-in schemas after an
intentional schema change:

```console
uv run python -c "from pathlib import Path; from pyahead.registry.schema import write_json_schemas; write_json_schemas(Path('docs/schema'))"
```

Then validate the complete bundled snapshot:

```console
uv run pyahead registry validate
uv run pyahead registry list
uv run pyahead explain CPY0001
```

An alternate registry directory or `index.yaml` can be supplied as the
positional `PATH` to `registry validate` and `registry list`, or with
`--registry PATH`. `explain` accepts `--registry PATH`.

Each manifest and rule file is limited to 2 MiB. Explicit registries must use
regular UTF-8 files beneath their registry root; symlinks, aliases, recursive
YAML, excessive YAML depth or node counts, and files replaced during opening
are rejected before the data is trusted.

## Index and stable IDs

`index.yaml` contains a release label, an optional release-metadata path, the
ordered rule paths, and IDs reserved after retirement:

```yaml
schema_version: 1
release: "2026.07.31"
releases: releases.yaml
retired_ids: [CPY0099]
rules:
  - cpython/CPY0001.yaml
```

CPython rule IDs are `CPY` followed by four digits. A canonical ID must be
globally unique, must equal its YAML filename stem, and must never be reassigned
to another concern. Paths and IDs cannot be repeated. A removed ID belongs in
`retired_ids`; validation rejects its reuse. A migrated rule may declare unique
`aliases`, but output always uses the canonical ID.

Rule paths use canonical relative POSIX spelling: ASCII identifier-like path
segments separated by one `/`, ending in `.yaml` or `.yml`. Absolute paths,
dot segments, repeated separators, backslashes, whitespace, and control
characters are invalid rather than normalized.

When present, `releases` names a strict YAML document that contributes to the
registry revision alongside the index and rules:

```yaml
schema_version: 1
releases:
  - python: "3.14"
    status: stable
    released_on: "2025-10-07"
  - python: "3.15"
    status: prerelease
    expected_final_on: "2026-10-01"
    source: "https://peps.python.org/pep-0790/"
```

Release records are strictly ordered and unique by Python minor. Allowed
statuses are `eol`, `security`, `stable`, `prerelease`, and `planned`; dates use
canonical `YYYY-MM-DD` form, and an optional source is a direct HTTPS URL.
These facts are informative presentation data and never alter detection
semantics.

## Sources and timelines

Every rule has at least one direct HTTPS source. Source IDs are unique within a
rule, and every timeline event refers to one of them. Timeline entries must be
strictly ordered by increasing Python minor version and cannot repeat an event
kind. `removed` and `support_dropped` are terminal events and therefore must be
last.

Supported events are `deprecated`, `removed`, `signature_changed`,
`behavior_changed`, `syntax_changed`, and `support_dropped`. Each authored event
requires its matching impact field:

| Event | Impact field |
| --- | --- |
| `deprecated` | `on_deprecation` |
| `removed` | `on_removal` |
| `signature_changed` | `on_signature_change` |
| `behavior_changed` | `on_behavior_change` |
| `syntax_changed` | `on_syntax_change` |
| `support_dropped` | `on_support_drop` |

Use only `released`, `scheduled`, or `provisional` certainty. A future schedule
must cite an authoritative source that names the version. Do not invent a
removal event when removal is unscheduled.

## Declarative matchers

All dotted names use ordinary Python identifiers. Name-based matchers rely on
LibCST import-derived qualified names, understand aliases, reject lexical
shadowing, and report multiple possible imported names at medium confidence.
An absolute import that can resolve to a project module is not presented as an
exact standard-library match.

### Module import

Matches direct, aliased, and from-module imports, including submodules:

```yaml
- kind: module-import
  module: cgi
```

### Qualified reference

Matches an exact imported symbol used as a read. Optional contexts restrict it
to `read`, `decorator`, `base-class`, or `annotation`:

```yaml
- kind: qualified-reference
  qualified_name: typing.no_type_check
  contexts: [decorator]
```

### Qualified call

Matches only when the exact imported callable is the function of a call:

```yaml
- kind: qualified-call
  qualified_name: locale.getdefaultlocale
```

### Call shape

A call shape adds conservative predicates. Positional bounds count only
ordinary positional arguments. Required and forbidden keywords use explicit
keyword arguments. A starred expansion prevents a match whenever it makes a
predicate unknowable.

```yaml
- kind: call-shape
  qualified_name: example.open_resource
  min_positional_args: 1
  max_positional_args: 2
  required_keywords: [mode]
  forbidden_keywords: [legacy]
  literal_arguments:
    - position: 0
      equals: "settings.toml"
    - keyword: mode
      equals: "text"
```

Each literal predicate selects exactly one zero-based `position` or one
`keyword`. Supported literal values are strings, finite numbers, booleans, and
null. `forbidden_keywords` also expresses an omitted-argument requirement. An
array predicate must be non-empty when present, and equivalent matchers cannot
be repeated within a rule. Matcher identity treats booleans, integers, and
floating-point values as distinct and normalizes set-like keyword/context
arrays before checking semantic duplicates; this invariant is enforced by the
runtime validator because JSON Schema equality cannot express it faithfully.

### Literal dynamic import

Matches only exact direct or imported aliases of `importlib.import_module()` or
the built-in `__import__()` when the module name is an absolute source literal.
For `__import__()`, `level` must be absent or statically zero; starred argument
expansions are rejected. Ambiguous imported targets reduce resolution
confidence, and lexical shadowing suppresses a match. A competing project
module produces candidate-path inference instead of a rule match. Schema
version 1 fixes this matcher at medium confidence and rejects an authored high
or low value, keeping it below M2's fixed high-confidence report and gate
boundary:

```yaml
- kind: literal-dynamic-import
  module: cgi
  confidence: medium
```

### Built-in pattern

Some syntax shapes need a dedicated implementation. Registry data selects only
a reviewed identifier from a fixed dispatch table:

```yaml
- kind: builtin-pattern
  pattern: bool-bitwise-inversion
```

Schema version 1 permits only `bool-bitwise-inversion`. A `callable`, module
path, entry point, or unknown pattern is rejected; registry YAML can never
cause an arbitrary import or function call.

## Remediation and automation metadata

Remediation is guidance. It may expose a verified Ruff or pyupgrade transform,
but PyAhead only displays this metadata and never invokes either tool:

```yaml
remediation:
  summary: "Apply the supported replacement."
  documentation_url: "https://docs.python.org/3/whatsnew/"
  automation:
    tool: ruff
    rule: UP999
```

Use `tool: pyupgrade` for a verified pyupgrade transform. Do not add automation
metadata until the named behavior has been checked against the tool.

## Fixture convention

Every implemented rule lives under `tests/fixtures/rules/<RULE_ID>/` and has an
`expected.json` manifest. Its cases name repository-relative input paths,
policy, expected findings, confidence, resolution evidence, and expected
inference codes. At least one positive and one negative case are mandatory.

Each matcher implementation also has executable fixtures covering:

- a direct positive use;
- an alias;
- lexical shadowing;
- an ambiguous imported name or project-module origin;
- a syntactically similar negative use.

For syntax-only built-in patterns, alias, shadowing, and ambiguity fixtures are
look-alike expressions proving that only the whitelisted literal syntax is
accepted; there is no import-derived name to resolve.

Keep fixture source minimal and name cases by behavior, not by an internal
visitor method. A rule cannot be considered implemented when its negative or
resolution fixtures are absent.

"""Inline and per-file M4 suppression handling."""

import io
import re
import tokenize
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass, field, replace
from heapq import heappop, heappush
from pathlib import PurePosixPath

import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider
from pathspec import PathSpec
from pathspec.pattern import Pattern

from pyahead.model import (
    ConfigurationError,
    Diagnostic,
    DiagnosticCategory,
    Finding,
    PerFileIgnore,
    Registry,
    SourceLocation,
    SourcePosition,
    SourceRegion,
    Suppression,
    SuppressionKind,
)

_DIRECTIVE_RE = re.compile(
    r"^#\s*pyahead:\s*ignore\[(?P<ids>[^\]]*)\]"
    r"(?:\s*--\s*(?P<reason>.*?))?\s*$"
)
_DIRECTIVE_PREFIX_RE = re.compile(r"^#\s*pyahead:")


@dataclass(frozen=True)
class InlineSuppression:
    """One validated rule-specific source comment."""

    rule_id: str
    line: int
    reason: str | None
    statement_region: SourceRegion | None = None


@dataclass(frozen=True)
class ResolvedPerFileIgnore:
    """A compiled configured pattern with known canonical rule IDs."""

    pattern: str
    rule_ids: tuple[str, ...]
    path_spec: PathSpec[Pattern]


@dataclass(frozen=True)
class _RuleInlineSuppressionIndex:
    """Search keys for directives naming one canonical rule."""

    statement_starts: tuple[SourcePosition, ...]
    statement_directives: tuple[InlineSuppression, ...]


@dataclass(frozen=True)
class InlineSuppressionIndex:
    """Rule-specific logarithmic lookup for one source file's directives."""

    by_rule_id: dict[str, _RuleInlineSuppressionIndex]

    def matching_directive(self, finding: Finding) -> InlineSuppression | None:
        """Find the first directive touching the finding's logical statement."""
        rule_index = self.by_rule_id.get(finding.rule_id)
        if rule_index is None:
            return None

        finding_region = finding.location.region
        # Bound logical-statement regions do not nest. The rightmost statement
        # start at or before the finding is therefore the only possible owner.
        statement_index = (
            bisect_right(rule_index.statement_starts, finding_region.start) - 1
        )
        if statement_index < 0:
            return None
        directive = rule_index.statement_directives[statement_index]
        statement_region = directive.statement_region
        if (
            statement_region is not None
            and statement_region.start <= finding_region.start
            and finding_region.end <= statement_region.end
        ):
            return directive
        return None


@dataclass(frozen=True)
class PerFileSuppressionIndex:
    """Rule-specific configured ignores cached once per path and rule."""

    by_rule_id: dict[str, tuple[ResolvedPerFileIgnore, ...]]
    _matches: dict[tuple[str, str], ResolvedPerFileIgnore | None] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )

    def matching_ignore(self, finding: Finding) -> ResolvedPerFileIgnore | None:
        """Return the first configured pattern matching this path and rule."""
        rendered_path = finding.location.path.as_posix()
        key = (rendered_path, finding.rule_id)
        if key not in self._matches:
            self._matches[key] = next(
                (
                    ignore
                    for ignore in self.by_rule_id.get(finding.rule_id, ())
                    if ignore.path_spec.match_file(rendered_path)
                ),
                None,
            )
        return self._matches[key]


def _canonical_rule_ids(registry: Registry) -> dict[str, str]:
    return {
        identifier: rule.id
        for rule in registry.rules
        for identifier in (rule.id, *rule.aliases)
    }


def _location(
    path: PurePosixPath,
    start: tuple[int, int],
    end: tuple[int, int],
) -> SourceLocation:
    return SourceLocation(
        path=path,
        region=SourceRegion(
            start=SourcePosition(line=start[0], column=start[1] + 1),
            end=SourcePosition(line=end[0], column=end[1] + 1),
        ),
    )


def collect_inline_suppressions(
    source: str,
    path: PurePosixPath,
    registry: Registry,
) -> tuple[tuple[InlineSuppression, ...], tuple[Diagnostic, ...]]:
    """Parse comments without mistaking string contents for directives."""
    directives: list[InlineSuppression] = []
    diagnostics: list[Diagnostic] = []
    canonical_rule_ids: dict[str, str] | None = None
    comments: list[tokenize.TokenInfo] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        comments.extend(token for token in tokens if token.type == tokenize.COMMENT)
    except (IndentationError, tokenize.TokenError):
        # Preserve directives tokenized before later malformed source. They must
        # remain diagnostic alongside the incomplete-analysis parse result.
        pass
    for comment in comments:
        if _DIRECTIVE_PREFIX_RE.match(comment.string) is None:
            continue
        location = _location(path, comment.start, comment.end)
        match = _DIRECTIVE_RE.fullmatch(comment.string)
        if match is None:
            diagnostics.append(
                Diagnostic(
                    code="PYA3002",
                    category=DiagnosticCategory.SUPPRESSION,
                    message=(
                        "invalid suppression; use "
                        "# pyahead: ignore[RULE_ID] -- optional reason"
                    ),
                    location=location,
                )
            )
            continue
        identifiers = tuple(
            dict.fromkeys(
                item.strip() for item in match.group("ids").split(",") if item.strip()
            )
        )
        if not identifiers:
            diagnostics.append(
                Diagnostic(
                    code="PYA3002",
                    category=DiagnosticCategory.SUPPRESSION,
                    message="suppression must name at least one rule ID",
                    location=location,
                )
            )
            continue
        reason_text = match.group("reason")
        reason = reason_text.strip() if reason_text and reason_text.strip() else None
        if canonical_rule_ids is None:
            canonical_rule_ids = _canonical_rule_ids(registry)
        for identifier in identifiers:
            rule_id = canonical_rule_ids.get(identifier)
            if rule_id is None:
                diagnostics.append(
                    Diagnostic(
                        code="PYA3001",
                        category=DiagnosticCategory.SUPPRESSION,
                        message=f"unknown suppression rule ID {identifier!r}",
                        location=location,
                    )
                )
                continue
            directives.append(
                InlineSuppression(
                    rule_id=rule_id,
                    line=comment.start[0],
                    reason=reason,
                )
            )
    return tuple(directives), tuple(diagnostics)


def resolve_per_file_ignores(
    ignores: tuple[PerFileIgnore, ...],
    registry: Registry,
) -> tuple[PerFileSuppressionIndex, tuple[Diagnostic, ...]]:
    """Compile patterns and diagnose every unknown configured rule ID."""
    resolved: list[ResolvedPerFileIgnore] = []
    diagnostics: list[Diagnostic] = []
    canonical_rule_ids = _canonical_rule_ids(registry)
    for ignore in ignores:
        try:
            path_spec = PathSpec.from_lines("gitignore", [ignore.pattern])
        except (TypeError, ValueError) as error:
            message = f"invalid per-file ignore pattern {ignore.pattern!r}"
            raise ConfigurationError(message) from error
        canonical: list[str] = []
        for identifier in ignore.rule_ids:
            rule_id = canonical_rule_ids.get(identifier)
            if rule_id is None:
                diagnostics.append(
                    Diagnostic(
                        code="PYA3001",
                        category=DiagnosticCategory.SUPPRESSION,
                        message=(
                            f"unknown suppression rule ID {identifier!r} "
                            f"for pattern {ignore.pattern!r}"
                        ),
                    )
                )
            elif rule_id not in canonical:
                canonical.append(rule_id)
        resolved.append(
            ResolvedPerFileIgnore(
                pattern=ignore.pattern,
                rule_ids=tuple(canonical),
                path_spec=path_spec,
            )
        )
    by_rule_id: defaultdict[str, list[ResolvedPerFileIgnore]] = defaultdict(list)
    for resolved_ignore in resolved:
        for rule_id in resolved_ignore.rule_ids:
            by_rule_id[rule_id].append(resolved_ignore)
    return (
        PerFileSuppressionIndex(
            by_rule_id={
                rule_id: tuple(rule_ignores)
                for rule_id, rule_ignores in sorted(by_rule_id.items())
            }
        ),
        tuple(diagnostics),
    )


def bind_inline_suppressions(
    directives: tuple[InlineSuppression, ...],
    wrapper: MetadataWrapper,
) -> tuple[InlineSuppression, ...]:
    """Associate comments with statements in near-linear sweep order."""
    if not directives:
        return ()
    positions = wrapper.resolve(PositionProvider)
    statement_regions = {
        SourceRegion(
            start=SourcePosition(
                line=code_range.start.line,
                column=code_range.start.column + 1,
            ),
            end=SourcePosition(
                line=code_range.end.line,
                column=code_range.end.column + 1,
            ),
        )
        for node, code_range in positions.items()
        if isinstance(
            node,
            (cst.Decorator, cst.SimpleStatementLine, cst.SimpleStatementSuite),
        )
    }
    compound_header_nodes = (
        cst.BaseCompoundStatement,
        cst.ExceptHandler,
        cst.MatchCase,
    )
    for node, code_range in positions.items():
        if not isinstance(node, compound_header_nodes):
            continue
        body = node.body
        if not isinstance(body, cst.IndentedBlock):
            continue
        header_range = positions[body.header]
        start_range = (
            positions[node.name]
            if isinstance(node, (cst.ClassDef, cst.FunctionDef))
            else code_range
        )
        statement_regions.add(
            SourceRegion(
                start=SourcePosition(
                    line=start_range.start.line,
                    column=code_range.start.column + 1,
                ),
                end=SourcePosition(
                    line=header_range.start.line,
                    column=header_range.start.column + 1,
                ),
            )
        )
    sorted_statement_regions = sorted(
        statement_regions,
        key=lambda region: (region.start, region.end),
    )
    active: list[tuple[int, SourcePosition, SourcePosition, SourceRegion]] = []
    next_region = 0
    bound = list(directives)
    for directive_index, directive in sorted(
        enumerate(directives),
        key=lambda item: (item[1].line, item[0]),
    ):
        while (
            next_region < len(sorted_statement_regions)
            and sorted_statement_regions[next_region].start.line <= directive.line
        ):
            region = sorted_statement_regions[next_region]
            heappush(
                active,
                (
                    region.end.line - region.start.line,
                    region.start,
                    region.end,
                    region,
                ),
            )
            next_region += 1
        while active and active[0][3].end.line < directive.line:
            heappop(active)
        statement_region = active[0][3] if active else None
        bound[directive_index] = replace(
            directive,
            statement_region=statement_region,
        )
    return tuple(bound)


def index_inline_suppressions(
    directives: tuple[InlineSuppression, ...],
) -> InlineSuppressionIndex:
    """Build immutable search keys without scanning directives per finding."""
    grouped: defaultdict[str, list[InlineSuppression]] = defaultdict(list)
    for directive in directives:
        grouped[directive.rule_id].append(directive)

    by_rule_id: dict[str, _RuleInlineSuppressionIndex] = {}
    for rule_id, rule_directives in sorted(grouped.items()):
        by_statement: dict[SourceRegion, InlineSuppression] = {}
        for directive in rule_directives:
            if directive.statement_region is not None:
                by_statement.setdefault(directive.statement_region, directive)
        statement_regions = tuple(sorted(by_statement))
        by_rule_id[rule_id] = _RuleInlineSuppressionIndex(
            statement_starts=tuple(region.start for region in statement_regions),
            statement_directives=tuple(
                by_statement[region] for region in statement_regions
            ),
        )
    return InlineSuppressionIndex(by_rule_id=by_rule_id)


def suppression_for_finding(
    finding: Finding,
    inline: InlineSuppressionIndex | None,
    per_file: PerFileSuppressionIndex,
) -> Suppression | None:
    """Return the first specific suppression applicable to a finding."""
    directive = inline.matching_directive(finding) if inline is not None else None
    if directive is not None:
        return Suppression(
            kind=SuppressionKind.INLINE,
            reason=directive.reason,
        )
    ignore = per_file.matching_ignore(finding)
    if ignore is not None:
        return Suppression(
            kind=SuppressionKind.PER_FILE,
            pattern=ignore.pattern,
        )
    return None


__all__ = [
    "InlineSuppression",
    "InlineSuppressionIndex",
    "PerFileSuppressionIndex",
    "ResolvedPerFileIgnore",
    "bind_inline_suppressions",
    "collect_inline_suppressions",
    "index_inline_suppressions",
    "resolve_per_file_ignores",
    "suppression_for_finding",
]

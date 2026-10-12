"""Opt-in dependency metadata and isolated resolver evidence.

The implementation lives in private submodules: _config (configuration and
targets), _archives and _metadata (direct inspection), _assessment,
_resolution (resolver-result validation), _uv and _process (running uv),
and _report (collection, documents and rendering).
"""

from pyahead.dependencies._assessment import (
    assess_dependency_metadata,
)
from pyahead.dependencies._config import (
    load_dependency_configuration,
)
from pyahead.dependencies._metadata import (
    inspect_dependency_metadata,
)
from pyahead.dependencies._model import (
    ArtifactAvailability,
    DependencyAssessment,
    DependencyCompatibilityStatus,
    DependencyConfiguration,
    DependencyProjectKind,
    EnvironmentTarget,
    EvaluatedRequirement,
    MetadataArtifact,
    MetadataIssue,
    MetadataKind,
    RequiresPythonStatus,
    ResolutionStatus,
    ResolvedPackage,
    ResolverResult,
    TransitiveRequirementEvidence,
)
from pyahead.dependencies._process import (
    ProcessRunner,
)
from pyahead.dependencies._report import (
    DependencyReport,
    ResolverAdapter,
    TargetDependencyResult,
    collect_dependency_report,
    dependency_report_document,
    render_dependency_json,
    render_dependency_text,
)
from pyahead.dependencies._uv import (
    UvResolverAdapter,
)

__all__ = [
    "ArtifactAvailability",
    "DependencyAssessment",
    "DependencyCompatibilityStatus",
    "DependencyConfiguration",
    "DependencyProjectKind",
    "DependencyReport",
    "EnvironmentTarget",
    "EvaluatedRequirement",
    "MetadataArtifact",
    "MetadataIssue",
    "MetadataKind",
    "ProcessRunner",
    "RequiresPythonStatus",
    "ResolutionStatus",
    "ResolvedPackage",
    "ResolverAdapter",
    "ResolverResult",
    "TargetDependencyResult",
    "TransitiveRequirementEvidence",
    "UvResolverAdapter",
    "assess_dependency_metadata",
    "collect_dependency_report",
    "dependency_report_document",
    "inspect_dependency_metadata",
    "load_dependency_configuration",
    "render_dependency_json",
    "render_dependency_text",
]

# The public names keep the module they had before the package was split, so
# reprs and pickles read as they did. Static type checkers still name the
# private module that defines each one.
for _name in __all__:
    globals()[_name].__module__ = __name__
del _name

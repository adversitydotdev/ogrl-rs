"""High-performance Rust kernel, linter, evaluator, and OSCAL bridge for OGRL.

Coarse-grained Python API backed by `ogrl-core` and `ogrl-oscal` via PyO3.
All heavy operations release the GIL and run in parallel Rust (`rayon`).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ogrl_rs import _ogrl_rs

__version__ = _ogrl_rs.__version__

__all__ = [
    "__version__",
    "OgrlGraph",
    "RenderedFile",
    "canonical_json",
    "check_graph",
    "check_object",
    "compare_library_revisions",
    "evaluate_program",
    "format_yaml",
    "import_oscal_catalog",
    "import_oscal_component",
    "lint_path",
    "parse_yaml",
    "projection_digest",
    "read_directory",
    "read_exchange",
    "render_oscal",
    "render_ssp",
    "summarize_program",
]


@dataclass(frozen=True, slots=True)
class RenderedFile:
    name: str
    media_type: str
    content: bytes


def _as_json_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8")
    return json.dumps(value, ensure_ascii=False)


def _as_timestamp(at: str | datetime) -> str:
    if isinstance(at, datetime):
        return at.isoformat()
    return at


def _as_list(items: Iterable[str] | None) -> list[str]:
    return list(items) if items is not None else []


class OgrlGraph:
    """Reusable indexed OGRL graph held in Rust memory.

    Construct once via `OgrlGraph.from_objects(...)` or `OgrlGraph.from_path(...)`
    to run repeated validation, evaluation, diff, and rendering calls without re-parsing.
    """

    def __init__(self, native: _ogrl_rs.OgrlGraph) -> None:
        self._native = native

    @classmethod
    def from_objects(
        cls,
        objects: Sequence[dict[str, Any]] | str | bytes,
        *,
        library_ids: Iterable[str] | None = None,
        provider_ids: Iterable[str] | None = None,
    ) -> OgrlGraph:
        native = _ogrl_rs.OgrlGraph.from_json(
            _as_json_str(objects),
            _as_list(library_ids),
            _as_list(provider_ids),
        )
        return cls(native)

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        library: str | Path | None = None,
        strict: bool = True,
        profile: str = "auto",
    ) -> OgrlGraph:
        native = _ogrl_rs.OgrlGraph.from_path(
            str(path),
            str(library) if library is not None else None,
            strict,
            profile,
        )
        return cls(native)

    def __len__(self) -> int:
        return len(self._native)

    def digest(self) -> str:
        """SHA-256 projection digest (`sha-256:<hex>`)."""
        return self._native.digest()

    def check_object(
        self, obj: dict[str, Any] | str | bytes, *, origin: str = "organization"
    ) -> list[dict[str, Any]]:
        """Validate one RFC 0001 object against this graph."""
        return json.loads(self._native.check_object(_as_json_str(obj), origin))

    def check_all(self) -> list[dict[str, Any]]:
        """Validate every object in this graph in parallel."""
        return json.loads(self._native.check_all())

    def evaluate(
        self,
        program_id: str,
        at: str | datetime,
        *,
        framework_id: str | None = None,
    ) -> dict[str, Any]:
        """Compute RFC 0001 §8 program status at `at`."""
        return json.loads(self._native.evaluate(program_id, _as_timestamp(at), framework_id))

    def summarize(self, program_id: str, at: str | datetime) -> dict[str, Any]:
        """Compute RFC 0001 §8 readiness summary counts at `at`."""
        return json.loads(self._native.summarize(program_id, _as_timestamp(at)))

    def compare_library(
        self,
        after_library: Sequence[dict[str, Any]] | str | bytes,
        at: str | datetime,
    ) -> dict[str, Any]:
        """Compute RFC 0002 §5 status & stale-review diff against a candidate library revision."""
        return json.loads(
            self._native.compare_library(_as_json_str(after_library), _as_timestamp(at))
        )

    def render_oscal(
        self,
        program_id: str,
        framework_id: str,
        at: str | datetime,
        *,
        include_xml: bool = False,
    ) -> list[RenderedFile]:
        """Render the 6-document OSCAL 1.2.3 package (JSON, plus optional XML)."""
        files = self._native.render_oscal(
            program_id, framework_id, _as_timestamp(at), include_xml
        )
        return [RenderedFile(name, media_type, content) for name, media_type, content in files]

    def render_ssp(self, program_id: str, at: str | datetime) -> list[RenderedFile]:
        """Render the narrative SSP (`ssp.md` and `ssp.json`)."""
        files = self._native.render_ssp(program_id, _as_timestamp(at))
        return [RenderedFile(name, media_type, content) for name, media_type, content in files]

    def import_oscal_component(self, content: bytes | str) -> dict[str, Any]:
        """Import an OSCAL 1.2.3 component definition (JSON or XML) against this library graph."""
        raw = content.encode("utf-8") if isinstance(content, str) else content
        return json.loads(self._native.import_oscal_component(raw))


# --- Stateless convenience functions ----------------------------------------


def parse_yaml(text: str | bytes, *, strict: bool = True) -> Any:
    """Parse strict RFC 0001 §6.1 YAML 1.2 (or JSON) into Python primitives."""
    raw = text.decode("utf-8") if isinstance(text, (bytes, bytearray)) else text
    return json.loads(_ogrl_rs.parse_yaml_json(raw, strict))


def format_yaml(obj: dict[str, Any] | str | bytes, *, header_comment: str | None = None) -> str:
    """Format an OGRL object or manifest in deterministic canonical YAML 1.2."""
    return _ogrl_rs.format_yaml_str(_as_json_str(obj), header_comment)


def canonical_json(value: Any) -> bytes:
    """Serialize any JSON value as RFC 8785 canonical JSON bytes."""
    return _ogrl_rs.canonical_json_bytes(_as_json_str(value))


def projection_digest(objects: Sequence[dict[str, Any]] | str | bytes) -> str:
    """Compute the deterministic `sha-256:<hex>` projection digest for a set of objects."""
    return _ogrl_rs.projection_digest_json(_as_json_str(objects))


def read_directory(
    root: str | Path,
    *,
    strict: bool = True,
    profile: str = "auto",
) -> dict[str, Any]:
    """Read a repository-form directory in parallel, returning `{manifest, objects, diagnostics}`."""
    return json.loads(_ogrl_rs.read_directory_json(str(root), strict, profile))


def read_exchange(
    content: str | bytes,
    *,
    strict: bool = True,
    profile: str = "auto",
) -> dict[str, Any]:
    """Read an exchange-form YAML/JSON bundle, returning `{manifest, objects, diagnostics}`."""
    raw = content.decode("utf-8") if isinstance(content, (bytes, bytearray)) else content
    return json.loads(_ogrl_rs.read_exchange_json(raw, strict, profile))


def lint_path(
    path: str | Path,
    *,
    library: str | Path | None = None,
    strict: bool = True,
    profile: str = "auto",
) -> dict[str, Any]:
    """Run full parallel YAML 1.2 + schema + RFC 0001 §7.20 lint on a directory or bundle."""
    return json.loads(
        _ogrl_rs.lint_path_json(
            str(path),
            str(library) if library is not None else None,
            strict,
            profile,
        )
    )


def check_object(
    obj: dict[str, Any] | str | bytes,
    graph_objects: Sequence[dict[str, Any]] | str | bytes,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
    origin: str = "organization",
) -> list[dict[str, Any]]:
    graph = OgrlGraph.from_objects(
        graph_objects, library_ids=library_ids, provider_ids=provider_ids
    )
    return graph.check_object(obj, origin=origin)


def check_graph(
    objects: Sequence[dict[str, Any]] | str | bytes,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    graph = OgrlGraph.from_objects(objects, library_ids=library_ids, provider_ids=provider_ids)
    return graph.check_all()


def evaluate_program(
    objects: Sequence[dict[str, Any]] | str | bytes,
    program_id: str,
    at: str | datetime,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
    framework_id: str | None = None,
) -> dict[str, Any]:
    graph = OgrlGraph.from_objects(objects, library_ids=library_ids, provider_ids=provider_ids)
    return graph.evaluate(program_id, at, framework_id=framework_id)


def summarize_program(
    objects: Sequence[dict[str, Any]] | str | bytes,
    program_id: str,
    at: str | datetime,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    graph = OgrlGraph.from_objects(objects, library_ids=library_ids, provider_ids=provider_ids)
    return graph.summarize(program_id, at)


def compare_library_revisions(
    before_objects: Sequence[dict[str, Any]] | str | bytes,
    after_library: Sequence[dict[str, Any]] | str | bytes,
    at: str | datetime,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    graph = OgrlGraph.from_objects(
        before_objects, library_ids=library_ids, provider_ids=provider_ids
    )
    return graph.compare_library(after_library, at)


def import_oscal_catalog(
    content: bytes | str,
    framework_id: str,
    *,
    name: str | None = None,
    publisher: str = "NIST",
    source_uri: str | None = None,
    source_path: str | None = None,
    commit: str | None = None,
    resolve_catalog: bytes | str | None = None,
    resolve_framework: str | None = None,
) -> dict[str, Any]:
    """Import an OSCAL 1.2.3 catalog (JSON or XML) including assessment objectives."""
    raw = content.encode("utf-8") if isinstance(content, str) else content
    resolve_raw = (
        resolve_catalog.encode("utf-8")
        if isinstance(resolve_catalog, str)
        else resolve_catalog
    )
    return json.loads(
        _ogrl_rs.import_oscal_catalog_json(
            raw,
            framework_id,
            name,
            publisher,
            source_uri,
            source_path,
            commit,
            resolve_raw,
            resolve_framework,
        )
    )


def import_oscal_component(
    content: bytes | str,
    library_objects: Sequence[dict[str, Any]] | str | bytes,
) -> dict[str, Any]:
    """Import an OSCAL 1.2.3 component definition (JSON or XML) against pinned library objects."""
    graph = OgrlGraph.from_objects(library_objects)
    return graph.import_oscal_component(content)


def render_oscal(
    objects: Sequence[dict[str, Any]] | str | bytes,
    program_id: str,
    framework_id: str,
    at: str | datetime,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
    include_xml: bool = False,
) -> list[RenderedFile]:
    graph = OgrlGraph.from_objects(objects, library_ids=library_ids, provider_ids=provider_ids)
    return graph.render_oscal(program_id, framework_id, at, include_xml=include_xml)


def render_ssp(
    objects: Sequence[dict[str, Any]] | str | bytes,
    program_id: str,
    at: str | datetime,
    *,
    library_ids: Iterable[str] | None = None,
    provider_ids: Iterable[str] | None = None,
) -> list[RenderedFile]:
    graph = OgrlGraph.from_objects(objects, library_ids=library_ids, provider_ids=provider_ids)
    return graph.render_ssp(program_id, at)

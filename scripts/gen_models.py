#!/usr/bin/env python3
"""Regenerate the vendored OCSF Pydantic models for a pinned OCSF version.

We generate a full Pydantic v2 model tree for the set of OCSF classes we
support (see ``ROOT_CLASSES``) and commit the result to
``src/ocsf_emitter/_models.py``. Runtime therefore depends only on ``pydantic``
-- no network access or code generation at import time.

Pipeline:
    1. Fetch the pinned OCSF *metaschema* with ``ocsf-lib`` (works for ANY
       version, unlike the JSON-Schema endpoint which only serves the latest).
    2. Convert each root class (and the *union* of their transitive object
       closures) into a self-contained draft JSON Schema. Every root class and
       every shared object becomes a ``$def`` so ``datamodel-code-generator``
       emits one Pydantic class each, with shared objects deduplicated. We emit
       the *base* class only -- attributes tagged with a ``profile`` are dropped,
       mirroring the schema server's ``?profiles=`` selector, so profile-only
       fields (cloud, osint, ...) are not forced into the required list.
    3. Feed that JSON Schema to ``datamodel-code-generator`` -> Pydantic v2.

The target version is pinned in one place (``ocsf_emitter.defaults.OCSF_SCHEMA_VERSION``,
kept in sync with ``DEFAULT_VERSION`` here). Bumping it is a one-line change plus
a regeneration.

Usage:
    uv run --extra codegen python scripts/gen_models.py [VERSION]
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# The version we pin by default. Keep in sync with defaults.OCSF_SCHEMA_VERSION.
DEFAULT_VERSION = "1.5.0"

# The OCSF classes we generate models for, by metaschema key. Each becomes a
# top-level Pydantic model; their shared object closures are deduplicated. Keep
# in sync with the class registry in ``ocsf_emitter.defaults``.
ROOT_CLASSES = [
    "detection_finding",  # 2004 Findings
    "compliance_finding",  # 2003 Findings
    "authentication",  # 3002 Identity & Access Management
    "account_change",  # 3001 Identity & Access Management
    "patch_state",  # 5004 Discovery (Operating System Patch State)
    "api_activity",  # 6003 Application Activity
    "web_resources_activity",  # 6001 Application Activity
    "file_hosting",  # 6006 Application Activity (File Hosting Activity)
]

OUT_PATH = Path(__file__).resolve().parent.parent / "src" / "ocsf_emitter" / "_models.py"

# OCSF scalar data types -> JSON Schema. Non-base types (e.g. port_t, ip_t)
# resolve to one of these via their ``type`` chain in schema.types.
_SCALAR_JSON: dict[str, dict[str, Any]] = {
    "boolean_t": {"type": "boolean"},
    "float_t": {"type": "number"},
    "integer_t": {"type": "integer"},
    "long_t": {"type": "integer"},
    "json_t": {},  # any
    "string_t": {"type": "string"},
}


def _resolve_scalar(types: dict[str, Any], type_name: str) -> dict[str, Any]:
    """Resolve an OCSF type name to a base JSON Schema scalar node."""
    seen: set[str] = set()
    while type_name in types and type_name not in _SCALAR_JSON and type_name not in seen:
        seen.add(type_name)
        nxt = getattr(types[type_name], "type", None)
        if not nxt:
            break
        type_name = nxt
    return dict(_SCALAR_JSON.get(type_name, {"type": "string"}))


def _attr_node(types: dict[str, Any], attr: Any) -> dict[str, Any]:
    """Build the JSON Schema node for a single OCSF attribute."""
    if getattr(attr, "object_type", None):
        node: dict[str, Any] = {"$ref": f"#/$defs/{attr.object_type}"}
    elif getattr(attr, "enum", None):
        keys = list(attr.enum)
        # Most OCSF enums are integer-keyed; some (e.g. severity colour) are not.
        if all(k.lstrip("-").isdigit() for k in keys):
            node = {"type": "integer", "enum": sorted(int(k) for k in keys)}
        else:
            node = _resolve_scalar(types, attr.type)
    else:
        node = _resolve_scalar(types, attr.type)

    if getattr(attr, "is_array", False):
        return {"type": "array", "items": node}
    return node


def _build_defs(schema: Any, root: str) -> dict[str, dict[str, Any]]:
    """Convert ``root`` and its object closure to JSON Schema ``$defs`` entries."""
    defs: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    stack = [root]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        obj = schema.classes.get(name) or schema.objects.get(name)
        if obj is None:
            raise RuntimeError(f"unresolved object reference: {name!r}")
        props: dict[str, Any] = {}
        required: list[str] = []
        for attr_name, attr in obj.attributes.items():
            # Base class only: skip profile-tagged attributes (cloud, osint, ...).
            if getattr(attr, "profile", None):
                continue
            props[attr_name] = _attr_node(schema.types, attr)
            if getattr(attr, "requirement", None) == "required":
                required.append(attr_name)
            if getattr(attr, "object_type", None):
                stack.append(attr.object_type)
        entry: dict[str, Any] = {
            "type": "object",
            "properties": props,
            "additionalProperties": True,
        }
        if required:
            entry["required"] = sorted(required)
        defs[name] = entry
    return defs


def metaschema_to_json_schema(schema: Any, roots: list[str]) -> dict[str, Any]:
    """Produce a self-contained draft JSON Schema for all ``roots``.

    Every root class and every object in the union of their transitive closures
    is emitted as a ``$def`` (roots first in declared order, then the shared
    objects sorted by name for a stable diff). The top-level node is a bare
    object -- ``datamodel-code-generator`` turns each ``$def`` into its own
    Pydantic model and produces no wrapper class for the root.
    """
    defs: dict[str, dict[str, Any]] = {}
    for root in roots:
        # Union the closures; shared objects collide on name and dedup for free.
        defs.update(_build_defs(schema, root))

    # Stable ordering: roots in declared order, then remaining objects sorted.
    ordered: dict[str, dict[str, Any]] = {}
    for root in roots:
        ordered[root] = defs[root]
    for name in sorted(k for k in defs if k not in roots):
        ordered[name] = defs[name]

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "OCSF supported classes",
        "$defs": ordered,
        "type": "object",
    }


def main() -> int:
    version = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VERSION

    from ocsf.api import OcsfApiClient

    print(f"Fetching OCSF {version} metaschema via ocsf-lib ...", file=sys.stderr)
    client = OcsfApiClient()
    schema = client.get_schema(version)
    if schema.version != version:
        print(
            f"WARNING: requested {version} but server returned {schema.version}",
            file=sys.stderr,
        )

    json_schema = metaschema_to_json_schema(schema, ROOT_CLASSES)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(json_schema, tf)
        schema_path = tf.name

    header = (
        f'"""Generated OCSF models for schema version {version}.\n\n'
        "DO NOT EDIT BY HAND. Regenerate with:\n"
        f"    uv run --extra codegen python scripts/gen_models.py {version}\n\n"
        f"Source: OCSF {version} metaschema (ocsf-lib), classes:\n"
        + "".join(f"    - {c}\n" for c in ROOT_CLASSES)
        + "converted to JSON Schema (base classes, profiles excluded).\n"
        '"""\n'
    )

    cmd = [
        "datamodel-codegen",
        "--input",
        schema_path,
        "--input-file-type",
        "jsonschema",
        "--output-model-type",
        "pydantic_v2.BaseModel",
        "--output",
        str(OUT_PATH),
        "--use-standard-collections",
        "--use-union-operator",
        "--target-python-version",
        "3.11",
        "--custom-file-header",
        header,
        "--formatters",
        "black",
    ]
    print("Running:", " ".join(cmd), file=sys.stderr)
    result = subprocess.run(cmd, check=False)  # noqa: S603
    if result.returncode != 0:
        return result.returncode

    print(
        f"\nGenerated {OUT_PATH.name} for OCSF {version}.\n"
        f"Ensure OCSF_SCHEMA_VERSION in defaults.py == '{version}'.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

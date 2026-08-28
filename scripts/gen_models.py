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
import re
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
    # System Activity [1]
    "file_activity",  # 1001
    "kernel_extension_activity",  # 1002
    "kernel_activity",  # 1003
    "memory_activity",  # 1004
    "module_activity",  # 1005
    "scheduled_job_activity",  # 1006
    "process_activity",  # 1007
    "event_log_actvity",  # 1008  (OCSF's own key is misspelled)
    "script_activity",  # 1009
    # Findings [2]
    "vulnerability_finding",  # 2002
    "compliance_finding",  # 2003
    "detection_finding",  # 2004
    "incident_finding",  # 2005
    "data_security_finding",  # 2006
    "application_security_posture_finding",  # 2007
    # Identity & Access Management [3]
    "account_change",  # 3001
    "authentication",  # 3002
    "authorize_session",  # 3003
    "entity_management",  # 3004
    "user_access",  # 3005
    "group_management",  # 3006
    # Network Activity [4]
    "network_activity",  # 4001
    "http_activity",  # 4002
    "dns_activity",  # 4003
    "dhcp_activity",  # 4004
    "rdp_activity",  # 4005
    "smb_activity",  # 4006
    "ssh_activity",  # 4007
    "ftp_activity",  # 4008
    "email_activity",  # 4009
    "ntp_activity",  # 4013
    "tunnel_activity",  # 4014
    # Discovery [5]
    "inventory_info",  # 5001
    "user_inventory",  # 5003
    "patch_state",  # 5004
    "device_config_state_change",  # 5019
    "software_info",  # 5020
    "osint_inventory_info",  # 5021
    "cloud_resources_inventory_info",  # 5023
    "evidence_info",  # 5040
    # Application Activity [6]
    "web_resources_activity",  # 6001
    "application_lifecycle",  # 6002
    "api_activity",  # 6003
    "datastore_activity",  # 6005
    "file_hosting",  # 6006
    "scan_activity",  # 6007
    "application_error",  # 6008
    # Remediation [7]
    "remediation_activity",  # 7001
    "file_remediation_activity",  # 7002
    "process_remediation_activity",  # 7003
    "network_remediation_activity",  # 7004
    # Unmanned Systems [8]
    "drone_flights_activity",  # 8001
    "airborne_broadcast_activity",  # 8002
]

OUT_PATH = Path(__file__).resolve().parent.parent / "src" / "ocsf_emitter" / "_models.py"
CATALOG_PATH = Path(__file__).resolve().parent.parent / "src" / "ocsf_emitter" / "_catalog.py"

# Category uid -> human-readable name (OCSF 1.5 categories). category_uid is the
# leading digit of the class_uid (1001 -> 1, 8002 -> 8) for all base classes.
_CATEGORY_NAMES = {
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
    7: "Remediation",
    8: "Unmanned Systems",
}

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
        # Stash OCSF constraints under a private key; metaschema_to_json_schema
        # either translates them to anyOf/oneOf (conformance) or strips them
        # (model generation must not see anyOf/oneOf -- it changes the models).
        con = getattr(obj, "constraints", None)
        if con:
            entry["__constraints__"] = dict(con)
        defs[name] = entry
    return defs


def _required_for_path(field: str) -> dict[str, Any]:
    """JSON Schema fragment asserting a (possibly dotted) field path is present."""
    parts = field.split(".")
    node: dict[str, Any] = {"required": [parts[-1]]}
    for parent in reversed(parts[:-1]):
        node = {"required": [parent], "properties": {parent: node}}
    return node


def _apply_constraints(entry: dict[str, Any]) -> dict[str, Any]:
    """Translate a def's stashed OCSF constraints into JSON Schema anyOf/oneOf."""
    con = entry.pop("__constraints__", None)
    if not con:
        return entry
    all_of = entry.setdefault("allOf", [])
    for kind, fields in con.items():
        branches = [_required_for_path(f) for f in fields]
        if kind == "at_least_one":
            all_of.append({"anyOf": branches})
        elif kind == "just_one":
            all_of.append({"oneOf": branches})
    return entry


def metaschema_to_json_schema(
    schema: Any, roots: list[str], *, include_constraints: bool = False
) -> dict[str, Any]:
    """Produce a self-contained draft JSON Schema for all ``roots``.

    Every root class and every object in the union of their transitive closures
    is emitted as a ``$def`` (roots first in declared order, then the shared
    objects sorted by name for a stable diff). The top-level node is a bare
    object -- ``datamodel-code-generator`` turns each ``$def`` into its own
    Pydantic model and produces no wrapper class for the root.

    ``include_constraints`` translates OCSF ``at_least_one``/``just_one``
    constraints into ``anyOf``/``oneOf`` on each def (for conformance checking).
    Model generation leaves it False -- ``datamodel-code-generator`` would turn
    those into union wrappers and change the emitted models.
    """
    defs: dict[str, dict[str, Any]] = {}
    for root in roots:
        # Union the closures; shared objects collide on name and dedup for free.
        defs.update(_build_defs(schema, root))

    for entry in defs.values():
        if include_constraints:
            _apply_constraints(entry)
        else:
            entry.pop("__constraints__", None)

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


def _pascal(key: str) -> str:
    """Metaschema class key -> the Pydantic model class name datamodel-codegen emits."""
    return "".join(part.capitalize() for part in key.split("_"))


def _ident(caption: str) -> str:
    """Turn an OCSF enum-member caption into an UPPER_SNAKE Python identifier."""
    out = []
    for ch in caption:
        out.append(ch if ch.isalnum() else "_")
    ident = "_".join(filter(None, "".join(out).split("_"))).upper()
    if not ident:
        ident = "UNKNOWN"
    if ident[0].isdigit():
        ident = f"N_{ident}"
    return ident


def _activity_members(schema: Any, key: str) -> list[tuple[str, int]]:
    """(identifier, id) pairs for a class's activity_id enum, id-sorted, de-duped."""
    attr = schema.classes[key].attributes.get("activity_id")
    enum = getattr(attr, "enum", None) or {"0": None}
    pairs: list[tuple[str, int]] = []
    used: set[str] = set()
    for id_str, member in sorted(enum.items(), key=lambda kv: int(kv[0])):
        caption = getattr(member, "caption", None) or f"id_{id_str}"
        name = _ident(caption)
        while name in used:
            name = f"{name}_"
        used.add(name)
        pairs.append((name, int(id_str)))
    return pairs


def emit_catalog(schema: Any, roots: list[str], version: str) -> str:
    """Render ``_catalog.py``: OcsfClass, the identity registry, per-class activity
    IntEnums, and the SupportedEvent union -- all derived from the metaschema."""
    lines: list[str] = [
        f'"""Generated OCSF class catalog for schema version {version}.\n',
        "DO NOT EDIT BY HAND. Regenerate with:",
        f"    uv run --extra codegen python scripts/gen_models.py {version}",
        "",
        "Derived from the OCSF metaschema (ocsf-lib): the class identity registry,",
        "one activity_id IntEnum per class, and the SupportedEvent union.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import enum",
        "",
        "from . import _models as _m",
        "",
        "",
        "class OcsfClass(enum.Enum):",
        '    """The OCSF classes this library supports, keyed by metaschema name."""',
        "",
    ]
    # OcsfClass members.
    for key in roots:
        lines.append(f'    {key.upper()} = "{key}"')
    lines.append("")
    lines.append("")

    # Per-class activity IntEnums.
    for key in roots:
        cls = _pascal(key)
        lines.append(f"class {cls}Action(enum.IntEnum):")
        lines.append(f'    """{schema.classes[key].caption} (activity_id)."""')
        lines.append("")
        for name, value in _activity_members(schema, key):
            lines.append(f"    {name} = {value}")
        lines.append("")
        lines.append("")

    # Identity registry: OcsfClass -> (class_uid, category_uid, class_name,
    # category_name, model_class_name, action_enum).
    lines.append(
        "CLASS_REGISTRY: dict[OcsfClass, tuple[int, int, str, str, str, type[enum.IntEnum]]] = {"
    )
    for key in roots:
        c = schema.classes[key]
        uid = int(c.uid)
        cat_uid = uid // 1000
        cat_name = _CATEGORY_NAMES[cat_uid]
        cls = _pascal(key)
        lines.append(
            f"    OcsfClass.{key.upper()}: "
            f'({uid}, {cat_uid}, "{c.caption}", "{cat_name}", "{cls}", {cls}Action),'
        )
    lines.append("}")
    lines.append("")

    # SupportedEvent union + tuple (for isinstance / typing).
    model_names = [_pascal(k) for k in roots]
    union = " | ".join(f"_m.{n}" for n in model_names)
    lines.append(f"SupportedEvent = {union}")
    lines.append("")
    lines.append("SUPPORTED_MODELS: tuple[type, ...] = (")
    for n in model_names:
        lines.append(f"    _m.{n},")
    lines.append(")")
    lines.append("")
    return "\n".join(lines)


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

    # Verify each catalog model-name matches a class datamodel-codegen actually
    # emitted (it renames on collisions); fail loudly rather than ship a bad map.
    emitted = set(re.findall(r"^class (\w+)\(BaseModel\):", OUT_PATH.read_text(), re.M))
    missing = [_pascal(k) for k in ROOT_CLASSES if _pascal(k) not in emitted]
    if missing:
        print(
            f"ERROR: expected model classes not found in {OUT_PATH.name}: {missing}\n"
            "datamodel-codegen may have renamed them; fix _pascal()/the catalog map.",
            file=sys.stderr,
        )
        return 1

    print(f"Writing {CATALOG_PATH.name} ...", file=sys.stderr)
    CATALOG_PATH.write_text(emit_catalog(schema, ROOT_CLASSES, version))
    subprocess.run(["ruff", "format", str(CATALOG_PATH)], check=False)  # noqa: S603, S607
    subprocess.run(["ruff", "check", "--fix", str(CATALOG_PATH)], check=False)  # noqa: S603, S607

    print(
        f"\nGenerated {OUT_PATH.name} and {CATALOG_PATH.name} for OCSF {version}.\n"
        f"Ensure OCSF_SCHEMA_VERSION in defaults.py == '{version}'.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

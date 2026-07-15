"""Runtime validation of OCSF Detection Findings.

Validation re-runs Pydantic's model validation over the finding (catching any
post-construction mutation) and enforces a few OCSF invariants the generated
model does not encode as hard constraints (e.g. class identity, type_uid
consistency). On failure it raises :class:`InvalidFindingError` naming the
offending field(s).
"""

from __future__ import annotations

from pydantic import ValidationError

from . import _models as _m
from . import defaults
from .errors import InvalidFindingError


def validate(finding: _m.DetectionFinding) -> _m.DetectionFinding:
    """Validate a finding against the OCSF schema and OCSF invariants.

    Runs two passes: Pydantic re-validation of the current field values (which
    catches post-construction mutation), then invariant checks that the model
    does not encode (class/category identity, ``type_uid`` consistency, sibling
    name fields, and the pinned schema version).

    Args:
        finding: The detection finding to validate.

    Returns:
        The same ``finding`` instance, unchanged, so it can be used inline.

    Raises:
        InvalidFindingError: If schema validation fails or any invariant is
            violated. The error's ``field_errors`` name the offending field(s).
    """
    # 1. Re-run Pydantic validation against the current field values. This
    #    catches attribute mutation done after construction.
    try:
        finding = _m.DetectionFinding.model_validate(finding.model_dump(by_alias=True))
    except ValidationError as exc:
        raise InvalidFindingError(
            "Detection finding failed OCSF schema validation",
            field_errors=_format_pydantic_errors(exc),
        ) from exc

    # 2. Enforce OCSF invariants not expressible as simple field constraints.
    #    class_uid/category_uid/type_uid are IntEnums in the generated model, so
    #    we coerce with int() before comparing.
    problems: list[str] = []

    if int(finding.class_uid) != defaults.CLASS_UID:
        problems.append(f"class_uid: expected {defaults.CLASS_UID}, got {int(finding.class_uid)}")
    if int(finding.category_uid) != defaults.CATEGORY_UID:
        problems.append(
            f"category_uid: expected {defaults.CATEGORY_UID}, got {int(finding.category_uid)}"
        )

    # type_uid must equal class_uid * 100 + activity_id.
    expected_type_uid = defaults.TYPE_UID_BASE + int(finding.activity_id.value)
    if int(finding.type_uid) != expected_type_uid:
        problems.append(
            f"type_uid: expected {expected_type_uid} "
            f"(class_uid*100 + activity_id={int(finding.activity_id.value)}), "
            f"got {int(finding.type_uid)}"
        )

    # Sibling name fields must match the class (AWS Security Lake checks these).
    if finding.category_name != defaults.CATEGORY_NAME:
        problems.append(
            f"category_name: expected {defaults.CATEGORY_NAME!r}, got {finding.category_name!r}"
        )
    if finding.class_name is not None and finding.class_name != defaults.CLASS_NAME:
        problems.append(f"class_name: expected {defaults.CLASS_NAME!r}, got {finding.class_name!r}")

    # metadata.version should match the pinned schema version.
    if finding.metadata.version != defaults.OCSF_SCHEMA_VERSION:
        problems.append(
            f"metadata.version: expected {defaults.OCSF_SCHEMA_VERSION!r}, "
            f"got {finding.metadata.version!r}"
        )

    if problems:
        raise InvalidFindingError(
            "Detection finding failed OCSF invariant checks", field_errors=problems
        )

    return finding


def _format_pydantic_errors(exc: ValidationError) -> list[str]:
    """Turn a Pydantic ValidationError into 'field.path: message' strings."""
    formatted: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        formatted.append(f"{loc}: {err['msg']}")
    return formatted

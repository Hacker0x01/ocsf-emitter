"""Runtime validation of OCSF events.

Validation re-runs Pydantic's model validation over the event (catching any
post-construction mutation) and enforces a few OCSF invariants the generated
model does not encode as hard constraints (e.g. class identity, type_uid
consistency). On failure it raises :class:`InvalidFindingError` naming the
offending field(s).

It works for any of the supported OCSF classes (see :data:`SupportedEvent`);
the class-specific facts (expected class/category uids and name siblings) come
from the class registry in :mod:`ocsf_emitter.defaults`, keyed by the event's
own ``class_uid``.
"""

from __future__ import annotations

from pydantic import ValidationError

from . import _models as _m
from . import defaults
from .errors import InvalidFindingError

# The OCSF classes this library builds/validates/emits. Kept as a Union so type
# checkers accept any supported event where an "event" is expected.
SupportedEvent = (
    _m.DetectionFinding
    | _m.ComplianceFinding
    | _m.Authentication
    | _m.AccountChange
    | _m.PatchState
    | _m.ApiActivity
    | _m.WebResourcesActivity
    | _m.FileHosting
)


def validate(finding: SupportedEvent) -> SupportedEvent:
    """Validate an OCSF event against the schema and OCSF invariants.

    Runs two passes: Pydantic re-validation of the current field values (which
    catches post-construction mutation), then invariant checks that the model
    does not encode (class/category identity, ``type_uid`` consistency, sibling
    name fields, and the pinned schema version). The expected identity is looked
    up from the class registry by the event's ``class_uid``.

    Args:
        finding: The OCSF event to validate (any supported class).

    Returns:
        The same ``finding`` instance, unchanged, so it can be used inline.

    Raises:
        InvalidFindingError: If schema validation fails, the class is not one
            this library supports, or any invariant is violated. The error's
            ``field_errors`` name the offending field(s).
    """
    # 1. Re-run Pydantic validation against the current field values. This
    #    catches attribute mutation done after construction. Validate through the
    #    concrete class of the instance so every field constraint is re-checked.
    model_cls = type(finding)
    try:
        finding = model_cls.model_validate(finding.model_dump(by_alias=True))
    except ValidationError as exc:
        raise InvalidFindingError(
            f"{model_cls.__name__} failed OCSF schema validation",
            field_errors=_format_pydantic_errors(exc),
        ) from exc

    # 2. Enforce OCSF invariants not expressible as simple field constraints.
    #    class_uid/category_uid/type_uid are IntEnums in the generated model, so
    #    we coerce with int() before comparing.
    class_uid = int(finding.class_uid)
    spec = defaults.class_spec_by_uid(class_uid)
    if spec is None:
        raise InvalidFindingError(
            f"{model_cls.__name__} has unsupported class_uid {class_uid}",
            field_errors=[f"class_uid: {class_uid} is not a supported OCSF class"],
        )

    problems: list[str] = []

    if int(finding.category_uid) != spec.category_uid:
        problems.append(
            f"category_uid: expected {spec.category_uid}, got {int(finding.category_uid)}"
        )

    # type_uid must equal class_uid * 100 + activity_id.
    expected_type_uid = spec.type_uid(int(finding.activity_id.value))
    if int(finding.type_uid) != expected_type_uid:
        problems.append(
            f"type_uid: expected {expected_type_uid} "
            f"(class_uid*100 + activity_id={int(finding.activity_id.value)}), "
            f"got {int(finding.type_uid)}"
        )

    # Sibling name fields must match the class (AWS Security Lake checks these).
    if finding.category_name != spec.category_name:
        problems.append(
            f"category_name: expected {spec.category_name!r}, got {finding.category_name!r}"
        )
    if finding.class_name is not None and finding.class_name != spec.class_name:
        problems.append(f"class_name: expected {spec.class_name!r}, got {finding.class_name!r}")

    # metadata.version should match the pinned schema version.
    if finding.metadata.version != defaults.OCSF_SCHEMA_VERSION:
        problems.append(
            f"metadata.version: expected {defaults.OCSF_SCHEMA_VERSION!r}, "
            f"got {finding.metadata.version!r}"
        )

    if problems:
        raise InvalidFindingError(
            f"{model_cls.__name__} failed OCSF invariant checks", field_errors=problems
        )

    return finding


def _format_pydantic_errors(exc: ValidationError) -> list[str]:
    """Turn a Pydantic ValidationError into 'field.path: message' strings."""
    formatted: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        formatted.append(f"{loc}: {err['msg']}")
    return formatted

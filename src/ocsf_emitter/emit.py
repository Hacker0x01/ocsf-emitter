"""Serialize a validated finding to a transport-agnostic payload.

``emit`` is the boundary: it validates, then returns a JSON-serializable dict.
Transport (Kafka, HTTP, file, ...) is intentionally NOT this package's concern
-- callers ship the returned payload however they like.
"""

from __future__ import annotations

import json
from typing import Any

from . import _models as _m
from .validate import validate


def emit(finding: _m.DetectionFinding) -> dict[str, Any]:
    """Validate ``finding`` and return a JSON-serializable dict.

    OCSF ``*_id`` enums are serialized to their integer values and ``None``
    fields are dropped, matching what OCSF consumers expect on the wire.

    Args:
        finding: The detection finding to validate and serialize.

    Returns:
        A JSON-serializable ``dict`` representing the OCSF event.

    Raises:
        InvalidFindingError: If the finding fails schema or invariant validation.
    """
    validated = validate(finding)
    return validated.model_dump(mode="json", by_alias=True, exclude_none=True)


def emit_json(finding: _m.DetectionFinding, *, indent: int | None = None) -> str:
    """Validate ``finding`` and return it as a JSON string.

    Args:
        finding: The detection finding to validate and serialize.
        indent: Optional indentation passed to :func:`json.dumps` for
            pretty-printing; ``None`` produces compact output.

    Returns:
        The finding serialized as a JSON string (keys sorted).

    Raises:
        InvalidFindingError: If the finding fails schema or invariant validation.
    """
    return json.dumps(emit(finding), indent=indent, sort_keys=True)

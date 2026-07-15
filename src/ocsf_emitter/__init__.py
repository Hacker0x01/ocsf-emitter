"""ocsf_emitter -- construct, validate, and emit OCSF Detection Findings.

Typical use::

    from ocsf_emitter import (
        build_detection_finding, emit, Severity, Observable, ObservableType,
    )

    finding = build_detection_finding(
        uid="det-123",
        title="Suspicious login",
        severity=Severity.HIGH,
        message="Impossible-travel login detected",
        observables=[Observable(ObservableType.USER_NAME, "alice")],
    )
    payload = emit(finding)  # validates; raises InvalidFindingError if invalid
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from . import _models as models
from .builders import (
    build_attack,
    build_detection_finding,
    build_from_signal,
    build_observable,
)
from .defaults import (
    OCSF_SCHEMA_VERSION,
    Activity,
    Confidence,
    RiskLevel,
    Severity,
    Status,
    activity_id,
    category_uid,
    class_uid,
    confidence_id,
    configure_product,
    default_metadata,
    default_product,
    make_product,
    risk_level_id,
    severity_id,
    status_id,
    type_uid,
    type_uid_int,
)
from .domain import DetectionSignal, MitreAttack, Observable, ObservableType
from .emit import emit, emit_json
from .errors import InvalidFindingError, OcsfEmitterError
from .validate import validate

try:
    __version__ = version("ocsf-emitter")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0.dev0"

__all__ = [
    "OCSF_SCHEMA_VERSION",
    "__version__",
    "Activity",
    "Confidence",
    "DetectionSignal",
    "InvalidFindingError",
    "MitreAttack",
    "Observable",
    "ObservableType",
    "OcsfEmitterError",
    "RiskLevel",
    "Severity",
    "Status",
    "activity_id",
    "build_attack",
    "build_detection_finding",
    "build_from_signal",
    "build_observable",
    "category_uid",
    "class_uid",
    "configure_product",
    "confidence_id",
    "default_metadata",
    "default_product",
    "emit",
    "emit_json",
    "make_product",
    "models",
    "risk_level_id",
    "severity_id",
    "status_id",
    "type_uid",
    "type_uid_int",
    "validate",
]

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
    build_account_change,
    build_api,
    build_api_activity,
    build_attack,
    build_authentication,
    build_compliance,
    build_compliance_finding,
    build_detection_finding,
    build_device,
    build_endpoint,
    build_file,
    build_file_hosting,
    build_from_signal,
    build_observable,
    build_patch_state,
    build_user,
    build_web_resource,
    build_web_resources_activity,
)
from .defaults import (
    OCSF_SCHEMA_VERSION,
    AccountChangeAction,
    Activity,
    ApiAction,
    AuthAction,
    ClassSpec,
    Confidence,
    FileHostingAction,
    OcsfClass,
    PatchStateAction,
    RiskLevel,
    Severity,
    Status,
    WebResourceAction,
    activity_id,
    activity_id_int,
    category_uid,
    class_identity,
    class_spec,
    class_spec_by_uid,
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
    type_uid_for,
    type_uid_int,
)
from .domain import (
    ApiCall,
    ComplianceRef,
    DetectionSignal,
    DeviceRef,
    EndpointRef,
    FileRef,
    MitreAttack,
    Observable,
    ObservableType,
    UserRef,
    WebResourceRef,
)
from .emit import emit, emit_json
from .errors import InvalidFindingError, OcsfEmitterError
from .validate import SupportedEvent, validate

try:
    __version__ = version("ocsf-emitter")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0.dev0"

__all__ = [
    "OCSF_SCHEMA_VERSION",
    "__version__",
    # Shared vocabularies.
    "Activity",
    "Confidence",
    "RiskLevel",
    "Severity",
    "Status",
    # Per-class action vocabularies.
    "AccountChangeAction",
    "ApiAction",
    "AuthAction",
    "FileHostingAction",
    "PatchStateAction",
    "WebResourceAction",
    # Class registry.
    "ClassSpec",
    "OcsfClass",
    "class_identity",
    "class_spec",
    "class_spec_by_uid",
    # Domain input shapes.
    "ApiCall",
    "ComplianceRef",
    "DetectionSignal",
    "DeviceRef",
    "EndpointRef",
    "FileRef",
    "MitreAttack",
    "Observable",
    "ObservableType",
    "UserRef",
    "WebResourceRef",
    # Errors.
    "InvalidFindingError",
    "OcsfEmitterError",
    # Builders.
    "build_account_change",
    "build_api",
    "build_api_activity",
    "build_attack",
    "build_authentication",
    "build_compliance",
    "build_compliance_finding",
    "build_detection_finding",
    "build_device",
    "build_endpoint",
    "build_file",
    "build_file_hosting",
    "build_from_signal",
    "build_observable",
    "build_patch_state",
    "build_user",
    "build_web_resource",
    "build_web_resources_activity",
    # Id/identity mappers.
    "activity_id",
    "activity_id_int",
    "category_uid",
    "class_uid",
    "confidence_id",
    "configure_product",
    "default_metadata",
    "default_product",
    "make_product",
    "risk_level_id",
    "severity_id",
    "status_id",
    "type_uid",
    "type_uid_for",
    "type_uid_int",
    # Emit / validate.
    "SupportedEvent",
    "emit",
    "emit_json",
    "models",
    "validate",
]
